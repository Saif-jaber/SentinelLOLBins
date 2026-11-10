"""Export Deliverable-2 evaluation artifacts from the saved result files.

Produces:
  results/confusion_matrices.csv        exact + derived TP/FP/FN/TN per experiment
  results/pr_curve_test.csv             precision/recall/threshold points (XGB test)
  results/figures/pr_curve_test.png     PR curve for the report/reproducibility
  results/figures/confusion_matrix_xgb_test.png

It only reads existing result tables; it never retrains, retunes or re-scores.
"""

from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(BASE, "results")
FIGURES = os.path.join(RESULTS, "figures")
os.makedirs(FIGURES, exist_ok=True)


def rel(path: str) -> str:
    return os.path.relpath(path, BASE).replace("\\", "/")


def metrics(tp, fp, fn, tn):
    tp = float(tp) if tp is not None and not pd.isna(tp) else None
    fp = float(fp) if fp is not None and not pd.isna(fp) else None
    fn = float(fn) if fn is not None and not pd.isna(fn) else None
    tn = float(tn) if tn is not None and not pd.isna(tn) else None
    precision = tp / (tp + fp) if tp is not None and fp is not None and tp + fp else np.nan
    recall = tp / (tp + fn) if tp is not None and fn is not None and tp + fn else np.nan
    f1 = (
        2 * precision * recall / (precision + recall)
        if np.isfinite(precision) and np.isfinite(recall) and precision + recall
        else np.nan
    )
    fpr = fp / (fp + tn) if fp is not None and tn is not None and fp + tn else np.nan
    return precision, recall, f1, fpr


ROWS = []


def add(experiment, dataset, arm, n, tp, fp, fn, tn, threshold, source, derived=False, notes=""):
    precision, recall, f1, fpr = metrics(tp, fp, fn, tn)
    ROWS.append(
        {
            "experiment": experiment,
            "dataset": dataset,
            "arm": arm,
            "threshold": "" if threshold is None or pd.isna(threshold) else threshold,
            "n": n,
            "tp": "" if tp is None or pd.isna(tp) else int(tp),
            "fp": "" if fp is None or pd.isna(fp) else int(fp),
            "fn": "" if fn is None or pd.isna(fn) else int(fn),
            "tn": "" if tn is None or pd.isna(tn) else int(tn),
            "precision": round(precision, 4) if np.isfinite(precision) else "",
            "recall": round(recall, 4) if np.isfinite(recall) else "",
            "f1": round(f1, 4) if np.isfinite(f1) else "",
            "fpr": round(fpr, 4) if np.isfinite(fpr) else "",
            "derived": int(derived),
            "source": source,
            "notes": notes,
        }
    )


def counts(y_true, y_pred):
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    return tp, fp, fn, tn


# 1. XGBoost test split and PR curve.
threshold = float(json.load(open(os.path.join(RESULTS, "chosen_threshold.json")))["threshold"])
test = pd.read_csv(os.path.join(RESULTS, "test_event_outcomes.csv"))
xgb_pred = (test["proba"] >= threshold).astype(int)
tp, fp, fn, tn = counts(test["true"], xgb_pred)
add("E2_model_comparison", "original", "XGBoost (full context)", len(test),
    tp, fp, fn, tn, threshold, rel(os.path.join(RESULTS, "test_event_outcomes.csv")))

precision, recall, pr_thresholds = precision_recall_curve(test["true"], test["proba"])
ap = average_precision_score(test["true"], test["proba"])
pr = pd.DataFrame(
    {
        "threshold": np.append(pr_thresholds, np.nan),
        "precision": precision,
        "recall": recall,
    }
)
pr.to_csv(os.path.join(RESULTS, "pr_curve_test.csv"), index=False)

fig, ax = plt.subplots(figsize=(6.4, 5.0), dpi=150)
ax.plot(recall, precision, color="#c81e1e", lw=2, label=f"XGBoost (AP={ap:.4f})")
ax.axhline(0.80, color="#666666", ls=":", lw=1, label="precision target 0.80")
ax.set_xlabel("Recall")
ax.set_ylabel("Precision")
ax.set_title("Precision-recall curve - XGBoost on grouped test split")
ax.set_xlim(0, 1.0)
ax.set_ylim(0, 1.02)
ax.grid(alpha=0.25)
ax.legend(loc="lower left", fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(FIGURES, "pr_curve_test.png"))
plt.close(fig)

cm = np.array([[tn, fp], [fn, tp]])
fig, ax = plt.subplots(figsize=(4.6, 3.8), dpi=150)
image = ax.imshow(cm, cmap="Reds")
ax.set_xticks([0, 1], labels=["pred benign", "pred malicious"])
ax.set_yticks([0, 1], labels=["true benign", "true malicious"])
for (i, j), value in np.ndenumerate(cm):
    ax.text(j, i, f"{value:,}", ha="center", va="center", fontsize=11,
            color="white" if value > cm.max() / 2 else "#222222")
ax.set_title(f"XGBoost test confusion matrix (t={threshold})")
fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
fig.tight_layout()
fig.savefig(os.path.join(FIGURES, "confusion_matrix_xgb_test.png"))
plt.close(fig)

# 2. E1 rules on the test and held-out-technique splits.
rules_test = pd.read_csv(os.path.join(RESULTS, "rules_test.csv"))
merged = test.merge(rules_test[["record_id", "matched_any"]], on="record_id", how="left")
rule_pred = merged["matched_any"].fillna(0).astype(int)
tp, fp, fn, tn = counts(merged["true"], rule_pred)
add("E1_rules_only", "original", "Deterministic rules (Haitham)", len(merged),
    tp, fp, fn, tn, None, rel(os.path.join(RESULTS, "rules_test.csv")))

rules_holdout = pd.read_csv(os.path.join(RESULTS, "rules_holdout.csv"))
tp = int(rules_holdout["matched_any"].fillna(0).astype(int).sum())
fn = len(rules_holdout) - tp
add("E1_rules_only", "original", "Deterministic rules (Haitham)", len(rules_holdout),
    tp, None, fn, None, None, rel(os.path.join(RESULTS, "rules_holdout.csv")),
    notes="E4 holdout, malicious-only: FP/TN undefined")

# 3. E5 hybrid-with-rules. These rows already store TP/FP/FN/TN.
hybrid = pd.read_csv(os.path.join(RESULTS, "hybrid_rules_results.csv"))
for _, row in hybrid.iterrows():
    add(
        "E5_hybrid_rules", row["dataset"], f"{row['base_model']} / {row['policy']}",
        int(row["n"]), row["tp"], row["fp"], row["fn"], row["tn"], row["threshold"],
        rel(os.path.join(RESULTS, "hybrid_rules_results.csv")),
        notes=f"split={row['split']}" + ("; selected policy" if row["selected"] else ""),
    )

# 4. E4 held-out techniques: malicious recall and benign false positives.
holdout = pd.read_csv(os.path.join(RESULTS, "e4_holdout.csv")).iloc[0]
add("E4_heldout_techniques", "original", "XGBoost (full context)",
    int(holdout["n_holdout_malicious"] + holdout["n_benign"]),
    int(holdout["holdout_caught"]), int(holdout["benign_fp"]),
    int(holdout["n_holdout_malicious"] - holdout["holdout_caught"]),
    int(holdout["n_benign"] - holdout["benign_fp"]), holdout["threshold"],
    rel(os.path.join(RESULTS, "e4_holdout.csv")),
    notes="combined holdout attacks + test benign")

# 5. Benign-heavy 1:100 results at each reported threshold.
heavy = pd.read_csv(os.path.join(RESULTS, "benign_heavy_results.csv"))
for _, row in heavy.iterrows():
    add("Robustness_benign_heavy", "original", "XGBoost (full context)",
        int(row["n_benign"] + row["n_malicious"]),
        int(row["n_malicious"] - row["fn"]), int(row["fp"]), int(row["fn"]),
        int(row["n_benign"] - row["fp"]), row["threshold"],
        rel(os.path.join(RESULTS, "benign_heavy_results.csv")),
        notes=f"1:100 prevalence; {row['fp_per_10k_benign']} FP per 10k benign")

# 6. VM external check, event level for each arm.
vm = pd.read_csv(os.path.join(RESULTS, "vm_predictions.csv"))
for arm, column, threshold_arm in (
    ("XGBoost (frozen)", "xgb_pred", 0.55),
    ("Rules (frozen E1)", "rule_matched_any", None),
    ("Hybrid (XGBoost OR high-severity rule)", "hybrid_pred", 0.55),
):
    tp, fp, fn, tn = counts(vm["expected_label"], vm[column].fillna(0).astype(int))
    add("VM_external_check", "vm", arm, len(vm), tp, fp, fn, tn, threshold_arm,
        rel(os.path.join(RESULTS, "vm_predictions.csv")),
        notes="external sanity check; not a real-world estimate")

# 7. E3 context ablation. Counts are derived from the published metrics.
ablation = pd.read_csv(os.path.join(RESULTS, "e3_ablation.csv"))
positive = int((test["true"] == 1).sum())
negative = int((test["true"] == 0).sum())
for _, row in ablation.iterrows():
    tp = int(round(row["recall"] * positive))
    fn = positive - tp
    fp = int(round(row["fpr"] * negative))
    tn = negative - fp
    add("E3_feature_ablation", "original", row["variant"], positive + negative,
        tp, fp, fn, tn, row["threshold"], rel(os.path.join(RESULTS, "e3_ablation.csv")),
        derived=True, notes="derived from reported precision/recall/FPR and split sizes")

# 8. E2 encoder comparison. Derived because embeddings are not committed.
e2 = pd.read_csv(os.path.join(RESULTS, "e2_comparison.csv"))
for _, row in e2.iterrows():
    if row["model"].startswith("XGBoost"):
        continue
    tp = int(round(row["recall"] * positive))
    fn = positive - tp
    fp = int(round(row["fpr"] * negative))
    tn = negative - fp
    add("E2_model_comparison", "original", row["model"], positive + negative,
        tp, fp, fn, tn, row["threshold"], rel(os.path.join(RESULTS, "e2_comparison.csv")),
        derived=True, notes="derived from reported metrics and grouped test split sizes")

out = pd.DataFrame(ROWS)
out.to_csv(os.path.join(RESULTS, "confusion_matrices.csv"), index=False)

print(f"wrote {rel(os.path.join(RESULTS, 'confusion_matrices.csv'))} ({len(out)} rows)")
print(f"wrote {rel(os.path.join(RESULTS, 'pr_curve_test.csv'))} ({len(pr)} points, AP={ap:.4f})")
print(f"wrote {rel(os.path.join(FIGURES, 'pr_curve_test.png'))}")
print(f"wrote {rel(os.path.join(FIGURES, 'confusion_matrix_xgb_test.png'))}")
