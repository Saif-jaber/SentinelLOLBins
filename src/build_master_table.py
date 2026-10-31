import json
import os

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT_DIR = os.path.join(BASE, "results")


def read(name):
    path = os.path.join(RESULT_DIR, name)
    return pd.read_csv(path) if os.path.exists(path) else pd.DataFrame()


rows = []


def add(experiment, dataset, model, features=None, weight=None, threshold=None,
        precision=None, recall=None, f1=None, fpr=None, holdout_recall=None,
        notes="", source=""):
    rows.append({
        "experiment": experiment,
        "dataset": dataset,
        "model": model,
        "n_features": features,
        "w_xgb": weight,
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "holdout_recall": holdout_recall,
        "notes": notes,
        "source": source,
    })


add(
    "E1_rules_only", "original", "Deterministic rules (Haitham)", features=None,
    notes=("pending: rules/ is empty; scorer must emit record_id-level verdicts on the "
           "same test and holdout splits used here"),
    source="rules/ (pending)",
)

e2_orig = read("e2_comparison.csv")
e2_deb = read("e2_comparison_debiased.csv")
e4 = read("e4_holdout.csv")
enc = read("e2_encoder.csv")
enc_deb = read("debiased_e2_encoder.csv")
xgb_deb = read("debias_xgb.csv")
fus = read("fusion_results.csv")
fus_deb = read("debiased_fusion_results.csv")


def e2_row(experiment, dataset, model, features, weight, threshold, precision, recall,
           f1, fpr, holdout_recall, source, notes=""):
    add(experiment, dataset, model, features, weight, threshold, precision, recall, f1,
        fpr, holdout_recall, notes, source)


if not e2_orig.empty:
    r = e2_orig[e2_orig.model.str.contains("XGBoost")].iloc[0]
    ho = float(e4.iloc[0]["holdout_recall"]) if not e4.empty else None
    e2_row("E2_model_comparison", "original", "XGBoost (full context)", 108, 1.0,
           float(r["threshold"]), float(r["precision"]), float(r["recall"]),
           float(r["f1"]), float(r["fpr"]), ho, "e2_comparison.csv")

if not e2_deb.empty:
    r = e2_deb[e2_deb.model.str.contains("XGBoost")].iloc[0]
    ho = float(xgb_deb.iloc[0]["holdout_recall"]) if not xgb_deb.empty else None
    e2_row("E2_model_comparison", "debiased", "XGBoost (full context)", 108, 1.0,
           float(r["threshold"]), float(r["precision"]), float(r["recall"]),
           float(r["f1"]), float(r["fpr"]), ho, "e2_comparison_debiased.csv")

for df, dataset, source in [
    (e2_orig, "original", "e2_comparison.csv"),
    (e2_deb, "debiased", "e2_comparison_debiased.csv"),
]:
    if df.empty:
        continue
    r = df[df.model.str.contains("SecureBERT")].iloc[0]
    ho = float(enc.iloc[0]["holdout_recall"]) if dataset == "original" and not enc.empty else None
    if dataset == "debiased" and not enc_deb.empty:
        ho = float(enc_deb.iloc[0]["holdout_recall"])
    e2_row("E2_model_comparison", dataset, "SecureBERT2.0 frozen + logistic", 768, 0.0,
           float(r["threshold"]), float(r["precision"]), float(r["recall"]),
           float(r["f1"]), float(r["fpr"]), ho, source,
           "no process context; command text only")

for df, dataset, source in [
    (fus, "original", "fusion_results.csv"),
    (fus_deb, "debiased", "debiased_fusion_results.csv"),
]:
    if df.empty:
        continue
    r = df[df.method.str.startswith("Fusion")].iloc[0]
    e2_row("E2_fusion", dataset, "Fusion (weighted XGB + SecureBERT)", 108 + 768,
           float(r["w_xgb"]), float(r["threshold"]), float(r["precision"]),
           float(r["recall"]), float(r["f1"]), float(r["fpr"]),
           float(r["holdout_recall"]), source,
           "single-arm thresholds and weights in fusion_config.json")

e3 = read("e3_ablation.csv")
for _, r in e3.iterrows():
    add("E3_feature_ablation", "original", r["variant"], int(r["n_features"]), 1.0,
        float(r["threshold"]), float(r["precision"]), float(r["recall"]), float(r["f1"]),
        float(r["fpr"]), float(r["holdout_recall"]), "e3_ablation.csv")

if not e4.empty:
    r = e4.iloc[0]
    add("E4_heldout_techniques", "original", "XGBoost (full context)", 108, 1.0,
        float(r["threshold"]), None, None, None, None, float(r["holdout_recall"]),
        "e4_holdout.csv",
        f"{int(r['holdout_caught'])}/{int(r['n_holdout_malicious'])} held-out attacks caught; "
        f"benign FPR {float(r['benign_fpr']):.4f}")

bh = read("benign_heavy_results.csv")
for _, r in bh.iterrows():
    add("Robustness_benign_heavy", "original", "XGBoost (full context)", 108, 1.0,
        float(r["threshold"]), float(r["precision"]), float(r["recall"]), float(r["f1"]),
        float(r["fpr"]), None, "benign_heavy_results.csv",
        f"1:100 prevalence; {r['fp_per_10k_benign']:.1f} false alarms per 10k benign events")

lat = read("latency.csv")
for _, r in lat.iterrows():
    add("Ops_latency", "original", r["mode"], None, None, None, None, None, None, None,
        None, "latency.csv",
        f"mean {float(r['mean_ms']):.4f} ms, median {float(r['median_ms']):.4f} ms, "
        f"p95 {float(r['p95_ms']):.4f} ms over {int(r['n'])} events")

out = pd.DataFrame(rows)
out.to_csv(os.path.join(RESULT_DIR, "master_results.csv"), index=False)

with open(os.path.join(RESULT_DIR, "master_results.json"), "w") as f:
    json.dump({
        "generated_by": "src/build_master_table.py",
        "holdout_is_malicious_only": True,
        "e1_status": "pending (rules/ empty)",
        "sources": sorted(out["source"].unique().tolist()),
    }, f, indent=2)

print(out.to_string(index=False))
print("\nsaved results/master_results.csv, results/master_results.json")
