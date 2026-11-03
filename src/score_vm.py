"""Score the adapted Sysmon VM table with the frozen arms (E4 external check).

This script is intentionally data-blocked: it refuses to run until
``data/processed/vm_adapted.parquet`` exists (produced by
``src/vm_schema_adapter.py`` from Haitham's authorised VM collection). It never
fabricates VM results.

Usage
-----
    python src/score_vm.py
    python src/score_vm.py --adapted data/processed/vm_adapted.parquet \
        --out-dir results

Outputs (only on a genuine run)
-------------------------------
    results/vm_predictions.csv        one row per VM event
    results/vm_scenario_summary.csv   one row per scenario
    results/vm_summary.json           scenario-level recall / benign FP + caveats

The frozen XGBoost threshold comes from results/chosen_threshold.json (0.55).
Rule evidence uses the same deterministic engine as E1. The reported hybrid is
``XGBoost OR high-severity rule``; this is the conservative decision policy and
is labelled as an external check, not as the validation-selected fusion model
(SecureBERT embeddings are not available for raw VM telemetry unless computed).
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from rules.rule_engine import score_dataframe  # noqa: E402
from src.vm_schema_adapter import MODEL_INPUT_COLUMNS  # noqa: E402

PROC_DIR = os.path.join(BASE, "data", "processed")
RESULT_DIR = os.path.join(BASE, "results")
MODEL_DIR = os.path.join(RESULT_DIR, "models")
HIGH_SEVERITIES = {"high", "critical"}
DISCLAIMER = (
    "External check only: covers the scenarios actually run, on one isolated VM. "
    "It is not a real-world performance estimate and must not be generalised."
)


def load_threshold(out_dir):
    path = os.path.join(out_dir, "chosen_threshold.json")
    if not os.path.exists(path):
        raise SystemExit(f"missing {path}; cannot pin the validation-selected threshold")
    return float(json.load(open(path))["threshold"])


def scenario_rows(df, label_col):
    rows = []
    for scenario_id, grp in df.groupby("scenario_id", dropna=False):
        expected = pd.to_numeric(grp[label_col], errors="coerce").dropna()
        expected_label = int(expected.iloc[0]) if not expected.empty else None
        rows.append({
            "scenario_id": str(scenario_id),
            "expected_label": expected_label,
            "technique_expected": (
                str(grp["technique_expected"].dropna().iloc[0])
                if "technique_expected" in grp and grp["technique_expected"].notna().any()
                else ""
            ),
            "n_events": int(len(grp)),
            "n_flagged_xgb": int(grp["xgb_pred"].sum()),
            "n_flagged_rules": int(grp["rule_matched_any"].sum()),
            "n_flagged_hybrid": int(grp["hybrid_pred"].sum()),
        })
    out = pd.DataFrame(rows)
    for arm in ["xgb", "rules", "hybrid"]:
        out[f"detected_{arm}"] = out[f"n_flagged_{arm}"] > 0
    return out


def arm_rate(summary, arm, label):
    subset = summary[summary["expected_label"] == label]
    if subset.empty:
        return None, 0
    return float(subset[f"detected_{arm}"].mean()), int(len(subset))


def main():
    ap = argparse.ArgumentParser(description="Score the adapted VM Sysmon table.")
    ap.add_argument("--adapted", default=os.path.join(PROC_DIR, "vm_adapted.parquet"))
    ap.add_argument("--model-dir", default=MODEL_DIR)
    ap.add_argument("--out-dir", default=RESULT_DIR)
    args = ap.parse_args()

    if not os.path.exists(args.adapted):
        raise SystemExit(
            f"VM data not available: {args.adapted}\n"
            "Collect authorised Sysmon telemetry and run src/vm_schema_adapter.py first. "
            "No VM numbers are reported without real data."
        )

    df = pd.read_parquet(args.adapted)
    missing = [c for c in MODEL_INPUT_COLUMNS if c not in df.columns]
    if missing:
        raise SystemExit(f"adapted VM table is missing model-input columns: {missing}")
    if "scenario_id" not in df.columns:
        raise SystemExit("adapted VM table is missing scenario_id")
    if "CommandLine" not in df.columns:
        raise SystemExit("adapted VM table is missing the raw CommandLine audit column")

    threshold = load_threshold(args.out_dir)
    pre = joblib.load(os.path.join(args.model_dir, "preprocessor.joblib"))
    xgb = joblib.load(os.path.join(args.model_dir, "xgb_baseline.joblib"))

    p_xgb = xgb.predict_proba(pre.transform(df[MODEL_INPUT_COLUMNS]))[:, 1]
    rules = score_dataframe(df.rename(columns={"CommandLine": "command_line"}))
    high = rules["severity_max"].fillna("").astype(str).str.lower().isin(HIGH_SEVERITIES).to_numpy()

    pred = pd.DataFrame({
        "record_id": df.get("record_id", pd.Series(range(len(df)))).astype(str).values,
        "scenario_id": df["scenario_id"].astype(str).values,
        "expected_label": (
            pd.to_numeric(df["expected_label"], errors="coerce").values
            if "expected_label" in df.columns else np.nan
        ),
        "technique_expected": (
            df["technique_expected"].astype(str).values
            if "technique_expected" in df.columns else ""
        ),
        "process_name": df["process_name"].values,
        "parent_process": df["parent_process"].values,
        "CommandLine": df["CommandLine"].values,
        "xgb_proba": np.round(p_xgb, 6),
        "xgb_pred": (p_xgb >= threshold).astype(int),
        "rule_matched_any": rules["matched_any"].astype(int).values,
        "rule_severity_max": rules["severity_max"].fillna("").astype(str).values,
        "rule_ids": rules["matched_rule_ids"].fillna("").astype(str).values,
    })
    pred["hybrid_pred"] = (
        pred["xgb_pred"].astype(bool) | pd.Series(high, index=pred.index)
    ).astype(int)

    os.makedirs(args.out_dir, exist_ok=True)
    pred.to_csv(os.path.join(args.out_dir, "vm_predictions.csv"), index=False)

    has_labels = "expected_label" in df.columns and pred["expected_label"].notna().any()
    scenario_summary = pd.DataFrame()
    if has_labels:
        scenario_summary = scenario_rows(pred, "expected_label")
        scenario_summary.to_csv(os.path.join(args.out_dir, "vm_scenario_summary.csv"), index=False)

    summary = {
        "generated_by": "src/score_vm.py",
        "adapted_input": os.path.abspath(args.adapted),
        "threshold": threshold,
        "n_events": int(len(pred)),
        "n_scenarios": int(pred["scenario_id"].nunique()),
        "has_labels": bool(has_labels),
        "disclaimer": DISCLAIMER,
    }
    if has_labels and not scenario_summary.empty:
        for arm in ["xgb", "rules", "hybrid"]:
            recall, n_att = arm_rate(scenario_summary, arm, 1)
            fp_rate, n_ben = arm_rate(scenario_summary, arm, 0)
            summary[f"attack_scenario_recall_{arm}"] = recall
            summary[f"n_attack_scenarios"] = n_att
            summary[f"benign_scenario_fp_rate_{arm}"] = fp_rate
            summary[f"n_benign_scenarios"] = n_ben
        y = pred["expected_label"]
        pred_cols = {"xgb": "xgb_pred", "rules": "rule_matched_any", "hybrid": "hybrid_pred"}
        for arm in ["xgb", "rules", "hybrid"]:
            valid = y.isin([0, 1])
            yy = y[valid].astype(int)
            pp = pred.loc[valid, pred_cols[arm]].astype(int)
            tp = int(((yy == 1) & (pp == 1)).sum())
            fp = int(((yy == 0) & (pp == 1)).sum())
            fn = int(((yy == 1) & (pp == 0)).sum())
            summary[f"event_tp_{arm}"] = tp
            summary[f"event_fp_{arm}"] = fp
            summary[f"event_fn_{arm}"] = fn

    with open(os.path.join(args.out_dir, "vm_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"scored {len(pred)} VM events at threshold {threshold}")
    print(json.dumps(summary, indent=2))
    if not has_labels:
        print("warning: expected_label missing/empty; scenario recall and FPR not computed")


if __name__ == "__main__":
    main()
