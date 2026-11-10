"""Evaluate the hybrid model-plus-rules policies for RQ3.

The script combines a base model (XGBoost or XGB+SecureBERT fusion) with the
deterministic rule engine. Policies:

* ``base`` - use the model threshold only.
* ``override_high`` - model prediction OR a high/critical rule.
* ``or_any`` - model prediction OR any rule.

Selection uses validation only: base model by F1, then recall, then lower FPR;
rule policy by F1, recall, and FPR. Exact ties go to ``override_high`` because
it keeps the hybrid explainable and added no measured validation cost. The base
row remains as the hybrid-without-rules ablation.

Inputs:

* ``data/processed/sample_100k.parquet``
* ``data/splits/{val,test,holdout}.json``
* saved preprocessor, XGBoost, encoder scaler, and encoder head
* SecureBERT embeddings for validation, test, and holdout
* ``results/rules_{test,holdout}.csv``; validation rules are recomputed
* ``results/chosen_threshold.json`` and ``results/fusion_config.json``

Outputs:

* ``results/hybrid_rules_results.csv``
* ``results/hybrid_rules_ci.csv``
* ``results/hybrid_rules_config.json``
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from rules.rule_engine import score_dataframe  # noqa: E402

PROC_DIR = os.path.join(BASE, "data", "processed")
SPLITS_DIR = os.path.join(BASE, "data", "splits")
RESULT_DIR = os.path.join(BASE, "results")
MODEL_DIR = os.path.join(RESULT_DIR, "models")
EMB_DIR = os.path.join(PROC_DIR, "securebert")

DROP = [
    "label",
    "mitre_technique", "command_source", "rule_category",
    "record_id", "dedup_key", "dataset_origin",
    "command_line", "cmd_normalized", "model_text",
]

HIGH_SEVERITIES = {"high", "critical"}
POLICIES = ["base", "override_high", "or_any"]
# Higher values win exact ties on validation.
POLICY_TIEBREAK = {"override_high": 2, "base": 1, "or_any": 0}


def load_ids(splits_dir, name):
    with open(os.path.join(splits_dir, f"{name}.json")) as f:
        return set(json.load(f)["record_ids"])


def metrics(y_true, pred):
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": (float(fp / (fp + tn)) if (fp + tn) else None),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }


def rule_evidence(part, split, rules_dir):
    """Per-event rule evidence; use frozen CSVs when present, else recompute."""
    path = os.path.join(rules_dir, f"rules_{split}.csv")
    cols = ["record_id", "matched_any", "n_rules_matched", "matched_rule_ids", "severity_max"]
    if os.path.exists(path):
        ev = pd.read_csv(path)
        missing = [c for c in cols if c not in ev.columns]
        if missing:
            raise ValueError(f"{path} is missing columns: {missing}")
        if set(ev.record_id.astype(str)) != set(part.record_id.astype(str)):
            raise ValueError(f"{path} record_ids do not match the {split} split")
        ev = ev[cols].copy()
        ev["record_id"] = ev["record_id"].astype(str)
    else:
        ev = score_dataframe(part)[cols].copy()
        ev["record_id"] = ev["record_id"].astype(str)
    out = part[["record_id"]].copy()
    out["record_id"] = out["record_id"].astype(str)
    out = out.merge(ev, on="record_id", how="left", validate="one_to_one")
    out["matched_any"] = out["matched_any"].fillna(0).astype(int)
    out["severity_max"] = out["severity_max"].fillna("").astype(str).str.lower()
    return out


def decide(base_proba, threshold, ev, policy):
    pred = (base_proba >= threshold).astype(int)
    if policy == "base":
        return pred
    if policy == "override_high":
        high = ev["severity_max"].isin(HIGH_SEVERITIES).to_numpy()
        return (pred.astype(bool) | high).astype(int)
    if policy == "or_any":
        return (pred.astype(bool) | (ev["matched_any"].to_numpy() == 1)).astype(int)
    raise ValueError(f"unknown policy {policy}")


def selection_key(m):
    return (
        round(m["f1"], 9),
        round(m["recall"], 9),
        -round(m["fpr"] if m["fpr"] is not None else 0.0, 9),
    )


def main():
    ap = argparse.ArgumentParser(description="Hybrid ML + deterministic rules comparison.")
    ap.add_argument("--dataset", default=os.path.join(PROC_DIR, "sample_100k.parquet"))
    ap.add_argument("--splits-dir", default=SPLITS_DIR)
    ap.add_argument("--rules-dir", default=RESULT_DIR)
    ap.add_argument("--emb-dir", default=EMB_DIR)
    ap.add_argument("--model-dir", default=MODEL_DIR)
    ap.add_argument("--out-dir", default=RESULT_DIR)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    df = pd.read_parquet(args.dataset)
    features = [c for c in df.columns if c not in DROP]

    pre = joblib.load(os.path.join(args.model_dir, "preprocessor.joblib"))
    xgb = joblib.load(os.path.join(args.model_dir, "xgb_baseline.joblib"))
    scaler = joblib.load(os.path.join(args.model_dir, "encoder_scaler.joblib"))
    head = joblib.load(os.path.join(args.model_dir, "encoder_head.joblib"))

    with open(os.path.join(args.out_dir, "chosen_threshold.json")) as f:
        xgb_threshold = float(json.load(f)["threshold"])
    with open(os.path.join(args.out_dir, "fusion_config.json")) as f:
        fusion_cfg = json.load(f)
    w_xgb = float(fusion_cfg["w_xgb"])
    fusion_threshold = float(fusion_cfg["threshold"])

    data = {}
    for split in ["val", "test", "holdout"]:
        part = df[df["record_id"].isin(load_ids(args.splits_dir, split))].reset_index(drop=True)
        print(f"[{split}] {len(part)} events: xgb scores", flush=True)
        p_xgb = xgb.predict_proba(pre.transform(part[features]))[:, 1]
        emb = np.load(os.path.join(args.emb_dir, f"{split}_emb.npy"))
        meta = pd.read_parquet(os.path.join(args.emb_dir, f"{split}_meta.parquet")).reset_index(drop=True)
        rid_to_idx = pd.Series(meta.index.values, index=meta.record_id.astype(str).values)
        idx = rid_to_idx.loc[part["record_id"].astype(str).values].values
        assert (meta["label"].values[idx] == part["label"].values).all(), f"{split} labels misaligned"
        p_enc = head.predict_proba(scaler.transform(emb[idx]))[:, 1]
        p_fusion = w_xgb * p_xgb + (1 - w_xgb) * p_enc
        ev = rule_evidence(part, split, args.rules_dir)
        data[split] = {
            "part": part,
            "y": part["label"].to_numpy(),
            "p_xgb": p_xgb,
            "p_fusion": p_fusion,
            "ev": ev,
        }
        print(
            f"[{split}] rule matches {int(ev.matched_any.sum())}, "
            f"high-severity {int(ev.severity_max.isin(HIGH_SEVERITIES).sum())}",
            flush=True,
        )

    bases = {
        "xgboost": {"proba": "p_xgb", "threshold": xgb_threshold},
        "fusion": {"proba": "p_fusion", "threshold": fusion_threshold},
    }

    print("\nvalidation policy selection (frozen thresholds, no test peeking)")
    selection = {}
    for base_name, cfg in bases.items():
        cand = []
        for policy in POLICIES:
            pred = decide(data["val"][cfg["proba"]], cfg["threshold"], data["val"]["ev"], policy)
            m = metrics(data["val"]["y"], pred)
            cand.append((policy, m))
            print(
                f"  {base_name:8s} {policy:13s} P={m['precision']:.4f} "
                f"R={m['recall']:.4f} F1={m['f1']:.4f} FPR={m['fpr']}"
            )
        best_policy, best_m = max(
            cand,
            key=lambda pm: selection_key(pm[1]) + (POLICY_TIEBREAK[pm[0]],),
        )
        selection[base_name] = {"policy": best_policy, "val": best_m}

    best_base = max(
        selection,
        key=lambda b: selection_key(selection[b]["val"]) + (1 if b == "fusion" else 0,),
    )
    selected_policy = selection[best_base]["policy"]
    print(
        f"\nselected base={best_base} policy={selected_policy} "
        f"(validation F1={selection[best_base]['val']['f1']:.4f}, "
        f"FPR={selection[best_base]['val']['fpr']})"
    )

    rows = []
    for base_name, cfg in bases.items():
        for policy in POLICIES:
            for split in ["val", "test", "holdout"]:
                pred = decide(data[split][cfg["proba"]], cfg["threshold"], data[split]["ev"], policy)
                m = metrics(data[split]["y"], pred)
                rows.append({
                    "dataset": "original",
                    "base_model": base_name,
                    "policy": policy,
                    "split": split,
                    "threshold": cfg["threshold"],
                    "precision": round(m["precision"], 4),
                    "recall": round(m["recall"], 4),
                    "f1": round(m["f1"], 4),
                    "fpr": (round(m["fpr"], 5) if m["fpr"] is not None else None),
                    "tp": m["tp"], "fp": m["fp"], "fn": m["fn"], "tn": m["tn"],
                    "n": int(len(data[split]["y"])),
                    "selected": bool(base_name == best_base and policy == selected_policy),
                })

    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(args.out_dir, "hybrid_rules_results.csv"), index=False)

    # Grouped bootstrap CI for the selected policy on test, matching the fusion CI.
    sel = out[(out.base_model == best_base) & (out.policy == selected_policy) & (out.split == "test")].iloc[0]
    cfg = bases[best_base]
    pred = decide(data["test"][cfg["proba"]], cfg["threshold"], data["test"]["ev"], selected_policy)
    y = data["test"]["y"]
    groups = {}
    for i, g in enumerate(data["test"]["part"]["cmd_normalized"].values):
        groups.setdefault(g, []).append(i)
    keys = np.array(list(groups.keys()))
    idx_arrays = {g: np.asarray(v) for g, v in groups.items()}
    rng = np.random.default_rng(42)
    boot = []
    for _ in range(1000):
        samp = rng.choice(keys, size=len(keys), replace=True)
        idx = np.concatenate([idx_arrays[g] for g in samp])
        m = metrics(y[idx], pred[idx])
        boot.append((m["precision"], m["recall"], m["f1"], m["fpr"] or 0.0))
    boot = np.array(boot)
    point = [float(sel.precision), float(sel.recall), float(sel.f1), float(sel.fpr or 0.0)]
    ci = pd.DataFrame([{
        "metric": name,
        "point": round(point[i], 4),
        "ci_low": round(float(np.percentile(boot[:, i], 2.5)), 4),
        "ci_high": round(float(np.percentile(boot[:, i], 97.5)), 4),
        "n_boot": 1000,
        "unit": "command template (grouped)",
        "base_model": best_base,
        "policy": selected_policy,
        "split": "test",
    } for i, name in enumerate(["precision", "recall", "f1", "fpr"])])
    ci.to_csv(os.path.join(args.out_dir, "hybrid_rules_ci.csv"), index=False)

    with open(os.path.join(args.out_dir, "hybrid_rules_config.json"), "w") as f:
        json.dump({
            "generated_by": "src/hybrid_rules.py",
            "dataset": "original",
            "selected_base_model": best_base,
            "selected_policy": selected_policy,
            "selection_rule": (
                "validation only: F1, then recall, then lower FPR; exact ties "
                "prefer override_high (keeps high-severity rule evidence for "
                "analyst triage at zero measured validation cost)"
            ),
            "frozen_thresholds": {k: v["threshold"] for k, v in bases.items()},
            "fusion_weights": {"w_xgb": w_xgb, "w_encoder": round(1 - w_xgb, 2)},
            "validation": {b: selection[b] for b in selection},
            "feature_level_not_used": (
                "decision-level chosen: validation had no recall headroom for a "
                "meta-model to learn from, and feature-level fusion would need "
                "out-of-fold base scores; the decision policy is auditable"
            ),
            "selection_uses_validation_only": True,
            "reported_test_and_holdout_scores": (
                "from this script after the policy was frozen; rules, base "
                "thresholds and policy family were not tuned on test/holdout"
            ),
            "seed": 42,
        }, f, indent=2)

    print("\n" + out.to_string(index=False))
    print("\nsaved results/hybrid_rules_results.csv, .ci.csv, _config.json")


if __name__ == "__main__":
    main()
