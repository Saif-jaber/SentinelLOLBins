"""CLI runner for the SentinelLOLBins deterministic rules baseline (E1).

Produces, for the original dataset and the requested splits:
  results/rules_<split>.csv    per-event rule outputs (contract of section 5)
  results/rules_long.csv        per (event, matched rule) pairs
  results/rules_summary.csv    precision / recall / F1 / FPR and tp / fp / fn / tn
  results/rules_benign_heavy.csv benign-heavy false-alarm view

Usage (from the repository root):

  python rules/run_rules.py \
      --dataset data/processed/sample_100k.parquet \
      --splits-dir data/splits \
      --out-dir results \
      --datasets test holdout
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from rules.rule_engine import get_rules, score_dataframe  # noqa: E402

PROC_DIR = os.path.join(BASE_DIR, "data", "processed")
SPLITS_DIR = os.path.join(BASE_DIR, "data", "splits")
RESULT_DIR = os.path.join(BASE_DIR, "results")

SUMMARY_COLUMNS = [
    "dataset", "model", "threshold", "precision", "recall", "f1", "fpr",
    "tp", "fp", "fn", "tn", "notes",
]


def load_split_ids(name: str, splits_dir: str = SPLITS_DIR) -> List[str]:
    with open(os.path.join(splits_dir, f"{name}.json")) as f:
        return list(json.load(f)["record_ids"])


def _metrics(y_true: List[int], flagged: List[bool]) -> Dict[str, Any]:
    tp = sum(1 for t, f in zip(y_true, flagged) if t == 1 and f)
    fp = sum(1 for t, f in zip(y_true, flagged) if t == 0 and f)
    fn = sum(1 for t, f in zip(y_true, flagged) if t == 1 and not f)
    tn = sum(1 for t, f in zip(y_true, flagged) if t == 0 and not f)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    return {
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "n": len(y_true),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the E1 deterministic rules baseline.")
    ap.add_argument("--dataset", default=os.path.join(PROC_DIR, "sample_100k.parquet"))
    ap.add_argument("--splits-dir", default=SPLITS_DIR)
    ap.add_argument("--out-dir", default=RESULT_DIR)
    ap.add_argument("--datasets", nargs="*", default=["test", "holdout"])
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    df = pd.read_parquet(args.dataset)
    rules_index = {str(r.get("id")): r for r in get_rules()}

    summary_rows: List[Dict[str, Any]] = []
    long_rows: List[Dict[str, Any]] = []
    benign_heavy_rows: List[Dict[str, Any]] = []

    for name in args.datasets:
        ids = set(load_split_ids(name, args.splits_dir))
        part = df[df["record_id"].isin(ids)].reset_index(drop=True)
        out = score_dataframe(part)
        out.to_csv(os.path.join(args.out_dir, f"rules_{name}.csv"), index=False)

        flagged = out["matched_any"].to_numpy() == 1
        y_true = [int(x) for x in part["label"].to_numpy()]
        m = _metrics(y_true, flagged)

        if name == "test":
            notes = (
                "Event-level: flagged iff any rule matched; hand-written rules, "
                "not tuned on test."
            )
            benign_heavy_rows.append(_benign_heavy_row(out, part, notes))
        elif name == "holdout":
            notes = (
                "Holdout is malicious-only; FPR not defined. Rules caught "
                f"{m['tp']} of {m['n']} malicious holdout events."
            )
        else:
            notes = "Event-level: flagged iff any rule matched; hand-written rules."

        summary_rows.append({
            "dataset": "original",
            "model": "Rules-only (deterministic)",
            "threshold": "n/a",
            "precision": round(m["precision"], 3),
            "recall": round(m["recall"], 3),
            "f1": round(m["f1"], 3),
            "fpr": (round(m["fpr"], 4) if m["fpr"] is not None else None),
            "tp": int(m["tp"]),
            "fp": int(m["fp"]),
            "fn": int(m["fn"]),
            "tn": int(m["tn"]),
            "notes": notes,
        })

        for _, r in out.iterrows():
            if int(r["matched_any"]) != 1:
                continue
            rid = str(r["record_id"])
            for rule_id in filter(None, str(r["matched_rule_ids"]).split(";")):
                rule = rules_index.get(rule_id, {})
                long_rows.append({
                    "record_id": rid,
                    "rule_id": rule_id,
                    "matched": 1,
                    "reason": str(r["reasons"]).split(";")[0] if str(r["reasons"]) else "",
                    "attack_id": str(r["attack_ids"]).split(";")[0] if str(r["attack_ids"]) else str(rule.get("attack") or ""),
                    "severity": str(r["severity_max"]) if r["severity_max"] is not None else str(rule.get("severity") or ""),
                })

    summary = pd.DataFrame(summary_rows, columns=SUMMARY_COLUMNS)
    summary.to_csv(os.path.join(args.out_dir, "rules_summary.csv"), index=False)

    long = pd.DataFrame(long_rows, columns=["record_id", "rule_id", "matched", "reason", "attack_id", "severity"])
    long.to_csv(os.path.join(args.out_dir, "rules_long.csv"), index=False)

    benign_heavy = pd.DataFrame(benign_heavy_rows, columns=[
        "dataset", "model", "n_benign", "n_malicious_sampled", "n_events",
        "precision", "recall", "f1", "fpr", "fp_per_10k_benign", "notes",
    ])
    benign_heavy.to_csv(os.path.join(args.out_dir, "rules_benign_heavy.csv"), index=False)

    print(f"wrote {args.out_dir}/rules_{name}.csv")
    print(f"wrote {args.out_dir}/rules_long.csv")
    print(f"wrote {args.out_dir}/rules_summary.csv")
    print(f"wrote {args.out_dir}/rules_benign_heavy.csv")


def _benign_heavy_row(out: pd.DataFrame, part: pd.DataFrame, notes: str) -> Dict[str, Any]:
    benign = part[part["label"] == 0]
    mal = part[part["label"] == 1]
    n_mal = max(1, len(benign) // 100)
    mal_sample = mal.sample(n=n_mal, random_state=42)
    heavy = pd.concat([benign, mal_sample], ignore_index=True)
    hout = score_dataframe(heavy)
    flagged = hout["matched_any"].to_numpy() == 1
    fh = _metrics([int(x) for x in heavy["label"].to_numpy()], flagged.tolist())
    flagged_benign = int((flagged[: len(benign)]).sum())
    flagged_mal = int((flagged[len(benign):]).sum())
    return {
        "dataset": "original",
        "model": "Rules-only (deterministic)",
        "n_benign": int(len(benign)),
        "n_malicious_sampled": int(n_mal),
        "n_events": int(len(heavy)),
        "precision": round(fh["precision"], 3),
        "recall": round(fh["recall"], 3),
        "f1": round(fh["f1"], 3),
        "fpr": (round(fh["fpr"], 4) if fh["fpr"] is not None else None),
        "fp_per_10k_benign": round(flagged_benign / len(benign) * 10000, 1) if len(benign) > 0 else None,
        "notes": notes,
    }


if __name__ == "__main__":
    main()
