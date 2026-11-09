# Data & ML Handoff — Saif Abed

**Status:** Data & ML workstream complete. Ready for integration (Hamdan) and
dashboard (Abdalrahman). No model is retrained by these handoff artifacts.

## What to consume

| Need | File |
|---|---|
| **Per-event scoring contract** | `src/alert_scoring.py` (`score_event`, `score_dataframe`) |
| **Alert schema + examples** | `docs/alert_record_schema.md` |
| **Demo alert records** | `results/sample_alerts.json` / `.csv` (+ `_meta.csv` for TP/FP/FN/TN) |
| **Real VM alert records** | `results/vm_alerts.json` / `.csv` |
| **Dataset audit** | `docs/dataset_audit.md` |
| **VM external-check results** | `docs/vm_results_summary.md`, `results/vm_*.csv/json` |
| **All experiment metrics** | `results/master_results.csv` / `.json` |
| **Threshold (frozen)** | `results/chosen_threshold.json` (0.55) |
| **Fusion weights (frozen)** | `results/fusion_config.json` (`w_xgb=0.4`, t=0.50) |
| **Frozen model artifacts** | `results/models/preprocessor.joblib`, `results/models/xgboost_baseline.joblib` (git-ignored) |
| **Splits / manifests** | `data/splits/*.json`, `data/splits/manifest.json` |

## How to wire it

1. Hamdan: add a `POST /score` endpoint that calls
   `src.alert_scoring.score_event(payload)` and returns the dict unchanged.
2. Abdalrahman: render `risk`, `decision`, `evidence`, `rule_ids`,
   `attack_techniques`, `command_line`, `parent_process`, `review_required`.
3. Use `results/sample_alerts.json` as demo data until live Sysmon is wired.

## Reproduce the ML results

```powershell
python src/audit_dataset.py
python src/make_splits.py
python src/preprocess.py
python src/train_xgb.py
python src/train_encoder.py
python src/hybrid_fusion.py
python rules/run_rules.py --datasets test holdout
python src/build_master_table.py
python src/score_vm.py --adapted data/processed/vm_adapted.parquet --out-dir results
python src/alert_scoring.py --input results/test_event_outcomes.csv --proba-col proba --label-col true --per-outcome 8 --prefix sample_alerts
```

## Tests

```powershell
python -m pytest tests -q
```

`tests/test_alert_scoring.py` covers the alert contract, threshold behaviour,
rule override, review flag, and label-leakage checks.

## Honest scope

The models are evaluated on a synthetic balanced sample plus a small VM
external check. Numbers must not be quoted as real-world or enterprise
performance. Rules are evidence, not ground truth; risk is triage priority.
