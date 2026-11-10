# Deliverable-2 Evidence Index

This page maps the evidence promised in the report to the files in this repository. Paths are relative to the repository root. The report itself is not part of the index.

## Evaluation and metric evidence

| Artifact | Location | Notes |
|---|---|---|
| Dataset audit | `docs/dataset_audit.md` | Counts, leakage drops, 57 model inputs, group split |
| Train/validation/test manifests | `data/splits/*.json`, `data/splits/manifest.json` | Record ids, template counts, seed, withheld techniques |
| Debiased split manifests | `data/splits_debiased/*.json` | Class-prevalence sensitivity experiment |
| Rule definitions | `rules/*.yml`, `rules/README.txt` | Ids, conditions, reasons, ATT&CK mapping |
| Rule engine tests | `rules/tests/test_rule_engine.py` | Deterministic E1 checks |
| Model and threshold settings | `results/chosen_threshold.json`, `results/fusion_config.json`, `results/encoder_config.json` | Selected on validation only |
| All experiment metrics | `results/master_results.csv`, `results/master_results.json` | E1-E5, robustness, latency |
| Confusion matrices | `results/confusion_matrices.csv` | Exact for XGBoost, rules, hybrid, and VM; derived rows are marked |
| Confusion matrix figure | `results/figures/confusion_matrix_xgb_test.png` | XGBoost test split |
| Precision-recall curve | `results/figures/pr_curve_test.png` | XGBoost test; average precision is in the title |
| PR curve data | `results/pr_curve_test.csv` | Threshold, precision, and recall points |
| Threshold sweep | `results/threshold_sweep_val.csv`, `results/threshold_test.csv` | Selection on validation only |
| Grouped confidence intervals | `results/ci_*.csv`, `results/debiased_ci_encoder.csv` | Cluster bootstrap by command template |
| Benign-heavy robustness | `results/benign_heavy_results.csv`, `results/rules_benign_heavy.csv` | 1:100 prevalence, false positives per 10k |
| Context ablation (E3) | `results/e3_ablation.csv` | Name-only through full context |
| Encoder comparison (E2) | `results/e2_comparison.csv`, `results/e2_comparison_debiased.csv` | XGBoost vs SecureBERT 2.0 |
| Held-out techniques (E4) | `results/e4_holdout.csv` | 15 withheld techniques |
| Hybrid with rules (E5) | `results/hybrid_rules_results.csv`, `results/hybrid_rules_config.json` | Base model vs high-severity override |
| Latency | `results/latency.csv` | Single-event and batch prediction |
| Error analysis | `results/test_event_outcomes.csv` | Per-event outcome labels |
| Correctly and incorrectly classified examples | `results/sample_alerts.json/.csv`, `results/sample_alerts_meta.csv` | Eight rows per TN/TP/FP/FN outcome |
| VM collection notes | `docs/vm_run_log.txt`, `docs/vm_validation.md`, `scripts/collect_sysmon.ps1`, `scripts/lab_files/README.txt` | VM identity, timing, failures, rollback |
| VM authorisation | `docs/vm_authorisation.md` | Signed scope, 30/10/2026 |
| VM missing-field report | `docs/vm_missing_fields.txt` | 14 all-NaN fields; no imputation |
| VM external-check results | `docs/vm_results_summary.md`, `results/vm_*.csv/.json` | 32 events across 20 scenarios |
| VM alert records | `results/vm_alerts.json/.csv` | Adapted Sysmon telemetry |
| Dependency versions | `requirements-lock.txt`, `docs/reproducibility.md` | Pinned environment and seeds |
| Dashboard screenshots | `results/figures/dashboard_*.png` | Local run; see `docs/dashboard_screenshots.md` |
| Alert record schema | `docs/alert_record_schema.md` | `score_event` contract |
| API endpoints | `api/main.py` | `POST /score`, `GET /health`, `GET /schema` |
| Integration tests | `tests/` | Alert contract, API, VM adapter |

## Repository and process evidence

| Requirement | Location |
|---|---|
| Initialised repository with folder structure | `src/`, `rules/`, `data/`, `results/`, `dashboard/`, `api/`, `docs/`, `tests/`, `scripts/` |
| Issue and task board | GitHub Issues #1-#5 plus `docs/issues.md` |
| Contribution evidence | GitHub contributors graph and per-member issue boards |
| Workstream records | `docs/issues.md` and Table 2 of the report |
| Ethics and authorisation | `docs/vm_authorisation.md`, `docs/vm_run_log.txt` |

## Limitations to keep in the report

- The VM check is a small external sanity check (32 events, 20 scenarios), not a real-world estimate. The XGBoost model flagged every VM event because of the transfer mismatch and 14 missing feature columns.
- Rules are evidence, not ground truth. E1 has high precision and low recall.
- Encoder-run package versions were not captured; only the checkpoint is recorded.
- The data is synthetic and parametric. Grouping reduces template leakage but does not eliminate it.
- Manual dashboard triage is an out-of-distribution calibration aid and is not part of the offline evaluation.
