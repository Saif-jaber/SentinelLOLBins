# VM External-Check Results

**Owner:** Saif Abed (Data & ML)
**Inputs:** Haitham Wail Omer (Rules & Windows validation)
**Run:** `python src/score_vm.py --adapted data/processed/vm_adapted.parquet --out-dir results`
**Data:** 32 events across 20 scenarios (8 attack, 12 benign); XGBoost threshold 0.55.

These results are an external check. The VM data was not used for training and is not a benchmark. The numbers are not comparable with the balanced test split or the withheld-technique split.

## Results by arm

| Arm | Attack scenario recall (n=8) | Benign scenario FP rate (n=12) | Event TP | Event FP | Event FN |
|---|---|---|---|---|---|
| XGBoost at 0.55 | 1.000 (8/8) | 1.000 (12/12) | 15 | 17 | 0 |
| Rules (E1) | 0.625 (5/8) | 0.000 (0/12) | 5 | 0 | 10 |
| Hybrid (XGBoost OR high-severity rule) | 1.000 (8/8) | 1.000 (12/12) | 15 | 17 | 0 |

XGBoost and Hybrid cover all 32 events (TP + FP + FN). Rules cover 15 events, with 17 true negatives.

## Missed attack scenarios

None. The hybrid arm flagged at least one event from all eight attack scenarios: ATT-1047, ATT-1059-001, ATT-1140, ATT-1218-003, ATT-1218-005, ATT-1218-007, ATT-1218-010, and ATT-1218-011.

## Benign scenarios flagged

All 12 benign scenarios were flagged at least once: BEN-001, BEN-002-r3, BEN-003, BEN-004, BEN-005-r3, BEN-006, BEN-007-r3, BEN-008-r3, BEN-009, BEN-010, BEN-011-r3, and BEN-012-r3.

## Interpretation

The XGBoost arm flagged every event (32/32), so both its attack recall and benign false-positive rate are 1.0. This fits a transfer and calibration mismatch between the training features and the adapted Sysmon table, where 14 model inputs are NaN (see `docs/vm_missing_fields.txt`). As a result, the XGBoost and Hybrid arms cannot separate the two classes in this small check.

The Rules arm kept the benign false-positive rate at 0.0 but missed 3 of 8 attack scenarios: ATT-1059-001, ATT-1218-007, and ATT-1218-011. The Hybrid OR policy cannot do better than XGBoost while XGBoost flags everything. No model was retrained, refit, threshold-tuned, or imputed on VM data.

## Caveat

> The VM check was limited to the scenarios actually run on one isolated, snapshot-backed Windows VM. It is an external sanity check of transfer to raw Sysmon Event ID 1 telemetry, not an estimate of real-world detection performance, and it must not be generalised to enterprise deployment.

## Collection notes

- `ATT-1197` (BITS) failed and is excluded from the scored set.
- Sysmon Event ID 3 was not collected under host-only isolation, so `has_destination` and `network_connection_true` are NaN.

## Outputs

- `results/vm_predictions.csv` (32 rows)
- `results/vm_scenario_summary.csv` (20 rows)
- `results/vm_summary.json`
