# VM External-Check Results

**Owner:** Saif Abed (Data & ML)
**Inputs:** Haitham Wail Omer (Rules & Windows validation)
**Run:** `python src/score_vm.py --adapted data/processed/vm_adapted.parquet --out-dir results`
**Data:** 32 events / 20 scenarios (8 attack scenarios, 12 benign scenarios), frozen XGBoost threshold = 0.55.

These are an **external check**, not training data and not a benchmark. They are not comparable to the balanced test split or the held-out-technique split.

## Results by arm

| Arm | Attack scenario recall (n=8) | Benign scenario FP rate (n=12) | Event TP | Event FP | Event FN |
|---|---|---|---|---|---|
| XGBoost (frozen @ 0.55) | 1.000 (8/8) | 1.000 (12/12) | 15 | 17 | 0 |
| Rules (frozen E1) | 0.625 (5/8) | 0.000 (0/12) | 5 | 0 | 10 |
| Hybrid (XGBoost OR high-severity rule) | 1.000 (8/8) | 1.000 (12/12) | 15 | 17 | 0 |

Per-arm event totals: XGBoost and Hybrid TP+FP+FN = 32; Rules TP+FP+FN = 15 (TN = 17).

## Attack scenarios missed by the hybrid arm

None. All 8 attack scenarios (ATT-1047, ATT-1059-001, ATT-1140, ATT-1218-003, ATT-1218-005, ATT-1218-007, ATT-1218-010, ATT-1218-011) had at least one event flagged.

## Benign scenarios falsely flagged by the hybrid arm

All 12 benign scenarios were flagged at least once: BEN-001, BEN-002-r3, BEN-003, BEN-004, BEN-005-r3, BEN-006, BEN-007-r3, BEN-008-r3, BEN-009, BEN-010, BEN-011-r3, BEN-012-r3.

## Interpretation note

The frozen XGBoost arm flagged every event (32/32), so its attack recall and benign FP rate are both 1.0. This is consistent with a transfer/calibration mismatch between the training features and the adapted raw Sysmon table, where 14 model-input columns are NaN (see `docs/vm_missing_fields.txt`). The XGBoost and Hybrid arms are therefore non-discriminating on this small external check. The Rules arm kept benign FP at 0.0 but missed 3 of 8 attack scenarios (ATT-1059-001, ATT-1218-007, ATT-1218-011). The hybrid OR policy cannot improve on XGBoost while XGBoost flags every event. No model was retrained, refit, threshold-tuned, or imputed on VM data.

## Caveat

> The VM check was limited to the scenarios actually run on one isolated,
> snapshot-backed Windows VM. It is an external sanity check of transfer to raw
> Sysmon Event ID 1 telemetry, not an estimate of real-world detection
> performance, and it must not be generalised to enterprise deployment.

## Collection notes

- `ATT-1197` (BITS) is excluded; the failed BITS scenario was not scored and was not re-added.
- Sysmon Event ID 3 was not collected under host-only isolation, so network features (`has_destination`, `network_connection_true`) are NaN.

## Outputs

- `results/vm_predictions.csv` (32 rows)
- `results/vm_scenario_summary.csv` (20 rows)
- `results/vm_summary.json`
