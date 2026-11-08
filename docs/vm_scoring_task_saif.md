# VM Scoring Task — Saif Abed (Data & ML)

**Owner:** Saif Abed  
**Inputs from:** Haitham Wail Omer (Rules & Windows validation)  
**Purpose:** Score the authorised VM Sysmon collection with the frozen XGBoost
model and the frozen rule engine. This is an **external check**, not training
data and not a real-world performance estimate.

---

## 1. Files you receive from Haitham

| File | Meaning |
|---|---|
| `data/processed/vm_adapted.parquet` | 32 VM events, 20 scenarios, 57 model-input columns, plus `scenario_id`, `record_id`, `expected_label`, `technique_expected`, and raw audit columns |
| `docs/vm_missing_fields.txt` | 14 model-input columns that are NaN for all rows, with reasons |
| `docs/vm_run_log.txt` | What ran, what failed, retry/timing history, rollback evidence |

Do not regenerate or edit these files. Do not add the failed BITS scenario
(`ATT-1197`) back. The clean dataset is **32 events / 20 scenarios**:
12 benign scenarios (17 events) and 8 attack scenarios (15 events).

---

## 2. Put the frozen model files in place

The VM scoring runner needs the **already-trained** artifacts:

```text
results/models/preprocessor.joblib
results/models/xgboost_baseline.joblib
```

If `results/models/` does not exist, create it. Copy the files from the training
run. Do **not** retrain, refit, or replace them with a new model for this check.

Also confirm the threshold file exists:

```text
results/chosen_threshold.json
```

It should contain `"threshold": 0.55` selected on validation. Do **not** change
the threshold for the VM run.

---

## 3. Check the Python environment

Run from the repository root (`SentinelLOLBins`). The scoring path needs:

```text
pandas, numpy, pyarrow, joblib, xgboost, scikit-learn, pyyaml
```

Use the same environment/versions used to train and save the model where
possible. Quick check:

```powershell
python -c "import pandas, numpy, pyarrow, joblib, xgboost, sklearn, yaml; print('deps ok')"
```

If a dependency is missing, install it in the project environment. On the
current host, pandas 3.1.1 is blocked by an Application Control policy; pandas
3.0.6 works. That is a host tooling issue only, not a data issue.

---

## 4. Validate the input before scoring

Run this once:

```powershell
python -c "import pandas as pd; df = pd.read_parquet('data/processed/vm_adapted.parquet'); print(df.shape); print(df.scenario_id.nunique()); print(df.expected_label.value_counts().to_dict()); print(df.record_id.duplicated().sum())"
```

Expected:

```text
(32, 70)
20
{'0': 17, '1': 15}
0
```

`70` columns = 57 model-input columns + `scenario_id` + `record_id` +
`expected_label` + `technique_expected` + 9 raw audit columns. If the shape or
counts differ, stop and report the mismatch; do not hand-edit the parquet.

---

## 5. Run the scoring script

From the repository root:

```powershell
python src/score_vm.py --adapted data/processed/vm_adapted.parquet --out-dir results
```

The script:

- loads `results/models/preprocessor.joblib` and `results/models/xgboost_baseline.joblib`;
- transforms the 57 model-input columns;
- predicts with the frozen XGBoost at threshold **0.55**;
- runs the frozen rule engine from `rules/`;
- defines the hybrid result as **XGBoost OR high-severity rule**;
- groups results by `scenario_id`.

It refuses to run without the adapted file. It does not fabricate numbers.

---

## 6. Check the outputs

Three files should appear:

```text
results/vm_predictions.csv
results/vm_scenario_summary.csv
results/vm_summary.json
```

Check:

1. `vm_predictions.csv` has **32 data rows** (one per VM event).
2. `vm_scenario_summary.csv` has **20 data rows** (one per scenario).
3. `vm_summary.json` reports:
   - `"n_events": 32`
   - `"n_scenarios": 20`
   - `"threshold": 0.55`
   - `"has_labels": true`
   - non-null `attack_scenario_recall_xgb`, `attack_scenario_recall_rules`,
     `attack_scenario_recall_hybrid`
   - non-null `benign_scenario_fp_rate_xgb`, `benign_scenario_fp_rate_rules`,
     `benign_scenario_fp_rate_hybrid`
4. The scenario summary has **8 attack scenarios** and **12 benign scenarios**.
5. Event-level `tp + fp + fn + tn = 32` for each arm. In `vm_summary.json`,
   `tp + fp + fn` must be **≤ 32**.

If any of these fail, stop and report the exact error/output. Do not patch the
CSVs by hand.

---

## 7. Interpret the results correctly

Report these three arms separately:

- **XGBoost** — frozen model at threshold 0.55.
- **Rules** — frozen E1 rule engine.
- **Hybrid** — XGBoost OR high-severity rule.

Use:

- **Scenario recall** for the 8 attack scenarios.
- **Benign scenario false-positive rate** for the 12 benign scenarios.
- **Event-level TP / FP / FN** for the 32 events.
- **Miss list** from `vm_predictions.csv`: attack rows with `hybrid_pred = 0`,
  including `scenario_id`, `CommandLine`, `xgb_proba`, and `rule_ids`.
- **False positives**: benign rows with `hybrid_pred = 1`, including
  `scenario_id` and `CommandLine`.

Do **not** describe these numbers as enterprise performance. The VM check only
covers the scenarios actually run, on one isolated VM. It is not comparable to
the balanced test split or the held-out-technique split.

---

## 8. Write the results summary for Yehya

Create `docs/vm_results_summary.md` containing:

1. A small table:

| Arm | Attack scenario recall (n=8) | Benign scenario FP rate (n=12) | Event TP | Event FP | Event FN |
|---|---|---|---|---|---|
| XGBoost | | | | | |
| Rules | | | | | |
| Hybrid | | | | | |

2. The attack scenarios missed by the hybrid arm.
3. Any benign scenarios falsely flagged by the hybrid arm.
4. This caveat, verbatim:

> The VM check was limited to the scenarios actually run on one isolated,
> snapshot-backed Windows VM. It is an external sanity check of transfer to raw
> Sysmon Event ID 1 telemetry, not an estimate of real-world detection
> performance, and it must not be generalised to enterprise deployment.

5. A note that `ATT-1197` (BITS) is excluded and Event ID 3 was not collected
   under host-only isolation, so network features are NaN.

Send that file, plus `results/vm_predictions.csv`, `results/vm_scenario_summary.csv`
and `results/vm_summary.json`, to Yehya for the report.

---

## 9. Commit the outputs

From the repository root:

```powershell
git add results/vm_predictions.csv results/vm_scenario_summary.csv results/vm_summary.json docs/vm_results_summary.md
git commit -m "Add VM external-check scoring results"
```

`results/models/*.joblib` is git-ignored and must not be committed.

---

## 10. Stop conditions — do not work around these

Stop and report back if:

- the model files are missing or fail to load;
- the input parquet is not 32 rows / 20 scenarios / 57 model-input columns;
- `expected_label` is missing or all empty;
- the script raises an error;
- any metric is null or the scenario groups are not 8 attack / 12 benign.

Do **not**:

- retrain or refit the preprocessor or XGBoost on VM data;
- tune the threshold on VM data;
- impute the 14 NaN columns;
- add VM rows to training, validation, test, or holdout splits;
- add `ATT-1197` back or invent Event ID 3 records;
- quote VM numbers as real-world or enterprise performance.
