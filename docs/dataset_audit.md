# Dataset Audit: WinLOLBIN-GT v1.0.1

**Owner:** Saif Abed (Data & ML)
**Purpose:** Record the checks made on the dataset before modelling: schema, integrity, leakage, and the group-aware split. The counts below come from the project files, not from the publisher's summary.

- Source: WinLOLBIN-GT v1.0.1, CC BY 4.0 (https://doi.org/10.5281/zenodo.20533434)
- Working sample: `data/processed/sample_100k.parquet`
- Splits: `data/splits/*.json`, `data/splits/manifest.json`
- Audit script: `src/audit_dataset.py`

## 1. Working sample

| Property | Value |
|---|---|
| Rows | 100,000 |
| Columns | 67 |
| Malicious (`label=1`) | 50,000 |
| Benign (`label=0`) | 50,000 |
| Distinct ATT&CK labels | 58 (benign rows have no technique label) |
| Sampling seed | 42 |
| Reproduction | `python src/audit_dataset.py` (50k benign + 50k malicious) |

The publisher reports about 10,000,000 raw generated rows and 10,006,645 processed rows. We did not independently verify those figures; this project uses the balanced 100k sample.

## 2. Schema and leakage control

The sample has 67 columns. `src/preprocess.py` drops 10 and passes 57 features to the model. Those 57 names match `src/vm_schema_adapter.MODEL_INPUT_COLUMNS` exactly.

| Dropped column | Reason |
|---|---|
| `label` | Target variable |
| `mitre_technique` | Label leakage |
| `command_source` | Provenance leakage |
| `rule_category` | Category leakage |
| `record_id` | Join key only |
| `dedup_key` | Join key only |
| `dataset_origin` | Provenance only |
| `command_line` | Raw text, used only by the encoder branch |
| `cmd_normalized` | Grouping key, not a tabular feature |
| `model_text` | Encoder text field |

The result is 57 inputs: two categorical (`process_name`, `parent_process`) and 55 numeric or behavioural features. One-hot encoding brings the XGBoost matrix to 108 columns.

## 3. Missing values

Only `mitre_technique` is null in the working sample, exactly for the 50,000 benign rows. No model input is missing there. Raw VM telemetry is different: 14 columns cannot be recovered from Sysmon and are left as NaN. They are listed in `docs/vm_missing_fields.txt` and were not imputed.

## 4. Group-aware splits

Rows are split by command template (`cmd_normalized`) rather than at random. The generator creates many variants of the same command, so a random split would put near-duplicates on both sides of the evaluation.

| Split | Rows | Use |
|---|---:|---|
| Train | 63,311 | Fit preprocessing, feature selection, and class weighting |
| Validation | 14,186 | Select thresholds and fusion weights |
| Test | 14,029 | Final comparison, scored once |
| Holdout | 8,122 | Withheld techniques, malicious only (E4) |

The manifest records seed 42, a 70/15/15 split with a technique holdout, 15 withheld techniques, and 352 holdout rows removed because their command template already appeared in train, validation, or test.

Withheld techniques: T1003, T1036, T1048, T1055, T1059.005, T1112, T1127.002, T1216, T1218.001, T1218.005, T1218.010, T1218.014, T1543.003, T1552.001, T1564.004.

## 5. Integrity rules

- The preprocessor, vocabulary, feature selection, and class weights are fitted on train only. Validation, test, and holdout are transform-only.
- The threshold was selected on validation and stored in `results/chosen_threshold.json` (0.55). It was not tuned on test or VM data.
- Label, technique, scenario, and provenance columns are never model inputs.
- VM telemetry was never added to the train, validation, test, or holdout splits.
- The failed BITS scenario (`ATT-1197`) is excluded from the VM check.

## 6. Limitations

- Parametric generation means many rows share command templates. Grouping and the template-overlap drop reduce the risk but cannot remove it.
- The publisher's row counts are self-reported.
- Fourteen dataset fields are not exactly recoverable from raw Sysmon and were left missing rather than guessed.
- A single process-creation event does not establish attacker intent.
