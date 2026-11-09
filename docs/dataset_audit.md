# Dataset Audit Summary — WinLOLBIN-GT (v1.0.1)

**Owner:** Saif Abed (Data & ML)
**Purpose:** Deliverable-2 evidence for dataset integrity, schema, leakage control,
and group-aware partitioning. These are measured counts from the project
artifacts, not the publisher's headline numbers.

- Source dataset: WinLOLBIN-GT v1.0.1, CC BY 4.0
  (DOI: https://doi.org/10.5281/zenodo.20533434)
- Working sample: `data/processed/sample_100k.parquet`
- Split manifests: `data/splits/*.json`, `data/splits/manifest.json`
- Audit script: `src/audit_dataset.py`

## 1. Working sample

| Property | Value |
|---|---|
| Rows | 100,000 |
| Columns | 67 |
| Malicious (`label=1`) | 50,000 |
| Benign (`label=0`) | 50,000 |
| Distinct ATT&CK labels (`mitre_technique`) | 58 (benign rows are null) |
| Sampling seed | 42 |
| Reproduction | `python src/audit_dataset.py` (50k benign + 50k malicious) |

The publisher reports ~10,000,000 raw generated rows and 10,006,645 processed
rows. Those are publisher-reported counts and were **not** independently audited
here; this project works from the 100k balanced sample above.

## 2. Schema and leakage control

The sample has 67 columns. `src/preprocess.py` drops 10 and feeds exactly 57
features to the model. The 57 features were checked to match
`src/vm_schema_adapter.MODEL_INPUT_COLUMNS` with **zero missing and zero extra**.

| Dropped column | Reason |
|---|---|
| `label` | Target variable |
| `mitre_technique` | Ground-truth label leakage |
| `command_source` | Ground-truth provenance leakage |
| `rule_category` | Ground-truth category leakage |
| `record_id` | Join/meta id only |
| `dedup_key` | Join/meta id only |
| `dataset_origin` | Meta provenance only |
| `command_line` | Raw text reserved for the encoder branch |
| `cmd_normalized` | Text used for grouping, not tabular XGBoost |
| `model_text` | Encoder text field |

Result: **57 model-input columns** = 2 categorical (`process_name`,
`parent_process`) + 55 numeric/behavioural. After one-hot encoding the XGBoost
matrix is 108 columns wide.

## 3. Missing values

Only `mitre_technique` is null in the balanced sample (50,000 / 100,000 — exactly
the benign half, which has no ATT&CK label). No model-input feature is missing in
the 100k sample. Missing values do appear in the raw VM adaptation and are
documented in `docs/vm_missing_fields.txt` (14 columns, never imputed).

## 4. Group-aware partitioning

Rows are split by a **group key**, not at random, because the generator produces
parametric variants of the same command template. Group key: `cmd_normalized`.

| Split | Record IDs | Notes |
|---|---|---|
| Train | 63,311 | Fit all preprocessing/feature selection here only |
| Validation | 14,186 | Threshold and fusion-weight selection only |
| Test | 14,029 | Scored once for the final comparison |
| Holdout | 8,122 | Withheld techniques, malicious-only (E4) |

Manifest facts (`data/splits/manifest.json`): seed 42, ratios 70/15/15 with a
technique-holdout carve-out, 15 withheld techniques, and 352 template-overlap
rows dropped from the holdout to prevent parametric leakage.

Withheld techniques: T1003, T1036, T1048, T1055, T1059.005, T1112, T1127.002,
T1216, T1218.001, T1218.005, T1218.010, T1218.014, T1543.003, T1552.001,
T1564.004.

## 5. Integrity rules applied

- Preprocessor, vocabulary, feature selection, and class weighting are fit on
  **train only**; validation/test/holdout are transform-only.
- The threshold is selected on validation and frozen in
  `results/chosen_threshold.json` (0.55); it is never tuned on test or VM data.
- Label, technique, scenario, and provenance columns are never model inputs.
- VM telemetry is never added to any train/validation/test/holdout split.
- `ATT-1197` (BITS) is excluded from the VM external check.

## 6. Known limitations

- Synthetic parametric generation means many rows share command templates; the
  group split and template-overlap drop mitigate but do not eliminate this.
- Publisher row counts are self-reported and not independently reconstructed.
- 14 precomputed dataset fields are not exactly recoverable from raw Sysmon and
  are left NaN in the VM adaptation rather than fabricated.
- A single process-creation event does not establish attacker intent.
