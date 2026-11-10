# Task and Workstream Record

The live GitHub issue boards (#1-#5) are the authoritative task record. This page keeps a local summary of what each workstream completed so the repository can be reviewed without opening GitHub.

## Workstreams

| Workstream | Owner | Local status |
|---|---|---|
| Research and report | Yehya | Report work is outside this repository |
| Data and ML | Saif | Complete |
| Rules and Windows validation | Haitham | Complete |
| Integration and quality | Hamdan | Complete for the prototype |
| Dashboard/UI | Abdalrahman | Complete for the prototype |

## Completed work

### Data and ML

- Audited WinLOLBIN-GT, documented leakage columns, and built the balanced 100k sample.
- Created group-aware train/validation/test splits and a withheld-technique holdout.
- Trained the XGBoost baseline and the SecureBERT 2.0 branch using the same splits.
- Selected thresholds and fusion weights on validation only.
- Produced E1-E5 comparisons, context ablation, benign-heavy testing, confidence intervals, latency, and error analysis.
- Packaged the saved model, rules, and explainability output into the `score_event` alert contract.
- Added the FastAPI wrapper and demo/VM alert samples.

### Rules and Windows validation

- Wrote deterministic Sigma-style rules for PowerShell, WMI, PsExec, mshta, rundll32, regsvr32, certutil, msbuild, cmstp, and bitsadmin.
- Prepared the isolated VirtualBox VM and installed Sysmon with instructor approval.
- Collected 32 Event ID 1 rows across 20 scenarios: 12 benign scenarios (17 rows) and 8 attack scenarios (15 rows).
- Ran the schema adapter and documented the 14 fields that raw Sysmon cannot provide.
- Rolled the VM back to the clean snapshot and verified the rollback.
- Scored the adapted table with the saved XGBoost model, rules, and hybrid policy.

`ATT-1197` (BITS) failed because BITS could not start without a network connection, so it is excluded. Event ID 3 was not collected under host-only isolation.

### Integration and quality

- Implemented `POST /score`, `GET /health`, and `GET /schema` in `api/main.py`.
- Added tests for the alert contract, API, and VM adapter.
- Recorded the environment, seeds, dependency lock file, and reproduction commands.
- Generated the consolidated metrics, confusion matrices, PR curve, and evidence index.

### Dashboard/UI

- Built the Streamlit triage dashboard with alert queue, detail view, rules/ATT&CK view, experiment view, VM view, manual scorer, and limitations page.
- Captured eight screenshots from a real local run.
- Added the out-of-distribution manual scoring path and a clear caveat that it is not part of the offline evaluation.

## Measured status

The final rules and hybrid numbers are in `results/master_results.csv` and the related CSVs. The main points are:

| Arm | Test result | Holdout result |
|---|---|---|
| E1 rules | Precision 0.995, recall 0.034, FPR 0.0001 | Recall 0.039 on 8,122 malicious rows |
| Hybrid with rules | No change on balanced test | Recovers 5 of the fusion's 24 withheld-technique misses |

The E1 rule set is a high-precision, low-recall evidence source, not a standalone detector. The rule contribution is small and concentrated on withheld techniques. Do not describe it as a large recall gain.

## External items

- The written report and presentation are managed outside this repository.
- The signed VM authorisation email or message must be attached before submission.
- The live GitHub issue boards and contributor graph remain the source for contribution evidence.
