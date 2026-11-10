# SentinelLOLBins

Behavioural machine-learning detection of Living-off-the-Land Binary (LOLBin) abuse.

**Course:** CSCY413 - Special Topics in Cybersecurity
**Deliverables:** Deliverable 1 (written report, not included here) and Deliverable 2 (implementation, evaluation and evidence)
**Status:** Implementation and evaluation complete

## 1. Overview

SentinelLOLBins is a prototype for detecting malicious use of legitimate Windows utilities. It combines deterministic Sigma-style rules, XGBoost, a SecureBERT command-line branch, and process context, then presents the result as an alert record that an analyst can review.

The aim was to see whether combining these methods gives better triage evidence than any single method. The dashboard and API are demonstration tools; neither replaces an EDR product nor proves that an attack occurred.

## 2. Objectives

- Study behavioural detection of LOLBin abuse.
- Compare Sigma-style rules, XGBoost, and a SecureBERT model pre-trained on cybersecurity text.
- Measure the contribution of command-line content and parent-process context.
- Test a hybrid policy that combines model output, rule evidence, and context.
- Evaluate performance with precision, recall, F1, false-positive rate, and related metrics.
- Run an independent check on authorised Windows Sysmon telemetry.
- Produce interpretable alerts and a small analyst dashboard.

## 3. Dataset

**Dataset:** WinLOLBIN-GT, version 1.0.1
**DOI:** https://doi.org/10.5281/zenodo.20533434

The dataset contains labelled Windows process-creation records. Before modelling, we checked its schema, labels, feature definitions, licence, and possible leakage. The results are in `docs/dataset_audit.md`.

## 4. Technologies

- Python, pandas, and scikit-learn
- XGBoost
- Hugging Face Transformers with SecureBERT 2.0 (`cisco-ai/SecureBERT2.0-base`)
- Sigma-style detection rules and MITRE ATT&CK
- Windows Sysmon
- FastAPI for the scoring API (`api/main.py`)
- Streamlit for the analyst dashboard (`dashboard/app.py`)
- Git and GitHub for version control and task tracking

## 5. Methodology

1. Audit the dataset and verify labels and features.
2. Preprocess command-line and process-context data.
3. Build baseline detectors.
4. Compare rules, XGBoost, and the pre-trained encoder.
5. Test process context and hybrid evidence.
6. Evaluate on held-out data.
7. Validate on an authorised, isolated Windows VM.
8. Expose the selected outputs through the dashboard and API.

All eight steps were implemented for the evaluated prototype. Results are in `results/`, and the current state is summarised in section 11.

## 6. Evaluation

The evaluation covers precision, recall, F1, false-positive rate, confusion matrices, precision-recall curves, and inference latency. It also looks at class imbalance, a benign-heavy test set, possible dataset leakage, and performance on techniques withheld from training.

The consolidated results are in `results/master_results.csv` and `results/master_results.json`.

## 7. Ethics and legal considerations

Testing was limited to systems and environments for which the team had permission. Windows experiments used an isolated virtual machine and harmless test scenarios. No production system was touched, no unauthorised access was attempted, and no unnecessary sensitive data was collected. Dataset use follows the published licence.

## 8. Repository structure

- `docs/` - dataset audit, alert schema, VM records, reproducibility notes, evidence index
- `data/` - processed sample, split manifests, adapted VM table; raw data is not committed
- `src/` - preprocessing, models, experiments, alert scoring, artifact export
- `rules/` - Sigma-style rule definitions and the E1 runner
- `tests/` - alert contract, API, and VM adapter tests
- `results/` - metric tables, model artifacts, alert records, figures
- `dashboard/` - Streamlit analyst dashboard
- `api/` - FastAPI `POST /score` wrapper around `score_event`
- `scripts/` - authorised Sysmon collection tooling and benign lab files

## 9. Team and project management

Workstreams follow Table 2 of the report: research and report (Yehya), data and pre-trained ML (Saif), rules and Windows validation (Haitham), integration and quality (Hamdan), and dashboard/UI (Abdalrahman). Per-member GitHub issue boards are open (#2 Saif, #3 Abdalrahman, #4 Haitham, #5 Hamdan). `docs/issues.md` is the local copy of the task list and its completion state.

## 10. Running the prototype

```powershell
# Dashboard
streamlit run dashboard/app.py

# Scoring API: POST /score, GET /health, GET /schema
uvicorn api.main:app --port 8000

# Tests
python -m pytest tests rules/tests -q
```

## 11. Current status

**Deliverable 1:** introduction, literature review, and methodology are in the report, which is outside this repository.

The evaluated prototype is complete:

- Dataset audit, 100k working sample, group-aware splits, and leakage control.
- XGBoost baseline, SecureBERT 2.0 branch, and validation-selected fusion.
- E1 rules, E2 model comparison, E3 context ablation, E4 held-out techniques, E5 hybrid-with-rules, benign-heavy testing, grouped confidence intervals, latency, and error analysis. Source: `results/master_results.csv`.
- Alert-record contract (`score_event`), Streamlit dashboard, and FastAPI `POST /score`.
- **VM external check complete:** authorisation was granted on 30/10/2026, and Sysmon collection took place on 2026-11-06. The clean set contains 32 Event ID 1 rows across 20 scenarios (12 benign, 8 attack). The adapted table is committed, and the results are in `results/vm_*` and `docs/vm_results_summary.md`. The VM was rolled back and the rollback verified. This is a small external check, not a benchmark.
- Deliverable-2 evidence is indexed in `docs/artifact_index.md`. Seeds and dependency versions are recorded in `docs/reproducibility.md` and `requirements-lock.txt`.

Known limitations: the VM sample is very small, and the XGBoost model flagged every VM event because 14 features are unavailable in raw Sysmon and the feature distribution differs from training. The rules are high-precision but low-recall evidence. Encoder-run package versions were not captured. The synthetic data is parametric, so grouping reduces template leakage but does not remove it. The manual dashboard scorer is an out-of-distribution triage aid and is not part of the offline evaluation.

## 12. References

- WinLOLBIN-GT dataset: https://doi.org/10.5281/zenodo.20533434
- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://sigmahq.io/
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- CISA, Identifying and Mitigating Living Off the Land Techniques: https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques
