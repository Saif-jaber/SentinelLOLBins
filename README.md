# SentinelLOLBins
### Behavioural Machine-Learning Detection of Living-off-the-Land (LOLBins) Abuse

**Course:** CSCY413 - Special Topics in Cybersecurity  
**Deliverable:** Deliverable 1 - Introduction, Literature Review and Methodology  
**Project status:** Initialisation and methodology planning

## 1. Project Overview

SentinelLOLBins is a proposed cybersecurity detection prototype that investigates the detection of potentially malicious use of legitimate Windows utilities, known as Living-off-the-Land Binaries (LOLBins).

The project will explore a hybrid detection approach combining transparent Sigma-style rules, machine-learning classification, command-line analysis, and process context. The objective is to investigate whether combining these methods improves the identification of suspicious activity compared with individual detection approaches.

The system is intended to support security analyst triage and experimentation. It is not intended to replace an operational endpoint detection and response system or independently confirm that an attack has occurred.

## 2. Project Objectives

- Investigate behavioural detection of LOLBin abuse.
- Compare Sigma-style rule detection, XGBoost, and a cybersecurity-pretrained SecureBERT model.
- Evaluate the contribution of command-line arguments and parent-process context.
- Investigate a hybrid approach that combines model predictions, rule evidence, and contextual information.
- Evaluate performance using precision, recall, F1-score, false-positive rate, and other appropriate metrics.
- Explore independent validation using authorised Windows Sysmon telemetry.
- Provide interpretable alert records and a lightweight demonstration dashboard.

## 3. Proposed Dataset

**Dataset:** WinLOLBIN-GT, version 1.0.1

**Dataset DOI:** https://doi.org/10.5281/zenodo.20533434

The dataset is proposed for evaluating detection methods using labelled Windows process-creation records. Dataset structure, labels, feature definitions, licence conditions, and potential data leakage will be checked before model development.

## 4. Proposed Technologies

- Python
- pandas and scikit-learn
- XGBoost
- Hugging Face Transformers
- SecureBERT 2.0, subject to compatibility and resource availability
- Sigma-style detection rules
- MITRE ATT&CK
- Windows Sysmon
- Flask or FastAPI for a proposed API
- HTML, CSS, and JavaScript for a proposed dashboard
- Git and GitHub for version control and task management

## 5. Proposed Methodology

1. Audit the dataset and verify its labels and features.
2. Preprocess command-line and process-context data.
3. Establish baseline detection methods.
4. Compare rule-based detection, XGBoost, and a pretrained cybersecurity encoder.
5. Investigate the contribution of process context and hybrid evidence.
6. Evaluate models using held-out data and suitable metrics.
7. Conduct independent validation in an authorised, isolated Windows virtual machine, subject to feasibility.
8. Integrate selected outputs into a demonstration dashboard.

These are planned activities. Results will be documented after implementation and evaluation.

## 6. Evaluation Plan

Planned metrics include precision, recall, F1-score, false-positive rate, confusion matrices, precision-recall curves, and inference latency where applicable.

Evaluation will consider class imbalance, benign-heavy test data, possible dataset leakage, and performance on withheld scenarios. No performance results are claimed at the initialisation stage.

## 7. Ethical and Legal Considerations

Testing will be restricted to systems and environments for which the team has authorisation. Proposed Windows experiments will use an isolated virtual machine and controlled test scenarios. The team will avoid unauthorised access, production-system testing, and unnecessary collection of sensitive information. Dataset usage and attribution will follow the applicable licence.

## 8. Repository Structure

- `docs/` - project report and documentation
- `data/` - dataset documentation and manifests; raw datasets are not committed by default
- `src/` - planned source code
- `rules/` - planned detection rules
- `tests/` - planned tests
- `notebooks/` - planned exploratory analysis
- `results/` - planned evaluation outputs
- `dashboard/` - planned user interface
- `README.md` - project overview and setup information

## 9. Team and Project Management

The team will allocate responsibilities across research and reporting, data and pretrained machine learning, rules and Windows validation, and integration and quality assurance. Final assignments will be confirmed by the team and instructor.

GitHub Issues or Projects will be used to track tasks, assign owners, record progress, and coordinate the Weeks 4–8 development schedule.

## 10. Current Status

**Deliverable 1:** Introduction, literature review, and methodology planning.

The repository is being initialised. Dataset auditing, implementation, model training, testing, and dashboard integration are planned future activities and will not be reported as completed until verified.

## 11. References and Resources

- WinLOLBIN-GT dataset: https://doi.org/10.5281/zenodo.20533434
- MITRE ATT&CK: https://attack.mitre.org/
- Sigma: https://sigmahq.io/
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- CISA, Identifying and Mitigating Living Off the Land Techniques: https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques
