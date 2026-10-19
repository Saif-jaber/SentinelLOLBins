# Issues for GitHub board

Copy each block into a new GitHub issue. Suggested labels: `data-ml`, `rules-vm`, `integration`, `dashboard`, `report`, `shared`.

---

## Saif Abed — Data & ML

### Issue: Download and audit WinLOLBIN-GT dataset
Label: `data-ml`
Milestone: Weeks 4-6

- [ ] Download `winlolbin_gt_processed_features_10m_plus.csv` + 4 sample files from Zenodo into `data/raw/`
- [ ] Run `src/audit_dataset.py`
- [ ] Check columns, nulls, class balance, label column
- [ ] Identify grouping key (template/scenario/command family)
- [ ] List leakage columns (MITRE ground truth, rationales)
- [ ] Build 50k benign + 50k malicious subset -> `data/processed/sample_100k.parquet`

### Issue: Group-aware train/val/test splits
Label: `data-ml`
Milestone: Weeks 4-6

- [ ] Split by group, not by row
- [ ] Hold out one full attack family/scenario for E4
- [ ] Write manifests to `data/splits/*.json`
- [ ] Commit only manifests, not data files

### Issue: XGBoost baseline
Label: `data-ml`
Milestone: Weeks 4-6

- [ ] `src/preprocess.py` — fit on train only, drop leakage columns
- [ ] `src/train_xgb.py` — train, evaluate precision/recall/F1/FPR
- [ ] Save model to `results/models/`
- [ ] Test on benign-heavy sample for false positives

### Issue: SecureBERT 2.0 encoder branch
Label: `data-ml`
Milestone: Weeks 4-6

- [ ] Frozen SecureBERT 2.0 embeddings + classification head
- [ ] Fallback to SecureBERT if input/compute incompatible
- [ ] Same splits as XGBoost
- [ ] Record checkpoint and seeds in `configs/encoder.yaml`

### Issue: Ablations, thresholds, error analysis
Label: `data-ml`
Milestone: Weeks 7-8

- [ ] E1-E4 results tables
- [ ] Hybrid without rules / without context ablation
- [ ] Threshold tuning on validation only
- [ ] Example correct and incorrect events for report

---

## Haitham Wail Omer — Rules & Windows validation

### Issue: Specify Sigma-style rules
Label: `rules-vm`
Milestone: Weeks 4-6

- [ ] Rule definitions for PowerShell, WMI, PsExec, mshta, rundll32
- [ ] Each rule: ID, condition, reason text, ATT&CK mapping
- [ ] Store in `rules/`

### Issue: Safe VM plan and Sysmon setup
Label: `rules-vm`
Milestone: Weeks 4-6

- [ ] Snapshot-backed Windows VM, isolated network
- [ ] Sysmon installed, Event ID 1 confirmed
- [ ] Written authorisation and safety notes

### Issue: Collect Sysmon telemetry and run approved tests
Label: `rules-vm`
Milestone: Weeks 7-8

- [ ] Capture benign admin workloads
- [ ] Run authorised Atomic Red Team tests for selected LOLBins
- [ ] Export Event ID 1 logs with dates and scenario IDs

### Issue: Schema adapter for raw telemetry
Label: `rules-vm`
Milestone: Weeks 7-8

- [ ] Map Sysmon fields to dataset fields
- [ ] Mark missing fields explicitly, never invent values

---

## Hamdan Al Sabahi — Integration & quality

### Issue: Define API, dashboard design and test plan
Label: `integration`
Milestone: Weeks 4-6

- [ ] API spec: score event in, alert record out
- [ ] Alert record fields agreed with dashboard team
- [ ] Test plan written

### Issue: Alert UI, automated tests, reproducibility, demo
Label: `integration`
Milestone: Weeks 7-8

- [ ] Wire API to dashboard
- [ ] Automated tests pass
- [ ] Fixed seeds and dependency versions recorded
- [ ] Demo run-through

---

## Abdalrahman Ibrahim — Dashboard/UI

### Issue: Design dashboard layout and alert record fields
Label: `dashboard`
Milestone: Weeks 4-6

- [ ] Alert list, filters, detail view layout
- [ ] Fields: event ID, risk, evidence, rules, scores, ATT&CK
- [ ] Agreement with integration team

### Issue: Build alert UI and demo screenshots
Label: `dashboard`
Milestone: Weeks 7-8

- [ ] Flask/FastAPI dashboard showing alert records
- [ ] Rule explanation and command/parent inspection
- [ ] Screenshots for report

---

## Yehya ElAghakasbah — Research & report

### Issue: Validate sources and refine gap
Label: `report`
Milestone: Weeks 4-6

- [ ] 12+ sources verified
- [ ] Gap statement and method refined
- [ ] Citations formatted

### Issue: Final report and presentation
Label: `report`
Milestone: Weeks 7-8

- [ ] 15-20 page report
- [ ] Slides for 10-15 minute presentation
- [ ] Results section filled from ML workstream

---

## Shared / team

### Issue: Instructor approval for 5-member team
Label: `shared`
Milestone: Weeks 4-6

- [ ] Get approval
- [ ] Replace placeholder date in report section 5.2

### Issue: score_event() contract
Label: `shared`
Milestone: Weeks 7-8

- [ ] Saif provides `score_event(row) -> alert` function
- [ ] Hamdan provides POST endpoint that calls it
- [ ] Both agree on input fields and output JSON

### Issue: Live VM watcher (demo bonus)
Label: `shared`, `rules-vm`
Milestone: Weeks 7-8
Blocked by: score_event() contract, Sysmon setup

- [ ] Script in VM reads Sysmon Event ID 1 live (pywin32)
- [ ] Calls score_event(), POSTs to API
- [ ] Alert appears on dashboard as attack runs
- [ ] VM only, no monitoring outside lab
- [ ] Confirm scope with instructor
