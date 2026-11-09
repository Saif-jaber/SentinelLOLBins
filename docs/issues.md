# Issues for GitHub board

Copy each block into a new GitHub issue. Suggested labels: `data-ml`, `rules-vm`, `integration`, `dashboard`, `report`, `shared`.

---

## Saif Abed — Data & ML

### Issue: Download and audit WinLOLBIN-GT dataset
Label: `data-ml`
Milestone: Weeks 4-6

- [x] Download `winlolbin_gt_processed_features_10m_plus.csv` + 4 sample files from Zenodo into `data/raw/`
- [x] Run `src/audit_dataset.py`
- [x] Check columns, nulls, class balance, label column (see `docs/dataset_audit.md`)
- [x] Identify grouping key (template/scenario/command family) — `cmd_normalized`
- [x] List leakage columns (MITRE ground truth, rationales)
- [x] Build 50k benign + 50k malicious subset -> `data/processed/sample_100k.parquet`

### Issue: Group-aware train/val/test splits
Label: `data-ml`
Milestone: Weeks 4-6

- [x] Split by group, not by row
- [x] Hold out one full attack family/scenario for E4
- [x] Write manifests to `data/splits/*.json`
- [x] Commit only manifests, not data files

### Issue: XGBoost baseline
Label: `data-ml`
Milestone: Weeks 4-6

- [x] `src/preprocess.py` — fit on train only, drop leakage columns
- [x] `src/train_xgb.py` — train, evaluate precision/recall/F1/FPR
- [x] Save model to `results/models/`
- [x] Test on benign-heavy sample for false positives

### Issue: SecureBERT 2.0 encoder branch
Label: `data-ml`
Milestone: Weeks 4-6

- [x] Frozen SecureBERT 2.0 embeddings + classification head
- [x] Fallback to SecureBERT if input/compute incompatible
- [x] Same splits as XGBoost
- [x] Record checkpoint and seeds in `results/encoder_config.json`

### Issue: Ablations, thresholds, error analysis
Label: `data-ml`
Milestone: Weeks 7-8

- [x] E1-E4 results tables
- [x] Hybrid without rules / without context ablation
- [x] Threshold tuning on validation only
- [x] Example correct and incorrect events for report

---

## Haitham Wail Omer — Rules & Windows validation

### Issue: Specify Sigma-style rules
Label: `rules-vm`
Milestone: Weeks 4-6

- [x] Rule definitions for PowerShell, WMI, PsExec, mshta, rundll32
- [x] Each rule: ID, condition, reason text, ATT&CK mapping
- [x] Store in `rules/`

### Issue: Safe VM plan and Sysmon setup
Label: `rules-vm`
Milestone: Weeks 4-6

- [x] Snapshot-backed Windows VM, isolated network
- [x] Sysmon installed, Event ID 1 confirmed
- [x] Written authorisation and safety notes

### Issue: Collect Sysmon telemetry and run approved tests
Label: `rules-vm`
Milestone: Weeks 7-8

- [x] Capture benign admin workloads
- [x] Run authorised Atomic Red Team tests for selected LOLBins
      (manual equivalent commands were used where Atomic Red Team was not
      installed; ATT-1197 failed and was excluded, see `docs/vm_run_log.txt`)
- [x] Export Event ID 1 logs with dates and scenario IDs

### Issue: Schema adapter for raw telemetry
Label: `rules-vm`
Milestone: Weeks 7-8

- [x] Map Sysmon fields to dataset fields
- [x] Mark missing fields explicitly, never invent values

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

- [x] Saif provides `score_event(row) -> alert` function (`src/alert_scoring.py`, `docs/alert_record_schema.md`)
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

---

## Measured results update (Saif, Data & ML)

**Status:** E1 rules are no longer pending and the hybrid-with-rules comparison is
done. The numbers below supersede any earlier draft values.

### Stale numbers - do not quote

Earlier drafts / intermediate rule runs used **recall 0.017 / 110 caught**. Those
are obsolete. The final reviewed rules (frozen before the single test/holdout
run) give:

| E1 rules-only | Precision | Recall | F1 | FPR | Caught |
|---|---|---|---|---|---|
| Test (14,029) | 0.995 | 0.034 | 0.065 | 0.0001 | 217 / 6,428 malicious |
| Holdout (8,122 malicious-only) | 1.000 | 0.039 | 0.076 | n/a | 320 / 8,122 |
| Benign-heavy (1:100) | 0.667 | 0.026 | 0.051 | 0.0001 | 1.3 FP per 10k benign |

Source: `results/rules_summary.csv`, `results/rules_benign_heavy.csv`.

### Hybrid-with-rules (RQ3)

Selected on validation only: frozen fusion (XGB + SecureBERT, `w_xgb=0.4`,
threshold 0.50) plus a high-severity rule override. This changes nothing on the
balanced test split and recovers 5 of the fusion's 24 withheld-technique misses
(holdout recall 0.9970 -> 0.9977) with no extra test false positives.

An XGBoost-only ablation shows the same direction more strongly: rules recover
50 of XGBoost's 89 holdout misses (holdout recall 0.989 -> 0.9952) with no extra
test false positive.

Honest reading: E1 is a high-precision / low-recall triage and evidence source,
not a standalone detector. The rule contribution is small and concentrated on
withheld techniques; do not describe it as a large recall improvement.

Sources: `results/hybrid_rules_results.csv`, `results/hybrid_rules_config.json`,
`results/master_results.csv`, `results/master_results.json`.
