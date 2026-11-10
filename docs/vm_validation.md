# VM Validation with Sysmon

**Owner:** Haitham Wail Omer (Rules & Windows validation)
**Purpose:** Record the independent Sysmon check for methodology section 3.6 and Experiment E4.
**Status:** Collection was completed on 2026-11-06 and the VM was rolled back. The adapter produced `data/processed/vm_adapted.parquet` (32 events, 20 scenarios) and `docs/vm_missing_fields.txt`. Scoring with the saved XGBoost model, rules, and hybrid policy is complete; results are in `docs/vm_results_summary.md` and `results/vm_*`.

This was a small external sanity check, not a real-world performance estimate.

## 1. What the check covers

The run used one isolated, snapshot-backed Windows VM and a fixed set of harmless scenarios. It tests whether the saved pipeline can consume raw Sysmon Event ID 1 telemetry without retraining.

- 12 benign administrative scenarios, 17 Event ID 1 rows.
- 8 harmless attack simulations, 15 Event ID 1 rows.
- `ATT-1197` (BITS) failed because BITS could not start without a network connection and is excluded.
- No Event ID 3 rows were collected under host-only isolation.
- `T1548.002`, `T1569.002`, and `T1105` were not feasible; the reasons are in `docs/vm_run_log.txt`.

The clean dataset therefore contains 32 Event ID 1 rows across 20 scenarios.

## 2. Authorisation and safety

Authorisation was granted by the instructor on 30/10/2026 and is recorded in `docs/vm_authorisation.md`. Collection did not start until that note was signed.

Safety rules:

- Windows 10 VM only, on an isolated network.
- No real malware, credential dumping, lateral movement, or persistence.
- Payloads limited to `calc.exe`, `notepad.exe`, and local `.inf`, `.hta`, or `.js` files.
- A clean snapshot was taken before Sysmon installation and restored after collection.

## 3. VM setup used

1. Windows 10 VM, fully patched, with UTC as the system time zone.
2. Snapshot `clean-pre-sysmon` taken before any changes.
3. Sysmon installed with a maintained configuration; Event ID 1 was verified with `Get-WinEvent`.
4. Snapshot `sysmon-ready` taken before the first scenario.
5. VM network set to host-only for collection.

The exact Sysmon version, configuration hash, snapshot ids, and timestamps are in `docs/vm_run_log.txt`.

## 4. Collection method

The collection script is `scripts/collect_sysmon.ps1`. It runs inside the guest and writes the raw CSV contract. For each scenario it:

1. Records `start_utc` and opens a scenario window.
2. Runs the benign command or harmless LOLBin simulation.
3. Exports Sysmon Event ID 1 rows inside the scenario window.
4. Appends one row to `scenarios.csv` with `scenario_id`, `expected_label`, and `technique_expected`.

The scenario table, retries, and the Event ID 1 flush timing problem are documented in `docs/vm_run_log.txt`. The script was updated after the first benign pass so that the newest event is flushed before export; the six affected scenarios were re-run.

## 5. Building the adapted table

The saved XGBoost model expects the same 57 model-input columns as `data/processed/sample_100k.parquet`. Those columns expand to 108 after one-hot encoding inside `src/preprocess.py`; the VM file does not contain one-hot columns.

From the repository root:

```powershell
python src/vm_schema_adapter.py `
  --events data/raw/vm/sysmon_events.csv `
  --network data/raw/vm/sysmon_network.csv `
  --scenarios data/raw/vm/scenarios.csv `
  --out data/processed/vm_adapted.parquet `
  --report docs/vm_missing_fields.txt `
  --csv
```

What the adapter guarantees:

- Exactly the 57 model-input columns, in the same order as the training table, plus `record_id`, `scenario_id`, raw audit columns, and optional `expected_label` / `technique_expected` join keys.
- Record ids are deterministic: `vm_` plus a SHA-1 of `Computer|UtcTime|ProcessId|Image|CommandLine`.
- Values are never invented. Columns that Sysmon cannot supply stay NaN and are listed with reasons in `docs/vm_missing_fields.txt`.
- Sixteen behavioural `flag_*` columns are computed and were checked against the dataset generator on 20,000 training rows.
- `cmd_normalized` follows the dataset's entity templating and matches it byte-for-byte on about 87.5% of training rows. `cmd_len`, `cmd_entropy`, and `cmd_avg_token_len` are computed from it.
- `parent_child_suspicious` is an approximation based on the dataset evidence; the exact generator predicate was not published.
- Missing required columns or an empty `Image` stop the run instead of producing a guessed row.

The 14 columns left missing are:

- `cmd_url_token_count`, `cmd_path_token_count`, `cmd_ip_token_count`, `cmd_b64_token_count` - the generator's exact token regexes were not published, and partial matches would distort the model inputs.
- `flag_certutil_encode`, `flag_remote_file`, `flag_rundll32_js`, `flag_msbuild`, `flag_adsi`, `flag_cmd_slash_c` - the generator templates cannot be recovered exactly.
- `signed_true` - NaN unless a `signed_status` column is supplied.
- `network_connection_true`, `has_destination` - derived from Event ID 3; NaN when network events were not collected.
- `integrity_ordinal` - the dataset's ordinal mapping was not published.

The adapter checks passed: 20 unique `scenario_id` values, no null scenario ids, no duplicate `record_id` values, every event inside its scenario's UTC window, and 18/18 adapter tests.

## 6. Scoring

The adapted table was scored with the saved preprocessor and XGBoost model at the validation-selected threshold of 0.55:

```powershell
python src/score_vm.py `
  --adapted data/processed/vm_adapted.parquet `
  --out-dir results
```

`score_vm.py` also applies the deterministic high-severity rule override as an external hybrid check. It writes `results/vm_predictions.csv`, `results/vm_scenario_summary.csv`, and `results/vm_summary.json`. The summary is in `docs/vm_results_summary.md`.

The XGBoost arm flagged every VM event. This matches a transfer mismatch: 14 feature columns are missing, and the real Sysmon distribution differs from the synthetic training data. No model was retrained, refitted, threshold-tuned, or imputed on VM data.

## 7. Rollback and reporting

- The VM was restored to `clean-pre-sysmon` after collection.
- Rollback was verified by confirming that the `Sysmon64` service and the Sysmon event log were absent. The timestamp and commands are in `docs/vm_run_log.txt`.
- The report must describe this as a check of transfer to raw Sysmon telemetry, not as a detection benchmark.

Use this wording in the report:

> The VM check was limited to the scenarios actually run on one isolated, snapshot-backed Windows VM. It is an external sanity check of transfer to raw Sysmon Event ID 1 telemetry, not an estimate of real-world detection performance, and it must not be generalised to enterprise deployment.

Measured paragraph:

> An authorised Sysmon collection was completed on one isolated, snapshot-backed Windows 10 VM (build 10.0.19045, Sysmon 15.22, host-only network). It produced 32 Event ID 1 rows across 20 scenarios: 12 benign administrative workloads (17 rows) and 8 harmless LOLBin simulations (15 rows). The BITS scenario (T1197) could not run without a network connection, and T1548.002, T1569.002 and T1105 were recorded as not feasible for the reasons in `docs/vm_run_log.txt`. The VM check was limited to the scenarios actually run on one isolated, snapshot-backed Windows VM. It is an external sanity check of transfer to raw Sysmon Event ID 1 telemetry, not an estimate of real-world detection performance, and it must not be generalised to enterprise deployment.

If `docs/vm_authorisation.md` were marked **NOT AUTHORISED**, the VM check would not have happened. It would then belong in Limitations and future work, not in the results.

## 8. Files owned by this workstream

- `src/vm_schema_adapter.py` - the adapter
- `tests/test_vm_schema_adapter.py` - 18 adapter tests
- `docs/vm_authorisation.md` - instructor approval
- `docs/vm_run_log.txt` - collected scenarios, timings, failures, and rollback
- `docs/vm_missing_fields.txt` - generated per run; do not edit by hand
