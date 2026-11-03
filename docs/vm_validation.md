# SentinelLOLBins — VM Validation (Sysmon) Guide

**Owner:** Haitham Wail Omer (Rules & Windows validation)
**Implements:** Deliverable-1 methodology §3.6 (independent Sysmon validation), Experiment E4 external check
**Status:** Adapter and scoring runner built and tested on synthetic input. **VM execution NOT done. Instructor authorisation NOT yet given. No VM results exist.**

This guide covers everything from an empty VM to handing files to Saif for scoring.
Read `docs/NOTES_TO_HAITHAM_SYSMON.txt` first — it defines the required output
contract; this document operationalises it and does not override it.

---

## 0. What "done" looks like

1. `docs/vm_authorisation.md` filled in and signed off by the instructor **before** running anything.
2. Snapshot taken; VM network isolated (host-only or disconnected) for attack runs.
3. Sysmon installed with a maintained config; Event ID 1 verified.
4. Benign scenarios captured (≥8–10) + priority attack scenarios (T1218.007, T1218.003, T1548.002 first, then the rest in the notes), repeated 2–3× where time allows.
5. Files handed to Saif:
   - `data/raw/vm/sysmon_events.csv` (raw Event ID 1 rows + `scenario_id`)
   - `data/raw/vm/sysmon_network.csv` (Event ID 3 rows; or note it was skipped)
   - `data/raw/vm/scenarios.csv` (one row per run; `expected_label`, `technique_expected`)
   - `docs/vm_run_log.txt` (what ran, what failed, rollback timestamps)
6. Adapter run → `data/processed/vm_adapted.parquet` + `docs/vm_missing_fields.txt`.
7. VM rolled back to the pre-test snapshot.

## 1. Authorisation (blocking)

Copy `docs/vm_authorisation.md`, fill it in with the instructor, and do not proceed
until it is signed. The note must record: who authorised, VM name/ID, date,
network state, rollback plan, and the scenario list.

## 2. VM setup

1. Windows 10/11 VM, fully patched; **isolated network** (host-only adapter or cable out). No production access.
2. Set the clock to **UTC**; record all timestamps in UTC.
3. Take a **clean snapshot** named e.g. `pre-sysmon-validation`.
4. Install Sysmon (Sysinternals) with a maintained config (SwiftOnSecurity or sysmon-modular). Minimum: Event ID 1 (process creation) and Event ID 3 (network connection).
   - Record: Sysmon version, config filename + SHA-256, Windows build, VM name → these go in the report's limitations section and in `docs/vm_run_log.txt`.
5. Verify Event ID 1 is written:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```
6. Creating test files locally is fine; copy nothing from outside the lab.

## 3. Collection plan

See `docs/NOTES_TO_HAITHAM_SYSMON.txt` §4 for the scenario lists and the UTC
`[start_utc, end_utc]` tagging procedure. Key points:

- Benign workloads run as a normal user and as admin (whoami, ipconfig /all,
  tasklist, net user, systeminfo, certutil -store My, robocopy, schtasks /query, …).
- Attack simulations use harmless payloads only (calc.exe, notepad.exe, a local
  .inf / .hta / .js). **No real malware. No credential dumping. No lateral
  movement. No persistence beyond the snapshot.**
- Prioritise T1218.007 (msiexec), T1218.003 (cmstp) and T1548.002 — the models
  miss these most often.
- One scenario per technique; 2–3 repetitions if time allows.
- Tag every Event ID 1 row with its `scenario_id`; include the real parent
  chain (e.g. winword.exe → cmd.exe → certutil.exe).
- Export Event ID 1 rows inside the UTC window per scenario.

## 4. Building the adapted feature table

The frozen XGBoost model consumes the same 57 model-input columns as
`data/processed/sample_100k.parquet` (those expand to the internal 108
post-one-hot width inside `src/preprocess.py` — the VM file does NOT contain
one-hot columns).

Run on this repo (no VM required):

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

- Exactly the 57 model-input columns (verified name-for-name, same order,
  against `data/processed/sample_100k.parquet` minus the leakage/id columns),
  plus `record_id`, `scenario_id`, raw audit columns (`Image`, `CommandLine`,
  `ParentImage`, `User`, `IntegrityLevel`, …), and — if `--scenarios` is given —
  `expected_label` / `technique_expected` as **join keys, never features**.
- Record IDs are deterministic (`vm_` + sha1 of Computer|UtcTime|ProcessId|Image|CommandLine).
- **Never invents values.** Not-derivable columns stay NaN and are listed in
  `docs/vm_missing_fields.txt` with reasons:
  - `cmd_url_token_count`, `cmd_path_token_count`, `cmd_ip_token_count`,
    `cmd_b64_token_count` — the dataset generator's exact token regexes are not
    published and 92–98% partial matches would systematically miscalibrate the
    frozen model, so they are left missing. XGBoost handles NaN natively.
  - `flag_certutil_encode`, `flag_remote_file`, `flag_rundll32_js`,
    `flag_msbuild`, `flag_adsi`, `flag_cmd_slash_c` — generator templates not
    recoverable exactly (a systematically-wrong flag is worse than a missing one).
  - `signed_true` — NaN unless you pass a `signed_status` column
    (valid → 1; invalid/unsigned → 0). Compute it on the VM with
    `Get-AuthenticodeSignature (Get-Item <Image>).Status`.
  - `network_connection_true`, `has_destination` — from `--network` (Event ID 3);
    NaN when not collected.
  - `integrity_ordinal` — the dataset's ordinal mapping is unpublished; NaN.
- 16 behavioural `flag_*` columns **are** computed and were verified to match
  the dataset's own generator 100% on 20,000 train rows (see the module
  docstring for the list and method).
- `cmd_normalized` reproduces the dataset's entity templating (~87.5% byte-exact
  on train); `cmd_len` / `cmd_entropy` / `cmd_avg_token_len` are computed on it,
  matching the recovered dataset definitions.
- `parent_child_suspicious` is an **approximation** (office/script-host parent
  AND powershell/pwsh/cmd child) matched to the dataset evidence; the exact
  generator predicate is not published.
- Contract violations stop the run instead of guessing: missing required
  columns, or any row with an empty `Image`, aborts with a message.

## 5. Hand-off and scoring (Saif)

Saif scores `vm_adapted.parquet` with the frozen XGBoost (validation-selected
threshold 0.55) and optionally SecureBERT on `CommandLine`. Extra columns are
ignored by the saved preprocessor (remainder="drop"). Unseen VM process names
are fine (OneHotEncoder `handle_unknown="ignore"`). He reports:

- scenario-level recall on attack runs; FPR on benign runs; list of misses
  with raw command lines → `results/vm_*.csv`.

The scoring runner is committed and data-blocked: it refuses to run unless the
adapted file exists, so no VM numbers can appear without a genuine collection.

```powershell
python src/score_vm.py `
  --adapted data/processed/vm_adapted.parquet `
  --out-dir results
```

It uses the frozen XGBoost at the validation-selected threshold 0.55, adds the
deterministic high-severity rule override as an external hybrid check, and writes
`results/vm_predictions.csv`, `results/vm_scenario_summary.csv` and
`results/vm_summary.json` (including a disclaimer field).

## 6. Rollback and honesty

- Roll the VM back to `pre-sysmon-validation` when collection is done.
- The report must say this check covers **only the techniques actually run, on
  one VM**, and is not a real-world estimate. No claims of generalisation.
- If a scenario could not run (tooling unavailable, unsafe, out of scope),
  record it as "not feasible" with the reason in the run log.

### Report wording (use this, do not upgrade the claim)

> The VM check was limited to the scenarios actually run on one isolated,
> snapshot-backed Windows VM. It is an external sanity check of transfer to raw
> Sysmon Event ID 1 telemetry, not an estimate of real-world detection
> performance, and it must not be generalised to enterprise deployment.

If `docs/vm_authorisation.md` is still marked **NOT AUTHORISED**, the VM
validation did not happen. In that case it belongs in **Limitations and future
work**, not in the results section: state that no independent Windows telemetry
was collected because instructor authorisation was not obtained, and that the
adapter and scoring runner are ready for a future authorised run.

## 7. Files this workstream owns

- `src/vm_schema_adapter.py` — the adapter (this guide's step 4)
- `tests/test_vm_schema_adapter.py` — 18 unit tests, all passing
- `docs/vm_authorisation.md` — instructor sign-off template (fill before running)
- `docs/vm_run_log.txt` — run log template (fill during/after the session)
- `docs/vm_missing_fields.txt` — auto-generated per run (do not hand-edit)
