SentinelLOLBins - Deterministic Sigma-Style Rules (Experiment E1)
===============================================================

This directory contains the hand-written, deterministic rule baseline for
SentinelLOLBins Experiment E1 (rules-only detector). E1 tests only the
Sigma-style rules; the frozen ML models are compared against them later in the
hybrid stage.

Layout:
  *.yml          Sigma-style rule definitions (one or more rules per file)
  rule_engine.py Python engine implementing score_event() / score_dataframe()
  tests/         Unit tests for the rule engine and the rules themselves
  run_rules.py   CLI runner that produces the per-event and summary CSVs

Rule format (declarative and auditable):
  - id:          stable rule identifier (e.g. RULE-PS-001)
  - title:       short human title
  - attack:      MITRE ATT&CK technique id (e.g. T1059.001)
  - severity:    low | medium | high | critical
  - applies_to_process: [image names] - implicit AND gate on process_name
  - conditions:  any / all / not composition of
                   process_is, parent_is, command_line_regex, path_regex
  - reason:      human readable reason text
  - references:  ATT&CK reference URLs

Condition semantics:
  - process_is:      process_name (lowercase image name) must equal one of the listed names
  - parent_is:       parent_process (lowercase image name) must equal one of the listed names
  - command_line_regex: case-insensitive regex over command_line (then cmd_normalized)
  - path_regex:      case-insensitive regex over command line / image path
  - any / all / not: boolean composition over sub-conditions

The engine is deterministic (no randomness, no training, no data access beyond
the event fields listed above) and exposes:

  score_event(row: dict) -> dict
      {
        "matched_any": bool,
        "matched_rule_ids": ["RULE-PS-001", ...],
        "reasons": ["human readable reason", ...],
        "attack_ids": ["T1059.001", ...],
        "severity_max": "low" | "medium" | "high" | "critical" | None
      }

  score_dataframe(df) -> pd.DataFrame
      One row per input event, same order, columns:
      record_id, matched_any, n_rules_matched, matched_rule_ids, reasons,
      attack_ids, severity_max

Outputs produced by the runner (event level, any rule match == flagged):
  results/rules_test.csv      one row per test event (all events kept, no drops)
  results/rules_holdout.csv   one row per holdout event (all events kept)
  results/rules_long.csv       one row per (event, matched rule) pair
  results/rules_summary.csv   precision / recall / F1 / FPR and tp / fp / fn / tn
  results/rules_benign_heavy.csv benign-heavy false-alarm view

Input contract: E1 uses the ORIGINAL dataset and splits (never the debiased
variants). test = 14,029 events (7,601 benign / 6,428 malicious); holdout =
8,122 malicious-only events (withheld techniques). Decisions are made with a
single fixed threshold of "any rule match".

--------------------------------------------------------------------------------
Rules
--------------------------------------------------------------------------------

RULE-PS-001 - PowerShell encoded command (T1059.001, severity: high)
  applies_to_process: powershell.exe, pwsh.exe
  logic: any of
      - command_line_regex: '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'
      - command_line_regex: '(?i)-e\s+[A-Za-z0-9+/=]{20,}'
  reason: PowerShell used with an encoded command or short encoded argument
  behaviour-based rationale: flags PowerShell launches carrying an encoded or
      short-encoded payload, independent of the executable name alone.

RULE-PS-002 - PowerShell remote script download or execution (T1059.001, high)
  applies_to_process: powershell.exe, pwsh.exe
  logic: any of
      - command_line_regex: '(?i)downloadstring'
      - command_line_regex: '(?i)invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b'
      - command_line_regex: '(?i)invoke-expression|\biex\b'
      - command_line_regex: '(?i)new-object\s+system\+net\+webclient'
  reason: PowerShell fetched or invoked a remote or script payload
  behaviour-based rationale: detects script acquisition / execution behaviours
      rather than naming the interpreter.

RULE-WMI-001 - WMI process creation (T1047, high)
  applies_to_process: wmiprvse.exe, wmic.exe
  logic: any of
      - command_line_regex: '(?i)process call create'
      - command_line_regex: '(?i)createprocess'
  reason: WMI provider created a new process (WMI-based process execution)
  behaviour-based rationale: detects WMI-mediated process creation behaviour.

RULE-PSEXEC-001 - PsExec remote service execution (T1021.002, high)
  applies_to_process: psexec.exe, services.exe, sc.exe
  logic: any of
      - command_line_regex: '(?i)^\\\\[^\s]+'      # UNC path (remote share)
  reason: PsExec-style remote execution via UNC path or service control
  behaviour-based rationale: detects remote execution transport behaviour.

RULE-MSHTA-001 - mshta script execution (T1218.005, high)
  applies_to_process: mshta.exe
  logic: any of
      - command_line_regex: '(?i)-File\s+[^\s]+'
      - command_line_regex: '(?i)http[s]?://'
  reason: mshta launched a script or hosted content
  behaviour-based rationale: detects mshta usage to launch scripts/hosted content.

RULE-RUNDLL32-001 - rundll32 pass-through execution from non-shell parent (T1218.011, medium)
  applies_to_process: rundll32.exe
  logic: all: [ parent_is in {winword.exe, excel.exe, powerpnt.exe, outlook.exe,
                                 msaccess.exe, onenote.exe, chrome.exe, firefox.exe,
                                 iexplore.exe} ]
  reason: rundll32 executed by a document or browser parent (pass-through execution)
  behaviour-based rationale: uses parent-process context (document/browser) plus
      the signed-binary proxy to flag pass-through execution.

RULE-CMSTP-001 - CMSTP signed installer proxy execution (T1218.003, high)
  applies_to_process: cmstp.exe
  logic: any of
      - command_line_regex: '(?i)/i\s+\S+\.inf'
  reason: CMSTP used to install a signed installer package (proxy execution)
  behaviour-based rationale: detects installer-proxy usage via command line.

RULE-MSBUILD-001 - MSBuild inline task or project execution (T1059, high)
  applies_to_process: msbuild.exe
  logic: any of
      - command_line_regex: '(?i)\.msbuild\.xml'
      - command_line_regex: '(?i)\.proj\b'
      - command_line_regex: '(?i)\.targets\b'
      - command_line_regex: '(?i)customtaskfactory'
  reason: MSBuild executed a build project or inline task
  behaviour-based rationale: detects build-tool-mediated script execution.

RULE-BITSADMIN-001 - BITSAdmin payload download (T1197, high)
  applies_to_process: bitsadmin.exe
  logic: any of
      - command_line_regex: '(?i)/add\b'
      - command_line_regex: '(?i)/transfer'
  reason: BITSAdmin created or transferred a download job (payload staging)
  behaviour-based rationale: detects BITS download-job behaviour used for
      payload staging / transfer.

RULE-CERTUTIL-001 - Certutil download or decode utility (T1105, high)
  applies_to_process: certutil.exe
  logic: any of
      - command_line_regex: '(?i)-urlcache'
      - command_line_regex: '(?i)https?://'
      - command_line_regex: '(?i)-decode'
  reason: Certutil used for download, fetch or payload decode
  behaviour-based rationale: detects certutil usage as a download / decode tool
      (benign admin use such as 'certutil -store' is not matched).

RULE-REGSVR32-001 - Regsvr32 scriptlet execution (T1218.010, medium)
  applies_to_process: regsvr32.exe
  logic: any of
      - command_line_regex: '(?i)\.(js|vbs|jscript|wscript|wsf|vbe|hta|ps1)\b'
  reason: Regsvr32 used to execute a scriptlet or script-backed binary
  behaviour-based rationale: detects script-backed binary execution via
      regsvr32 command line.

--------------------------------------------------------------------------------
Reporting / interpretation notes
--------------------------------------------------------------------------------

- E1 decision rule: an event is flagged if and only if at least one rule
  matched (matched_any = 1). Single threshold of "any match".
- Precision / recall / F1 / FPR are computed at event level on the test set;
  the holdout set is malicious-only so FPR is undefined there (reported as
  blank with counts in the notes column).
- Benign-heavy view: test benign events + a 1:100 malicious sample; false
  alarms per 10,000 benign events are reported for the rules arm.
- The rules are hand-written and were not tuned on test or holdout. Development
  use of train/val is permitted, final evaluation happens once on test/holdout.
- A rule that never fires is still a valid result and should be reported as such.
- Rules never read label, mitre_technique, command_source, rule_category,
  dataset_origin, record_id patterns or file paths that encode the answer, and
  no rule keys on the synthetic WLGT_* / -wlgtRef:* / wlgt_* benign markers.
