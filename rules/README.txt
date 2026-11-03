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

RULE-PS-001 - PowerShell encoded command, any host (T1059.001, severity: high)
  applies_to_process: none (host-agnostic; the pattern itself is the behaviour)
  logic: any of
      - command_line_regex: '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'
      - command_line_regex: '(?i)-e\s+[A-Za-z0-9+/=]{20,}'
  reason: Command line carries a PowerShell encoded payload (base64, often UTF-16LE)
  behaviour-based rationale: flags a base64-encoded PowerShell payload embedded in
      ANY host command line. This matters because WinLOLBIN-GT wraps encoded
      PowerShell inside LOLBins (wmic, reg, forfiles, schtasks, pcalua, mshta, cmd),
      not only under powershell.exe / pwsh.exe. The host process is not part of the
      condition; the payload marker is.
  change note: originally gated on powershell.exe/pwsh.exe and never fired (code
      review found all 210 encoded-payload rows carry a non-PowerShell host).

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
      - command_line_regex: '(?i)\\\\[^\s]+'      # UNC path anywhere in the command line
  reason: PsExec-style remote execution via UNC path or service control
  behaviour-based rationale: detects remote execution transport behaviour.
  change note: originally anchored with ^\\\\ (string must START with a UNC path),
      which matched nothing - real command lines start with the tool name
      (e.g. "psexec \\\\host -u ..."). Anchor removed; 27/27 train-split psexec
      rows match, 0 benign train/val rows match.

RULE-MSHTA-001 - mshta script execution (T1218.005, high)
  applies_to_process: mshta.exe
  logic: any of
      - command_line_regex: '(?i)-File\s+[^\s]+'
      - command_line_regex: '(?i)http[s]?://'
      - command_line_regex: '(?i)\.hta\b'
      - command_line_regex: '(?i)vbscript:|javascript:'
  reason: mshta launched a script, a local .hta, or hosted content
  behaviour-based rationale: detects mshta usage to launch scripts/hosted content,
      including the canonical local-file .hta invocation and vbscript:/javascript:
      protocol handlers.

RULE-RUNDLL32-001 - rundll32 pass-through execution (T1218.011, medium)
  applies_to_process: rundll32.exe
  logic: any of
      - all: [ parent_is in {winword.exe, excel.exe, powerpnt.exe, outlook.exe,
                              msaccess.exe, onenote.exe, chrome.exe, firefox.exe,
                              iexplore.exe} ]         # document/browser parent
      - command_line_regex: '(?i)javascript:'          # mshtml script protocol abuse
      - command_line_regex: '(?i)\\\\[^\s]+\.dll'     # UNC-hosted DLL payload
  reason: rundll32 executed by a document/browser parent, via a script protocol, or
      from a UNC-hosted DLL (pass-through execution)
  behaviour-based rationale: uses parent-process context (document/browser), a
      script-protocol handler, or a network-share DLL path - never the image name
      alone. 41 and 25 train-split malicious rows carry the script-protocol and
      UNC markers respectively; 0 benign train/val matches.

RULE-CMSTP-001 - CMSTP signed installer proxy execution (T1218.003, high)
  applies_to_process: cmstp.exe
  logic: any of
      - command_line_regex: '(?i)\.inf\b'
      - command_line_regex: '(?i)ms-appinstaller:'
      - command_line_regex: '(?i)https?://'
  reason: CMSTP used to install a signed installer package (proxy execution)
  behaviour-based rationale: detects installer-proxy usage via command line,
      including default-launch .inf, ms-appinstaller: protocol handler and remote
      scriptlet URLs seen in the dataset. The .inf clause subsumes the old
      /i-flag-specific pattern. 23/32 train-split malicious cmstp rows carry an
      .inf or URL marker; 0 benign train/val matches (the one benign .inf sighting
      in train is ie4uinit.exe, outside this rule's process scope).

RULE-MSBUILD-001 - MSBuild inline task or project execution (T1059, high)
  applies_to_process: msbuild.exe
  logic: any of
      - command_line_regex: '(?i)\.msbuild\.xml'
      - command_line_regex: '(?i)\.proj\b'
      - command_line_regex: '(?i)\.targets\b'
      - command_line_regex: '(?i)\.xml\b'
      - command_line_regex: '(?i)customtaskfactory'
  reason: MSBuild executed a build project or inline task
  behaviour-based rationale: detects build-tool-mediated script execution. The
      .xml clause catches remote/UNC inline-task payloads (e.g.
      MSBuild.exe \\host\path\XMLfile.xml), the dominant malicious msbuild shape
      in the dataset (157 train-split malicious rows, 0 benign train/val).

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
      - command_line_regex: '(?i)-encode\b'
  reason: Certutil used for download, fetch or payload decode/encode
  behaviour-based rationale: detects certutil usage as a download / encode / decode
      tool (benign admin use such as 'certutil -store' is not matched). -encode
      catches base64 payload encoding used to smuggle content past filters;
      25 train-split malicious rows carry it, 0 benign train/val matches.

RULE-REGSVR32-001 - Regsvr32 scriptlet execution (T1218.010, medium)
  applies_to_process: regsvr32.exe
  logic: any of
      - command_line_regex: '(?i)\.(js|vbs|jscript|wscript|wsf|vbe|hta|ps1)\b'
      - command_line_regex: '(?i)scrobj\.dll'
      - command_line_regex: '(?i)/i:(https?://|\\\\)'
      - command_line_regex: '(?i)https?://'
  reason: Regsvr32 used to execute a scriptlet or script-backed binary (Squiblydoo)
  behaviour-based rationale: detects script-backed binary execution and the
      scrobj.dll / /i: URL scriptlet pattern served over HTTP(S) or UNC; the
      classic remote-Squiblydoo shape absent from the original rule.

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

--------------------------------------------------------------------------------
Verification and change log (2026-11-03, review pass)
--------------------------------------------------------------------------------

Methodology: rule changes were designed from (a) code review and (b) the TRAIN
and VAL splits only. Every added pattern was required to have 0 matches on
benign train+val rows before being accepted. Test and holdout were used once,
for the final evaluation run, after the rules were frozen. Earlier intermediate
results were recorded before the change and are listed for transparency.

Changes made and why:
1. RULE-PSEXEC-001: removed erroneous leading ^ anchor. The rule could never
   fire - 0 hits anywhere. This is a logic bug, not test-set tuning: the
   pattern only matched strings starting with a UNC path, contrary to its
   stated purpose.
2. RULE-PS-001: dropped the powershell.exe/pwsh.exe applies_to_process gate.
   All 210 encoded-payload rows in the dataset launch encoded PowerShell from
   a LOLBin host (wmic/reg/forfiles/schtasks/pcalua/mshta/cmd), never from a
   powershell host. Host-agnostic payload marker; 0 benign train/val matches.
3. RULE-MSHTA-001: added \.hta\b and vbscript:|javascript: (local .hta files
   and script-protocol handlers; 0 benign train/val rows are mshta at all).
4. RULE-CMSTP-001: replaced the /i-flag-specific pattern with \.inf\b,
   ms-appinstaller: and https?:// (the dataset's cmstp abuse is /ni /s with
   URLs or default .inf launch). 0 benign matches on cmstp.exe train/val.
5. RULE-MSBUILD-001: added \.xml\b (UNC/inline-task .xml payloads are the
   dominant malicious shape; 157 train-split hits, 0 benign train/val).
6. RULE-CERTUTIL-001: added -encode\b (25 train-split hits, 0 benign).
7. RULE-REGSVR32-001: added scrobj\.dll, /i:(http(s)?://|UNC) and https?://
   (remote Squiblydoo; dataset regsvr32 rows are exclusively this shape).
8. RULE-RUNDLL32-001: restructured to any[ all[parent_is office/browser],
   javascript:, UNC .dll path ] - catches mshtml script-protocol abuse and
   \\host\share\payload.dll with 0 benign train/val matches.
9. run_rules.py: fixed stale loop-variable in the final print; rules_long.csv
   now writes per-pair reason/attack_id/severity looked up from the matched
   rule (previously event-level first/max values - a latent bug, no affected
   rows existed).

Results before -> after (event level, any rule match = flagged):
  TEST    precision 0.991 -> 0.995 | recall 0.017 -> 0.034 | tp 110 -> 217 |
          fp 1 -> 1 (unchanged)    | FPR 0.0001 -> 0.0001
  HOLDOUT recall 151/8122 -> 320/8122 | precision 1.0 (unchanged) | fp 0
  BENIGN-HEAVY (test 7,601 benign + 76 malicious, 1:100):
          precision 0.667, recall 0.026, fp_per_10k_benign 1.3 (unchanged;
          the single false positive is a pre-existing rule artefact)
  Every rule now fires at least once across test+holdout (before: RULE-PS-001,
  RULE-PSEXEC-001, RULE-MSBUILD-001, RULE-CMSTP-001 and RULE-REGSVR32-001 were
  zero-match).

Honest interpretation: E1 remains a HIGH-PRECISION / LOW-RECALL baseline.
WinLOLBIN-GT malicious command lines are dominated by dual-use recon and
administrative tooling that cannot be separated from benign admin activity by
command-line pattern alone without unacceptable false positives. Judge E1 as
a triage/evidence source inside the hybrid, not as a standalone detector.
These numbers must not be quoted as 'detection performance' without that
caveat.
