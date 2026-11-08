# VM Validation — Written Authorisation Note

STATUS: AUTHORISED — permission given by the instructor on 30/10/2026.
Attach the written confirmation (email / Blackboard message / signed copy)
before submission.

- Authorised by (instructor name / role): Sapna Sadhwani (Instructor / Doctor)
- Date of authorisation (UTC): 30/10/2026
- VM name / ID and hypervisor: `SentinalLOLbins` — VirtualBox VM ID `d7bc92eb-0a23-4eab-acfd-3dbc7fb8efeb`; Oracle VirtualBox 7.2.22 r175245; Windows 10 (64-bit) guest
- VM network state during tests: NAT only while downloading/installing tools; Host-only or disconnected during collection; no internet during attack simulations.
- Scope explicitly permitted (check all that apply):
  - [x] Isolated Windows VM only
  - [x] Sysmon install with maintained config
  - [x] Benign admin workloads (list in docs/vm_run_log.txt)
  - [x] Harmless attack simulations (calc.exe / notepad.exe / local .inf/.hta/.js only)
  - [x] Sysmon Event ID 1 and Event ID 3 collection
  - [x] Atomic Red Team or equivalent, local files only, no network beyond the VM
- Explicitly NOT permitted (default — strike through only if instructor agrees in writing):
  - Real malware, credential dumping, lateral movement, persistence, any internet-facing traffic, any production or shared systems
- Snapshot taken before changes (name / timestamp): `clean-pre-sysmon` — take immediately before Sysmon install and record the exact UTC timestamp in `docs/vm_run_log.txt`. Secondary snapshot: `sysmon-ready`, taken after Sysmon Event ID 1 is verified and before any scenario.
- Rollback plan (who rolls back, when, how verified): Haitham Wail Omer restores `clean-pre-sysmon` in VirtualBox immediately after collection. Verify by confirming the `Sysmon64` service is absent and `Microsoft-Windows-Sysmon/Operational` has no Event ID 1 records. Record the rollback UTC timestamp and verification method in `docs/vm_run_log.txt`.
- Approval signature / date: Sapna Sadhwani (Instructor / Doctor) — 30/10/2026. Written approval held by the team; attach the email/Blackboard message or signed copy before submission.
- Written confirmation: Instructor email / Blackboard message / signed copy is held by the team and must be attached to the repository before submission.

---

### Body (free text)

> Sapna Sadhwani (Instructor / Doctor) authorised Haitham Wail Omer on
> 30/10/2026 to use the isolated VirtualBox VM `SentinalLOLbins`
> (Windows 10 64-bit) for SentinelLOLBins VM validation. The VM will run on
> Host-only networking or with the network disconnected during collection.
> Only harmless payloads will be used (calc.exe, notepad.exe, local .inf/.hta/.js
> files). Sysmon Event ID 1 and Event ID 3 will be collected. The VM will be
> rolled back to the `clean-pre-sysmon` snapshot after collection, and the
> rollback will be recorded in `docs/vm_run_log.txt`. The approved scenario list
> is the benign and attack list in `docs/NOTES_TO_HAITHAM_SYSMON.txt` §4,
> limited to the techniques explicitly listed in the signed scope above.
> The "Atomic Red Team or equivalent" permission covers manual equivalent
> commands using local files only, where Atomic Red Team is not installed.

### Technical details at time of authorisation

- Hypervisor: Oracle VirtualBox 7.2.22 r175245
- VM name: `SentinalLOLbins`
- VM ID: `d7bc92eb-0a23-4eab-acfd-3dbc7fb8efeb`
- Guest OS type: Windows 10 (64-bit)
- Current RAM / vCPU: 2048 MB / 1 vCPU (recommend 4096 MB / 2 vCPU before Sysmon)
- Shared clipboard: disabled
- Drag and drop: disabled
- Current network adapter: NAT (change to Host-only or disconnected before collection)
