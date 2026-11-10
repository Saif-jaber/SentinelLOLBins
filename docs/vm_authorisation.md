# VM Validation: Written Authorisation

**Status:** AUTHORISED. Permission was given by the instructor on 30/10/2026. The written confirmation (email, Blackboard message, or signed copy) must be attached before submission.

- Authorised by: Sapna Sadhwani (Instructor / Doctor)
- Date of authorisation (UTC): 30/10/2026
- VM: `SentinalLOLbins`, VirtualBox VM id `d7bc92eb-0a23-4eab-acfd-3dbc7fb8efeb`
- Hypervisor: Oracle VirtualBox 7.2.22 r175245
- Guest: Windows 10, 64-bit
- Network during tests: NAT only while downloading and installing tools; host-only or disconnected during collection; no internet during attack simulations.

## Permitted scope

- [x] Isolated Windows VM only
- [x] Sysmon installed with a maintained configuration
- [x] Benign administrative workloads
- [x] Harmless attack simulations using only `calc.exe`, `notepad.exe`, and local `.inf`, `.hta`, or `.js` files
- [x] Sysmon Event ID 1 and Event ID 3 collection
- [x] Atomic Red Team or equivalent local commands, with no network beyond the VM

The following were not permitted: real malware, credential dumping, lateral movement, persistence, internet-facing traffic, and any production or shared system.

## Snapshots and rollback

- Snapshot before changes: `clean-pre-sysmon`, taken immediately before the Sysmon install. The exact UTC time is in `docs/vm_run_log.txt`.
- Second snapshot: `sysmon-ready`, taken after Event ID 1 was verified and before the first scenario.
- Rollback: Haitham Wail Omer restores `clean-pre-sysmon` in VirtualBox immediately after collection. The check confirms that the `Sysmon64` service is absent and that `Microsoft-Windows-Sysmon/Operational` contains no Event ID 1 records. The rollback time and verification method are recorded in `docs/vm_run_log.txt`.
- Approval: Sapna Sadhwani (Instructor / Doctor), 30/10/2026.
- Written confirmation: held by the team and to be attached to the repository before submission.

## Authorisation text

> Sapna Sadhwani (Instructor / Doctor) authorised Haitham Wail Omer on 30/10/2026 to use the isolated VirtualBox VM `SentinalLOLbins` (Windows 10 64-bit) for SentinelLOLBins validation. During collection the VM will use host-only networking or no network connection. Only harmless payloads will be used: `calc.exe`, `notepad.exe`, and local `.inf`, `.hta`, or `.js` files. Sysmon Event ID 1 and Event ID 3 will be collected. The VM will be rolled back to the `clean-pre-sysmon` snapshot after collection, and the rollback will be recorded in `docs/vm_run_log.txt`. The approved scenario list is the benign and attack list recorded in `docs/vm_run_log.txt`, limited to the techniques in the signed scope above. The permission for "Atomic Red Team or equivalent" covers manual equivalent commands using local files where Atomic Red Team is not installed.

## Technical details at authorisation

- Hypervisor: Oracle VirtualBox 7.2.22 r175245
- VM name: `SentinalLOLbins`
- VM id: `d7bc92eb-0a23-4eab-acfd-3dbc7fb8efeb`
- Guest OS: Windows 10 (64-bit)
- RAM / vCPU at the time: 2048 MB / 1 vCPU (4096 MB / 2 vCPU recommended before Sysmon)
- Shared clipboard: disabled
- Drag and drop: disabled
- Network adapter at the time: NAT; changed to host-only or disconnected before collection
