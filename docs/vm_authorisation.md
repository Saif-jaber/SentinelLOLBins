# VM Validation — Written Authorisation Note

**STATUS: NOT AUTHORISED — do not run any VM experiments until this form is
completed and signed by the instructor.**

Fill every field. One paragraph of prose is enough for the body; the checklist
drives the sign-off. Keep this file in git (no secrets, no credentials).

- Authorised by (instructor name / role):
- Date of authorisation (UTC):
- VM name / ID and hypervisor (e.g. Hyper-V, VMware Workstation, VirtualBox):
- VM network state during tests (host-only / disconnected / NAT + no internet):
- Scope explicitly permitted (check all that apply):
  - [ ] Isolated Windows VM only
  - [ ] Sysmon install with maintained config
  - [ ] Benign admin workloads (list in docs/vm_run_log.txt)
  - [ ] Harmless attack simulations (calc.exe / notepad.exe / local .inf/.hta/.js only)
  - [ ] Sysmon Event ID 1 and Event ID 3 collection
  - [ ] Atomic Red Team or equivalent, local files only, no network beyond the VM
- Explicitly NOT permitted (default — strike through only if instructor agrees in writing):
  - Real malware, credential dumping, lateral movement, persistence, any internet-facing traffic, any production or shared systems
- Snapshot taken before changes (name / timestamp):
- Rollback plan (who rolls back, when, how verified):
- Approval signature / date:

---

### Body (free text)

> In one short paragraph: who authorised the work, the VM identifier, the date,
> the network state, the rollback plan, and which scenario list (from
> docs/NOTES_TO_HAITHAM_SYSMON.txt) was approved. Sign and date it.
>
