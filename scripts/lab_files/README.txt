SentinelLOLBins - harmless lab files
====================================

These files are for the authorised, isolated Windows 10 VM only.
They do not contain malware. The payloads only open Calculator (or Notepad).

Copy these files into C:\Lab inside the VM:
  hello.hta   - mshta test (opens Calculator)
  hello.inf   - cmstp test (opens Calculator)
  hello.sct   - regsvr32 scriptlet test (opens Calculator)
  hello.proj  - MSBuild test (opens Calculator)
  source.txt  - BITS local copy source
  input.txt   - certutil encode/decode input

No file here contacts the network.
