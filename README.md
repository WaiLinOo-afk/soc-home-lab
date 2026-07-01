# SOC Home Lab — Splunk SIEM + MITRE ATT&CK Detection

Home lab I built to practice SOC analyst skills. Set up Splunk as a SIEM, forwarded logs from a Windows VM and Kali Linux, installed Sysmon, then simulated attacks using Atomic Red Team and wrote detection rules in Splunk.

---

## Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| Windows VM | Windows 11 | 192.168.56.130 | Splunk Enterprise + target |
| Kali VM | Kali Linux | 192.168.56.129 | Attacker |

Both VMs on VirtualBox with a host-only network adapter.

---

## Setup Overview

1. **Splunk Enterprise** — installed on Windows VM, created indexes (wineventlog, sysmon, syslog), receiving on port 9997
2. **Sysmon** — installed with SwiftOnSecurity config, forwarded to Splunk via Universal Forwarder
3. **Universal Forwarder (Windows)** — forwarding Security logs + Sysmon to localhost:9997
4. **Universal Forwarder (Kali)** — transferred .deb via Python HTTP server, forwarding dpkg.log
5. **Atomic Red Team** — installed on Windows VM, ran attack simulations
6. **Kali attacks** — Nmap recon + SMB brute force with smbclient

Full setup commands in [`docs/setup-notes.md`](docs/setup-notes.md)

---

## Attack Simulations

| Technique | Tool | Result |
|---|---|---|
| T1003.001 — LSASS Memory | Atomic Red Team | Blocked by Defender; attempt visible in PowerShell process logs |
| T1059.001 — PowerShell | Atomic Red Team | 3 hits in Splunk — CommandLine shows encoded payload flags |
| T1053.005 — Scheduled Task | Atomic Red Team | 7 hits — schtasks.exe /create with task names AtomicTask, EventViewerBypass |
| T1021.002 — SMB | Atomic Red Team | Admin share mapped successfully; no Splunk hit (loopback gap) |
| T1046 — Network Recon | Nmap (Kali) | Port 445 open, rest filtered |
| T1110 — Brute Force | smbclient loop (Kali) | 10x EventCode 4625 detected; account locked out at attempt 11 |

Detection queries → [`detection-rules/splunk_queries.md`](detection-rules/splunk_queries.md)

---

## Known Issues

- T1003.001: No EventID 10 (ProcessAccess) — Defender killed the process before Sysmon could log it
- T1021.002: Loopback SMB doesn't generate EventCode 4624 LogonType=3
- T1046: Host-based logs can't reliably detect port scans
- T1053.005: EventCode 4698 didn't fire on Windows 11 — used Sysmon process logs instead
- Kali: No auth.log (journald) — forwarding dpkg.log instead

---

## Tools Used

- [Splunk Enterprise](https://www.splunk.com/)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) + [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)
- [Nmap](https://nmap.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [VirtualBox](https://www.virtualbox.org/)
