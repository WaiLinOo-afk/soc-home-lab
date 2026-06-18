# SOC Home Lab — Splunk SIEM + MITRE ATT&CK Detection

A home lab I built to practice SOC analyst skills. Set up Splunk Enterprise as a SIEM, forwarded logs from a Windows VM and Kali Linux, installed Sysmon for endpoint visibility, then simulated real attacks using Atomic Red Team and detected them in Splunk.

This was mainly built to get hands-on experience with the tools I'd actually use as a SOC analyst — log forwarding, writing detection queries, and mapping findings to MITRE ATT&CK.

---

## Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| Windows VM | Windows 11 | 192.168.56.128 | Splunk Enterprise + Target |
| Kali VM | Kali Linux | 192.168.56.129 | Attacker |

Both VMs running on VirtualBox with a host-only network adapter.

---

## What's in this repo

```
soc-home-lab/
├── splunk-configs/         # inputs.conf and outputs.conf for the forwarders
├── sysmon/                 # Sysmon config (SwiftOnSecurity)
├── detection-rules/        # Splunk SPL queries mapped to MITRE ATT&CK
├── attack-outputs/         # Raw terminal output from Atomic Red Team tests
├── screenshots/            # Evidence screenshots from the lab
└── docs/                   # Step-by-step setup notes
```

---

## Setup Overview

### 1. Splunk Enterprise
- Installed on Windows VM (port 8000)
- Created 3 indexes: `wineventlog`, `sysmon`, `syslog`
- Configured receiving on port 9997

### 2. Sysmon
- Installed with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)
- Captures process creation, network connections, file changes, etc.
- Forwarded to Splunk via Universal Forwarder

### 3. Universal Forwarder — Windows
- Forwarding Windows Security logs + Sysmon to `127.0.0.1:9997`
- Had to run the forwarder as `LocalSystem` to fix channel access permission issue on Sysmon/Operational log

### 4. Universal Forwarder — Kali
- Installed manually (splunk.com was blocked on Kali's network, transferred file via Python HTTP server from Windows)
- Forwarding `/var/log/dpkg.log` and `/var/log/vmware-network.log` (Kali uses journald, no auth.log/syslog)
- Had to add a Windows firewall rule to allow inbound 9997

---

## Attack Simulations (MITRE ATT&CK)

Used [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) to simulate attacks on the Windows VM and detect them in Splunk.

| Technique | Tactic | Tool | Result |
|---|---|---|---|
| T1003.001 — LSASS Memory | Credential Access | Atomic Red Team | Blocked by Defender, but Sysmon still logged the attempt |
| T1059.001 — PowerShell | Execution | Atomic Red Team | Multiple tests ran, including NTFS ADS access |
| T1053.005 — Scheduled Task | Persistence | Atomic Red Team | Tasks created, Calculator + Event Viewer launched as PoC |
| T1021.002 — SMB Lateral Movement | Lateral Movement | Atomic Red Team | Admin share mapped successfully |
| T1046 — Network Recon | Discovery | nmap (Kali) | Port 445 (SMB) identified as open |
| T1110 — Brute Force | Credential Access | Hydra (Kali) | 13 failed login events (EventCode 4625) in Splunk |

> **Note on T1003.001:** Windows Defender blocked execution but the *attempt* was still logged by Sysmon. Prevention doesn't mean invisibility.

> **Note on T1046:** Nmap scans aren't logged by Windows Security event logs natively. Real detection needs IDS/IPS or network flow analysis.

---

## Detection Queries

See [`detection-rules/splunk_queries.md`](detection-rules/splunk_queries.md) for all SPL queries.

Quick example — detecting brute force:
```
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| stats count by src_ip | sort -count
```

---

## Screenshots

### Splunk Setup
| | |
|---|---|
| ![](screenshots/17-splunk-index-syslog.png) | ![](screenshots/18-splunk-index-sysmon.png) |
| Index: syslog | Index: sysmon |
| ![](screenshots/19-splunk-index-wineventlog.png) | ![](screenshots/12-soc-dashboard.png) |
| Index: wineventlog | SOC Dashboard |

### T1003.001 — LSASS Credential Dumping
![](screenshots/01-T1003.001-lsass-dump-attempt.png)
![](screenshots/02-T1003.001-lsass-dump-attempt-2.png)
![](screenshots/21-T1003.001-splunk-sysmon-detection.png)

### T1059.001 — PowerShell Execution
![](screenshots/07-T1059.001-powershell-execution-1.png)
![](screenshots/08-T1059.001-powershell-execution-2.png)
![](screenshots/09-T1059.001-powershell-execution-3.png)
![](screenshots/10-T1059.001-powershell-execution-4.png)

### T1053.005 — Scheduled Task Persistence
![](screenshots/05-T1053.005-scheduled-task-sim-1.png)
![](screenshots/06-T1053.005-scheduled-task-sim-2.png)
![](screenshots/04-T1053.005-scheduled-task-proof.png)
![](screenshots/15-T1053.005-sysmon-detection.png)

### T1021.002 — SMB Lateral Movement
![](screenshots/03-T1021.002-smb-admin-share-access.png)
![](screenshots/14-T1021.002-splunk-smb-detection.png)

### T1046 — Network Recon (Kali)
![](screenshots/20-T1046-nmap-scan-results.png)

### T1110 — Brute Force (Kali + Hydra)
![](screenshots/11-T1110-hydra-rdp-bruteforce.png)
![](screenshots/13-T1110-splunk-detection-4625.png)

### Windows Defender — Atomic Red Team Detections
![](screenshots/16-windef-atomic-redteam-alerts.png)

---

## Known Issues / Gotchas

- EventCode 4698 (scheduled task creation) didn't fire on Windows 11 even with audit policy enabled — used Sysmon process monitoring as workaround
- EventCode 4624 LogonType=3 didn't appear for the SMB test because it was loopback
- Sysmon/Operational log channel only allows LocalSystem/Administrators — forwarder needs to run as LocalSystem
- Kali doesn't have `/var/log/auth.log` (uses journald) — used dpkg.log and vmware-network.log instead

---

## Tools Used

- [Splunk Enterprise](https://www.splunk.com/) — SIEM
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — Endpoint telemetry
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) — Attack simulation
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) — Brute force
- [Nmap](https://nmap.org/) — Network recon
- [MITRE ATT&CK](https://attack.mitre.org/) — Framework reference
