# SOC Home Lab: Splunk SIEM with MITRE ATT&CK Detection

Home lab built to practice SOC analyst skills — Splunk as the SIEM, Sysmon for endpoint telemetry, and Atomic Red Team for attack simulation.

---

## Table of Contents

1. [Lab Architecture](#lab-architecture)
2. [Environment Setup](#environment-setup)
3. [Step 1 — Splunk Enterprise](#step-1--splunk-enterprise)
4. [Step 2 — Sysmon](#step-2--sysmon)
5. [Step 3 — Universal Forwarder (Windows)](#step-3--universal-forwarder-windows)
6. [Step 4 — Universal Forwarder (Kali)](#step-4--universal-forwarder-kali)
7. [Step 5 — Attack Simulations](#step-5--attack-simulations)
8. [Step 6 — SOC Dashboard](#step-6--soc-dashboard)
9. [Detection Summary](#detection-summary)
10. [Known Issues](#known-issues)
11. [Skills Demonstrated](#skills-demonstrated)
12. [References](#references)

---

## Lab Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         VirtualBox                               │
│                                                                  │
│  ┌──────────────────────────────┐  ┌───────────────────────────┐ │
│  │   Windows 11 VM              │  │  Kali Linux VM            │ │
│  │   192.168.56.130             │  │  192.168.56.129           │ │
│  │                              │  │                           │ │
│  │  ┌───────────────────────┐   │  │  ┌─────────────────────┐ │ │
│  │  │ Splunk Enterprise     │   │  │  │ Splunk UF           │ │ │
│  │  │ SIEM (port 8000)      │◄──┼──┼──┤ Nmap / smbclient    │ │ │
│  │  │ Receiver port 9997    │   │  │  └─────────────────────┘ │ │
│  │  └───────────────────────┘   │  └───────────────────────────┘ │
│  │            ▲                 │                               │
│  │  ┌─────────┴─────────────┐   │                               │
│  │  │ Splunk Universal FWD  │   │                               │
│  │  │ Sysmon v15.20         │   │                               │
│  │  │ SwiftOnSecurity config│   │                               │
│  │  └───────────────────────┘   │                               │
│  └──────────────────────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

Data flow: Sysmon + Windows Security logs → Splunk Universal Forwarder → Splunk Enterprise (port 9997). Kali forwards Linux logs via its own forwarder.

---

## Environment Setup

| Component | Details |
|---|---|
| SIEM | Splunk Enterprise 10.4.0 |
| Windows VM | Windows 11 — 192.168.56.130 |
| Kali VM | Kali Linux — 192.168.56.129 |
| Virtualization | VirtualBox |
| Log Forwarder | Splunk Universal Forwarder v10.4.0 |
| Endpoint Monitoring | Sysmon v15.20 with SwiftOnSecurity config |
| Splunk Web UI | http://localhost:8000 |
| Receiving Port | 9997 |

---

## Step 1 — Splunk Enterprise

Downloaded the Windows .msi installer from splunk.com and installed on the Windows VM with default settings.

### Create Indexes

Settings → Indexes → New Index — created three separate indexes to keep data organized and queries fast:

| Index | Purpose |
|---|---|
| `wineventlog` | Windows Security and System event logs |
| `sysmon` | Sysmon endpoint telemetry |
| `syslog` | Kali Linux logs |

### Configure Receiving Port

Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port → `9997`

---

## Step 2 — Sysmon

Downloaded Sysmon from Microsoft Sysinternals and used the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) — a community ruleset that filters out noise while keeping useful signals.

### Installation

```powershell
cd C:\Users\<username>\Downloads\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Verify

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Key EventIDs used in this lab: **1** (Process Create), **3** (Network Connection), **11** (File Create)

---

## Step 3 — Universal Forwarder (Windows)

Downloaded the Windows 64-bit .msi from splunk.com. Set receiving indexer to `127.0.0.1:9997` during install (loopback since Splunk runs on the same machine).

### inputs.conf

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0
index = wineventlog

[WinEventLog://System]
disabled = 0
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

`renderXml = true` keeps the full XML structure so field extraction with `rex` works properly in Splunk.

### outputs.conf

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 127.0.0.1:9997
```

### Fix: Sysmon channel access

The forwarder was silently dropping all Sysmon events — the Sysmon/Operational log channel only allows LocalSystem/Administrators to read it, and the default SplunkForwarder service account doesn't have access.

```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

### Verify

```spl
index=wineventlog | head 10
index=sysmon | head 10
```

---

## Step 4 — Universal Forwarder (Kali)

Splunk.com was blocked on Kali's network so transferred the .deb via Python HTTP server from the Windows VM:

```powershell
# Windows VM
python -m http.server 8080
```

```bash
# Kali
wget http://192.168.56.130:8080/splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
sudo dpkg -i splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
```

### outputs.conf

```ini
[tcpout:default-autolb-group]
server = 192.168.56.130:9997
```

### inputs.conf

Kali uses `systemd-journald` so there's no `/var/log/auth.log` or `/var/log/syslog`. Used available log files instead:

```ini
[monitor:///var/log/dpkg.log]
index = syslog
sourcetype = linux_logs

[monitor:///var/log/vmware-network.log]
index = syslog
sourcetype = linux_logs
```

### Fix: Windows firewall blocking port 9997

```powershell
New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

---

## Step 5 — Attack Simulations

### Atomic Red Team Setup

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Defender flags things during install — add an exclusion:
```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

---

### T1003.001 — LSASS Memory Dump

**Tactic:** Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```powershell
Invoke-AtomicTest T1003.001
```

**Result:** All sub-tests blocked by Defender (Access Denied). The attempt still shows in Sysmon EventID 1 — process creation is logged even when the process is immediately killed.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*lsass*"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| where NOT like(Image, "%Photos%")
  AND NOT like(Image, "%SnippingTool%")
  AND NOT like(Image, "%PickerHost%")
| table _time, host, Image, CommandLine
| sort -_time
```

---

### T1059.001 — PowerShell Execution

**Tactic:** Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

```powershell
Invoke-AtomicTest T1059.001
```

**Result:** 3 hits in Splunk. CommandLine field shows `-EncodedCommandParamVariation` and `-Execute` flags from the test sub-tests.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*<EventID>1</EventID>*"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| where like(lower(Image), "%powershell%")
| where like(lower(CommandLine), "%-enc%")
  OR like(lower(CommandLine), "%-bypass%")
  OR like(lower(CommandLine), "%-nop%")
  OR like(lower(CommandLine), "%iex%")
| table _time, host, Image, CommandLine, ParentImage
| sort -_time
```

---

### T1053.005 — Scheduled Task Persistence

**Tactic:** Persistence | [T1053.005](https://attack.mitre.org/techniques/T1053/005/)

```powershell
Invoke-AtomicTest T1053.005
```

**Result:** 7 hits in Splunk. Tasks created: `ATOMIC-T1053.005`, `EventViewerBypass`, `CompMgmtBypass`, `Atomic task`, `spawn`, `T1053_005_OnStartup`, `T1053_005_OnLogon`. Calculator and Event Viewer launched as proof of execution.

**Note:** EventCode 4698 (scheduled task created) didn't fire on Windows 11 even with audit policy enabled via `auditpol`. Used Sysmon process monitoring instead.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*<EventID>1</EventID>*"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| where like(lower(Image), "%schtasks%")
  AND like(lower(CommandLine), "%/create%")
| table _time, host, User, Image, CommandLine
| sort -_time
```

```powershell
Invoke-AtomicTest T1053.005 -Cleanup
```

---

### T1021.002 — SMB Admin Share Access

**Tactic:** Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

```powershell
Invoke-AtomicTest T1021.002
```

**Sub-test results:**

| Test | Result | Notes |
|---|---|---|
| 1 — Net share by hostname | ❌ | Hostname `Target` not resolvable |
| 2 — Map `\\Target\C$` as drive | ✅ | Mapped as drive G:, Exit code 0 |
| 3 — PsExec execution | ❌ | PsExec not on system |
| 4 — Write to admin share | ✅ | Exit code 0 |

**Why Splunk didn't detect it:** Test 2 mapped `\\Target\C$` which resolved to localhost. Loopback SMB doesn't generate EventCode 4624 LogonType=3 — Windows only creates that event when there's an actual network hop. Same reason Sysmon EventID 3 didn't fire. Would work in a real multi-machine setup.

**Detection Query (multi-host):**
```spl
earliest=0 index=wineventlog EventCode=4624
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<account>[^\r\n]+)"
| where LogonType="3"
| table _time, host, src_ip, account
| sort -_time
```

---

### T1046 — Network Service Discovery

**Tactic:** Discovery | [T1046](https://attack.mitre.org/techniques/T1046/)

First opened SMB on the Windows firewall so nmap would find something:
```powershell
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
```

```bash
nmap -sV -p 1-1000 192.168.56.130
```

**Result:** Port 445 (SMB) open, everything else filtered.

**Detection gap:** Nmap scans don't show up in Windows event logs. You'd need a network-level IDS (Snort, Suricata, Zeek) to catch this — host-based SIEM alone can't do it.

---

### T1110 — Brute Force

**Tactic:** Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/)

Set account lockout policy first so lockout events would fire:
```powershell
net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30
```

```bash
# From Kali — 15 SMB authentication attempts with wrong passwords
for i in {1..15}; do
  smbclient //192.168.56.130/C$ -U administrator%wrongpass$i 2>/dev/null
  echo "attempt $i"
done
```

**Result:** Attempts 1-10 returned `NT_STATUS_LOGON_FAILURE`, attempts 11-15 returned `NT_STATUS_ACCOUNT_LOCKED_OUT`. 10 EventCode 4625s appeared in Splunk.

Note: Hydra's SMB module doesn't work against Windows 11 — used smbclient loop instead.

**Detection Query:**
```spl
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Account Name:\t+(?<account>[^\n]+)" max_match=2
| bucket _time span=5m
| stats count as failed_attempts, values(account) as targeted_accounts by _time, src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

---

## Step 6 — SOC Dashboard

Splunk → Dashboards → Create New Dashboard → Classic Dashboard

| Panel | Type | Query |
|---|---|---|
| Total Events Today | Single Value | `index=* earliest=-24h \| stats count` |
| Failed Logins Over Time | Line Chart | `earliest=0 index=wineventlog EventCode=4625 \| timechart span=1h count` |
| Top 10 Source IPs | Bar Chart | `earliest=0 index=wineventlog EventCode=4625 \| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)" \| stats count by src_ip \| sort -count \| head 10` |
| Top Users with Failed Logins | Table | `earliest=0 index=wineventlog EventCode=4625 \| rex field=_raw "Account Name:\t+(?<user>[^\n]+)" max_match=2 \| stats count by user \| sort -count` |
| Sysmon Process Creation by Host | Table | `earliest=0 index=sysmon _raw="*<EventID>1</EventID>*" \| rex field=_raw "<Computer>(?<host>[^<]+)</Computer>" \| stats count by host \| sort -count` |
| Events by Index | Bar Chart | `earliest=0 index=* \| stats count by index \| sort -count` |

Set time range to **All Time** on each panel or events won't show (all data is historical).

---

## Detection Summary

| Technique | Detection Method | Log Source | Result |
|---|---|---|---|
| T1003.001 — LSASS | Sysmon EventID 1, lsass in cmdline | sysmon | ✅ Attempt logged despite Defender block |
| T1059.001 — PowerShell | Sysmon EventID 1, suspicious cmdline flags | sysmon | ✅ 3 hits |
| T1053.005 — Scheduled Task | Sysmon EventID 1, schtasks /create | sysmon | ✅ 7 hits |
| T1021.002 — SMB | EventCode 4624 LogonType=3 | wineventlog | ❌ Loopback gap |
| T1046 — Nmap | N/A | N/A | ❌ Requires network IDS |
| T1110 — Brute Force | EventCode 4625 threshold | wineventlog | ✅ 10 hits, account locked |

---

## Known Issues

| Issue | Root Cause | Fix / Workaround |
|---|---|---|
| EventCode 4698 not logged | Windows 11 audit policy bug — subcategory broken on this build | Used Sysmon EventID 1 on schtasks.exe instead |
| EventCode 4624 LogonType=3 not triggered | Loopback SMB has no network hop | Lab constraint — works in real multi-host setup |
| Nmap not visible in Splunk | Host-based logs can't capture port scans | Requires network IDS |
| Sysmon events silently dropped | SplunkForwarder service account lacked channel read access | Changed to LocalSystem |
| Hydra SMB failed | Incompatibility with Windows 11 SMB | Switched to smbclient loop |
| No auth.log on Kali | Kali uses journald, not syslog | Forwarded dpkg.log instead |

---

## Skills Demonstrated

- Splunk SIEM setup, index design, and Universal Forwarder deployment (Windows + Linux)
- Sysmon configuration and endpoint telemetry collection
- Writing SPL detection queries with field extraction mapped to MITRE ATT&CK
- Attack simulation with Atomic Red Team and cross-referencing results in Splunk
- Identifying and documenting detection gaps between host-based and network-based monitoring

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Docs](https://docs.splunk.com/Documentation/Splunk)
- [Windows Security Events Reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
