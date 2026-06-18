# Splunk Detection Rules — MITRE ATT&CK Mapped

All queries tested in this lab. Time range: set to **All Time** or add `earliest=0` to queries, otherwise historical events won't show.

A few notes on these:
- I started with simple keyword searches and realized they're useless — an attacker who renames mimikatz.exe bypasses them entirely. Rewrote everything to use EventCode + field extractions instead.
- False positive rates vary a lot. I've noted where tuning is needed for a real environment.
- T1046 (Nmap) has no real host-based detection — I documented the gap rather than pretending the WFP events work.

---

## T1003.001 — LSASS Credential Dumping
**Tactic:** Credential Access  
**Index:** sysmon  
**EventCode:** 10 (ProcessAccess)  
**What it detects:** Processes opening a handle to lsass.exe with memory-read permissions (GrantedAccess 0x1010, 0x1410, 0x1438). This fires on the *attempt*, not the binary name — so renaming a tool doesn't evade it.

```spl
index=sysmon EventCode=10
| rex field=_raw "TargetImage>(?<TargetImage>[^<]+)"
| rex field=_raw "SourceImage>(?<SourceImage>[^<]+)"
| rex field=_raw "GrantedAccess>(?<GrantedAccess>[^<]+)"
| where like(lower(TargetImage), "%lsass%")
| where GrantedAccess IN ("0x1010", "0x1410", "0x1418", "0x1438", "0x143a", "0x1fffff")
| table _time, host, SourceImage, TargetImage, GrantedAccess
| sort -_time
```

**Tuning note:** Filter out known-good callers (antivirus, EDR sensors, Task Manager). In this lab I saw Windows Security Health Service and MsMpEng.exe triggering it — add a `NOT (SourceImage IN (...))` clause in production.

**Lab result:** Defender blocked the dump but EventCode 10 still fired. The attempt is visible in Splunk even though nothing exfiltrated.

---

## T1110 — Brute Force (RDP)
**Tactic:** Credential Access  
**Index:** wineventlog  
**EventCode:** 4625 (Failed logon)  
**What it detects:** Threshold-based — more than 5 failed logins from the same source IP within 5 minutes. Reduces noise vs. alerting on every single 4625.

```spl
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Account Name:\t+(?<account>[^\n]+)"
| bucket _time span=5m
| stats count as failed_attempts, values(account) as targeted_accounts by _time, src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

**Tuning note:** Threshold of 5 in 5 minutes is aggressive for production — you'd tune this based on your baseline. Internally-sourced 4625s (locked accounts, service accounts) will false positive. Whitelist known IPs.

**Lab result:** Hydra from 192.168.56.129 generated 13 failures in under a minute. Clearly visible with correct src_ip extraction. EventCode 4624 LogonType=10 fires on the one eventual success if the password is found.

---

## T1059.001 — PowerShell Suspicious Execution
**Tactic:** Execution  
**Index:** sysmon  
**EventCode:** 1 (ProcessCreate)  
**What it detects:** PowerShell launched with execution bypass flags, encoded commands, or spawned by a suspicious parent (Office, WMI, scheduled task). Field-based, not string grep.

```spl
index=sysmon EventCode=1
| rex field=_raw "Image>(?<Image>[^<]+)"
| rex field=_raw "CommandLine>(?<CommandLine>[^<]+)"
| rex field=_raw "ParentImage>(?<ParentImage>[^<]+)"
| where like(lower(Image), "%powershell%") OR like(lower(Image), "%pwsh%")
| where like(lower(CommandLine), "%-enc%")
    OR like(lower(CommandLine), "%-nop%")
    OR like(lower(CommandLine), "%-bypass%")
    OR like(lower(CommandLine), "%-windowstyle hidden%")
    OR like(lower(CommandLine), "%iex%")
    OR like(lower(CommandLine), "%invoke-expression%")
    OR like(lower(CommandLine), "%-noprofile%")
| eval suspicious_parent=if(
    like(lower(ParentImage), "%winword%") OR like(lower(ParentImage), "%excel%") OR
    like(lower(ParentImage), "%wscript%") OR like(lower(ParentImage), "%cscript%") OR
    like(lower(ParentImage), "%mshta%") OR like(lower(ParentImage), "%wmiprvse%"),
    "YES", "NO")
| table _time, host, Image, CommandLine, ParentImage, suspicious_parent
| sort -_time
```

**Tuning note:** `-nop` and `-bypass` will fire on legitimate admin scripts. In production, add context — filter by user, restrict to interactive logon sessions (LogonType 2/10), or layer with a risk score rather than alerting directly.

**Lab result:** Atomic Red Team test T1059.001 Test 1 (Encoded command) and Test 9 (NTFS ADS access) both triggered this. CommandLine field shows the actual encoded payload.

---

## T1053.005 — Scheduled Task Persistence
**Tactic:** Persistence  
**Index:** sysmon  
**EventCode:** 1 (ProcessCreate)  
**What it detects:** schtasks.exe being called with `/create` flag. More reliable than EventCode 4698 on Windows 11 (audit policy for task creation didn't fire consistently in this environment).

```spl
index=sysmon EventCode=1
| rex field=_raw "Image>(?<Image>[^<]+)"
| rex field=_raw "CommandLine>(?<CommandLine>[^<]+)"
| rex field=_raw "ParentImage>(?<ParentImage>[^<]+)"
| rex field=_raw "User>(?<User>[^<]+)"
| where like(lower(Image), "%schtasks%")
    AND like(lower(CommandLine), "%/create%")
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time
```

**Tuning note:** Legitimate software installs and Windows Update create scheduled tasks too. Baseline your environment first. Filter by CommandLine patterns that include `/tr` pointing to temp paths, user profile directories, or unusual executables.

**Lab result:** Both Atomic Red Team tests (T1053.005 Test 1 and Test 4) triggered this. CommandLine shows the full `/create /tn` syntax with task names like "AtomicTask" and "EventViewerBypass."

Note on EventCode 4698: I enabled audit policy for scheduled task creation (`auditpol /set /subcategory:"Other Object Access Events" /success:enable`) but 4698 still didn't fire on Windows 11 22H2 with the test tasks. Sysmon process monitoring was more reliable.

---

## T1021.002 — SMB Lateral Movement
**Tactic:** Lateral Movement  
**Index:** wineventlog  
**EventCode:** 4624 (Successful logon, LogonType=3)  
**What it detects:** Network logon events (SMB/IPC) from non-domain-controller sources, filtered to reduce noise.

```spl
earliest=0 index=wineventlog EventCode=4624
| rex field=_raw "Logon Type:\t+(?<LogonType>[^\n]+)"
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Account Name:\t+(?<account>[^\n]+)"
| rex field=_raw "Workstation Name:\t+(?<workstation>[^\n]+)"
| where LogonType="3"
| where src_ip != "-" AND src_ip != "::1" AND src_ip != "127.0.0.1"
| where NOT like(account, "%$")
| stats count as logon_count, values(workstation) as source_hosts by src_ip, account
| where logon_count >= 1
| sort -logon_count
```

**Tuning note:** LogonType=3 fires constantly in domain environments (file shares, print servers, etc.). The `NOT like(account, "%$")` filter removes machine account logons. In production, you'd also filter known service accounts and domain controller IPs.

**Lab result:** Test was loopback (mapped `\\127.0.0.1\C$`) so 4624 LogonType=3 didn't fire — loopback SMB doesn't generate a network logon event. This is a real gap documented in `docs/setup-notes.md`. T1021.002 Test 2 (Map Admin Share via PowerShell) succeeded from a process perspective; Sysmon EventCode 3 (network connection) can be used as fallback evidence.

Fallback — Sysmon network connection to SMB port:
```spl
index=sysmon EventCode=3
| rex field=_raw "Image>(?<Image>[^<]+)"
| rex field=_raw "DestinationPort>(?<DestinationPort>[^<]+)"
| rex field=_raw "DestinationIp>(?<DestinationIp>[^<]+)"
| where DestinationPort="445"
| where NOT like(DestinationIp, "239.%") AND NOT like(DestinationIp, "ff%")
| table _time, host, Image, DestinationIp, DestinationPort
| sort -_time
```

---

## T1046 — Network Reconnaissance
**Tactic:** Discovery  

**Gap acknowledged:** Host-based SIEM (Windows Security event logs or Sysmon) does not reliably detect Nmap port scans. EventCode 5156/5157 (Windows Filtering Platform) fires on permitted/blocked connections but:
- Generates massive volume (easily 10,000+ events per scan)
- No aggregation logic in Windows natively
- Blocked connections (5157) would fire but require WFP auditing enabled and filtering for the scan source

To actually detect port scans you need network-level tooling: Snort/Suricata on a network tap or span port, or NetFlow/IPFIX analysis. Out of scope for this lab setup, but documented as a detection gap.

What I tested (limited value):
```spl
earliest=0 index=wineventlog EventCode=5157
| rex field=_raw "Source Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Destination Port:\t+(?<dst_port>[^\n]+)"
| stats count as blocked_connections, dc(dst_port) as unique_ports by src_ip
| where unique_ports > 20
| sort -unique_ports
```

The `unique_ports > 20` threshold is the key — a legitimate host doesn't try 20+ different destination ports. But this only works if WFP blocking is active, which it isn't by default.

---

## T1059.001 + T1053.005 Combined — Scheduled Task running PowerShell
**Tactic:** Execution + Persistence chained  
**Index:** sysmon  
**What it detects:** Scheduled task (svchost.exe → taskeng.exe parent chain) spawning PowerShell. This is a common persistence + execution combo and worth having as a correlation rule.

```spl
index=sysmon EventCode=1
| rex field=_raw "Image>(?<Image>[^<]+)"
| rex field=_raw "CommandLine>(?<CommandLine>[^<]+)"
| rex field=_raw "ParentImage>(?<ParentImage>[^<]+)"
| where like(lower(Image), "%powershell%")
| where like(lower(ParentImage), "%svchost%") OR like(lower(ParentImage), "%taskeng%") OR like(lower(ParentImage), "%taskhostw%")
| table _time, host, Image, CommandLine, ParentImage
| sort -_time
```

---

## General Sysmon Exploration

```spl
index=sysmon
| stats count by EventCode
| sort -count
```

Common EventCodes:
- `1` = Process Create (CommandLine, ParentImage — most useful for detection)
- `3` = Network Connection (DestinationIp, DestinationPort)
- `10` = ProcessAccess (TargetImage, GrantedAccess — critical for T1003)
- `11` = File Create
- `13` = Registry Value Set
- `22` = DNS Query
