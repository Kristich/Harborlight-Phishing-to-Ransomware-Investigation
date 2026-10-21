# Harborlight-Phishing-to-Ransomware-Investigation
End-to-end SOC investigation of a phishing-initiated ransomware attack against Harborlight Dental &amp; Insurance. Reconstructs initial access, privilege escalation, credential theft, lateral movement, encryption and recovery inhibition using Microsoft Sentinel, KQL, Sysmon and MITRE ATT&amp;CK.



# 🛡️ Threat Hunt Report – Hunt 22: Harborlight Phishing-to-Ransomware Investigation

**Incident ID:** `HL-INC-2026-0204`  
**Incident Date:** 4 February 2026  
**Status:** 15/15 kill-chain stages completed  
**Organisation:** Harborlight Dental & Insurance  
**Workspace:** `LAW-SilentCorridor`  
**Primary Telemetry:** `HarborlightDental_CL`



---

## Executive Summary

The investigation reconstructed a phishing-initiated intrusion across `BACKOFFICE-PC1`, file server `HL-FS01`, and domain controller `ADDC01`. The attacker executed a DLL from a mounted ISO, injected into legitimate processes, bypassed UAC, accessed LSASS, moved laterally over SMB, and used `ntdsutil` to export the domain directory database. Anti-forensics included Security-event-log clearing on all three hosts; subsequent activity included cloud-storage exfiltration commands, recovery inhibition, persistent backdoors, domain account manipulation, and ransomware encryption.

The hunt reports **27 distinct `.akira` encrypted file paths**, **128 copies of `akira_readme.txt`**, and **no pre-existing alert queue**. Backdoor network activity continued until at least **13:55:18Z**, beyond the visible encryption phase near 05:23, so successful containment was **not** established. The hunt associates command-line activity with exfiltration to MEGA, but independently verified transferred byte volumes or cloud-provider receipts are not supplied.


---

## Hunt Objectives

- Reconstruct the intrusion chronologically from phishing initial access to ransomware impact.
- Correlate Sysmon and Windows Security events across all three affected hosts.
- Identify privilege escalation, credential theft, domain compromise, anti-forensics, exfiltration activity and persistence.
- Reproduce supporting KQL for every investigative flag where the completed hunt supplied a query.
- Map findings to MITRE ATT&CK and recommend response and detection improvements.


---

## Scope & Environment

| Asset | Role | Address / Context |
|---|---|---|
| `BACKOFFICE-PC1` | User workstation | `HARBORLIGHT\Emily.Grant`, standard user |
| `HL-FS01` | File server | `172.16.0.8` |
| `ADDC01` | Domain controller | `172.16.0.7` |
| Network | Flat LAN | `172.16.0.0/24`, no segmentation |

- Coastal MSP managed the environment with five contractors and no SOC or alert queue. Staff discovered ransom notes on 4 February 2026.
- Front-office personnel had no legitimate administrative or domain-controller access. Domain administration was performed by the MSP.
- **Use `EventTime` for all incident searches.** The source explicitly warns that `TimeGenerated` is ingestion time and `SystemTime` is missing from many records.
- Host values may be FQDNs (for example, `BACKOFFICE-PC1.Harborlight.local`). Queries below use `host has` instead of strict short-name equality where necessary.
- Telemetry consists of Sysmon and Windows Security events; no packet capture, Zeek, or Suricata was supplied.


---

## Table of Contents

- [Hunt Overview](#hunt-overview)
- [MITRE ATT&CK Summary](#mitre-attck-summary)
- [Flag Analysis](#flag-analysis)

- [Stage 1: Initial Access](#stage-1)

- [Stage 2: Execution](#stage-2)

- [Stage 3: Privilege Escalation](#stage-3)

- [Stage 4: Defence Evasion](#stage-4)

- [Stage 5: Credential Access](#stage-5)

- [Stage 6: Lateral Movement](#stage-6)

- [Stage 7: Credential Access (again)](#stage-7)

- [Stage 8: Defence Evasion (again)](#stage-8)

- [Stage 9: Exfiltration](#stage-9)

- [Stage 10: Impact (Anti-Recovery)](#stage-10)

- [Stage 11: Persistence](#stage-11)

- [Stage 12: Command and Control](#stage-12)

- [Stage 13: Persistence / Privilege Escalation (again)](#stage-13)

- [Stage 14: Impact (Encryption)](#stage-14)

- [Stage 15: Judgement](#stage-15)

- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)
- [Analyst Notes](#analyst-notes)


---

## Hunt Overview

```text
Phishing 7z → ISO / rundll32 DLL → notepad injection → fodhelper UAC bypass
   → taskhostw masquerade / spoolsv injection → LSASS credential access
   → SMB: BACKOFFICE-PC1 → HL-FS01 → ADDC01 → NTDS.dit / IFM export
   → log clearing ↔ MEGA exfiltration commands → recovery inhibition
   → three-host backdoors → external C2 / HTTPS beaconing
   → domain backdoor account / privileges → ransomware encryption & ransom notes
   → continued C2 after the visible impact phase
```


---

## MITRE ATT&CK Summary
| Stage | Kill-Chain Phase | Technique IDs | Flags |
|---:|---|---|---:|
| 1 | Initial Access | `T1566` | 2 |
| 2 | Execution | `T1218.011`, `T1055`, `T1027` | 3 |
| 3 | Privilege Escalation | `T1548.002`, `T1036` | 3 |
| 4 | Defence Evasion | `T1055` | 1 |
| 5 | Credential Access | `T1078`, `T1555`, `T1003.001` | 5 |
| 6 | Lateral Movement | `T1078`, `T1021.002`, `T1047` | 5 |
| 7 | Credential Access (again) | `T1003.003` | 1 |
| 8 | Defence Evasion (again) | `T1070.001` | 4 |
| 9 | Exfiltration | `T1567.002`, `T1036.005` | 4 |
| 10 | Impact (Anti-Recovery) | `T1490` | 4 |
| 11 | Persistence | `T1547`, `T1036.005`, `T1543` | 3 |
| 12 | Command and Control | `T1568.001`, `T1090.004`, `T1071.001` | 3 |
| 13 | Persistence / Privilege Escalation (again) | `T1558`, `T1136.002`, `T1098`, `T1036` | 4 |
| 14 | Impact (Encryption) | `T1486` | 3 |
| 15 | Judgement | Tactic-level / synthesis | 1 |


*Mappings reflect the completed hunt. Some entries are broader technique or tactic labels; consult the evidence for strength and limitations.*


---

## Flag Analysis

_All investigation flags are collapsible for readability. Each contains the hunt finding, reproducible KQL when provided, and detection guidance._


<a id="stage-1"></a>

### Stage 1: Initial Access


The phishing delivery was documented on the workstation. File arrival is not itself execution; the next stage establishes that the payload ran.


<details>
<summary><strong>🚩 Flag 1.1: Execution Gate</strong></summary>


#### Objective

Execution Gate.


#### Finding

a) It has to run. Correct. Delivery without execution is not a compromise. A file sitting on disk is inert until a process loads it. The entire next section exists to confirm execution actually happened.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 1: Initial Access |
| MITRE ATT&CK | TA0001, Initial Access |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on unexpected invoice-themed archive and script creation in standard-user sessions.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 1.2: How did they get in?</strong></summary>


#### Objective

How did they get in.


#### Finding

Vendor_Invoice_Review.7z downloaded by emily.grant, the phishing payload arrived as a 7z archive mimicking a vendor invoice, targeting a front-office user.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 1: Initial Access |
| MITRE ATT&CK | T1566, Phishing |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `11` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The filename and target selection show social engineering tailored to a dental office's daily workflow.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 11
| where TargetFilename has "7z"
| project EventTime, TargetFilename, Image
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on unexpected invoice-themed archive and script creation in standard-user sessions.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-2"></a>

### Stage 2: Execution


The loaded DLL and subsequent process-injection events established execution. The second lure reportedly re-executed the same payload rather than introducing a separate malware family.


<details>
<summary><strong>🚩 Flag 2.1: What actually runs, once that file lands?</strong></summary>


#### Objective

What actually runs, once that file lands.


#### Finding

rundll32.exe D:\the binary,StartW, the ISO mounts as D: and rundll32 loads the DLL via its StartW export. Same ISO-in-archive technique that bypasses Mark of the Web.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 2: Execution |
| MITRE ATT&CK | T1218.011, Rundll32 |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

rundll32 is a living-off-the-land binary; using it to load a DLL from a mounted ISO avoids downloading a standalone .exe.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 1
| where Image has "rundll32"
| where CommandLine has "review.dll"
| project EventTime, CommandLine, ParentImage
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect unusual rundll32 execution from mounted media and unexpected process injection into user applications.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 2.2: What does it hide inside, before anyone&#x27;s even looking for it?</strong></summary>


#### Objective

What does it hide inside, before anyone's even looking for it.


#### Finding

notepad.exe, the payload immediately injects into notepad.exe via remote thread creation. A dentist's PC running notepad is invisible.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 2: Execution |
| MITRE ATT&CK | T1055, Process Injection |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `8` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Process injection gives the attacker a benign-looking host process. Detection requires correlating the access event, not just the process name.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 8
| where EventTime < datetime(2026-02-04 02:36:00)
| extend SourceImage = extract("SourceImage'>([^<]+)", 1, EventData_Xml)
| extend TargetImage = extract("TargetImage'>([^<]+)", 1, EventData_Xml)
| project EventTime, SourceImage, TargetImage
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect unusual rundll32 execution from mounted media and unexpected process injection into user applications.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 2.3: Why does the second file matter if it&#x27;s not new malware?</strong></summary>


#### Objective

Why does the second file matter if it's not new malware.


#### Finding

The second file re-runs the same DLL-in-ISO technique, redundancy, not new malware. Its CommandLine shows a loop/scan pattern for resilience.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 2: Execution |
| MITRE ATT&CK | T1027, Obfuscated Files |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

A second lure establishing a redundant foothold via the same payload indicates operational discipline, not a second malware family.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 1
| where CommandLine has "dll"
| where EventTime between (datetime(2026-02-04 02:24:00) .. datetime(2026-02-04 02:26:00))
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect unusual rundll32 execution from mounted media and unexpected process injection into user applications.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-3"></a>

### Stage 3: Privilege Escalation


The hunt identified `ms-settings` Registry hijacking and `fodhelper.exe`. Only the second of two attempts reached high integrity at about 02:42:39.


<details>
<summary><strong>🚩 Flag 3.1: How do they get elevated without a UAC prompt?</strong></summary>


#### Objective

How do they get elevated without a UAC prompt.


#### Finding

HKCU\Software\Classes\ms-settings\shell\open\command → C:\Users\Public\taskhostw.exe, the fodhelper.exe UAC bypass. The attacker hijacks the auto-elevating utility's command handler.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 3: Privilege Escalation |
| MITRE ATT&CK | T1548.002, Bypass UAC |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `13` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

fodhelper auto-elevates without a UAC prompt. Hijacking its command handler lets the attacker's binary inherit that elevation silently.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 13
| where TargetObject has "ms-settings"
| project EventTime, TargetObject, Details
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on ms-settings handler changes, UAC auto-elevation and unexpected binaries in user-writable paths.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 3.2: Real or Noise: taskhostw.exe</strong></summary>


#### Objective

Real or Noise: taskhostw.exe.


#### Finding

Full path distinguishes real from fake, legitimate the binary lives in C:\Windows\System32\. The attacker's copy runs from C:\Users\Public\. Name is identical; only the path differs.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 3: Privilege Escalation |
| MITRE ATT&CK | T1036, Masquerading |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Filename-based detection is insufficient. Path-based analysis is the only reliable discriminator for masquerading.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 1
| where Image has "taskhostw"
| project EventTime, host, Image, IntegrityLevel
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on ms-settings handler changes, UAC auto-elevation and unexpected binaries in user-writable paths.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 3.3: Of the two attempts, which one actually elevated?</strong></summary>


#### Objective

Of the two attempts, which one actually elevated.


#### Finding

Second attempt at 02:42:39, two UAC bypass attempts fire seconds apart, only the second reaches High integrity. The first failed due to timing or environment.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 3: Privilege Escalation |
| MITRE ATT&CK | T1548.002, Bypass UAC |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Not every technique attempt succeeds. Distinguishing success from failure requires checking the actual integrity level achieved.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 1
| where Image has "fodhelper"
| project EventTime, Image, IntegrityLevel
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on ms-settings handler changes, UAC auto-elevation and unexpected binaries in user-writable paths.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-4"></a>

### Stage 4: Defence Evasion


Path mattered: legitimate `taskhostw.exe` was in `C:\Windows\System32`, whereas the masqueraded copy was in `C:\Users\Public`. The latter injected into the Print Spooler.


<details>
<summary><strong>🚩 Flag 4.1: How does spoolsv.exe end up doing everything from here on?</strong></summary>


#### Objective

How does spoolsv.exe end up doing everything from here on.


#### Finding

taskhostw.exe injects into spoolsv.exe, the elevated backdoor injects code into the Print Spooler service. All subsequent attacker activity runs as spoolsv.exe across all three hosts.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 4: Defence Evasion |
| MITRE ATT&CK | T1055, Process Injection |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `8` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

This is the operational pivot. From this point, every lateral movement command, credential dump, and exfiltration traces back to spoolsv.exe as the parent.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 8
| where EventData_Xml has "spoolsv"
| extend SourceImage = extract("SourceImage'>([^<]+)", 1, EventData_Xml)
| extend TargetImage = extract("TargetImage'>([^<]+)", 1, EventData_Xml)
| project EventTime, SourceImage, TargetImage
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor remote-thread creation targeting spoolsv.exe, especially from masqueraded binaries.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-5"></a>

### Stage 5: Credential Access


The source separated ordinary Security Event 5379 noise from malicious LSASS process access. A stolen credential later appeared in a `net use` command; the password is redacted here.


<details>
<summary><strong>🚩 Flag 5.1: Local to Domain Escalation</strong></summary>


#### Objective

Local to Domain Escalation.


#### Finding

b) Local credential material. Correct. SYSTEM-level access does not grant domain credentials automatically. The attacker must extract locally cached credentials (from LSASS, SAM, or credential stores) before they can move laterally with domain-scoped access.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 5: Credential Access |
| MITRE ATT&CK | T1078, Valid Accounts |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate suspicious LSASS access, exposed credentials on process command lines and abnormal account use.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 5.2: Real or Noise: Credential Manager reads</strong></summary>


#### Objective

Real or Noise: Credential Manager reads.


#### Finding

Noise, the Credential Manager reads (EventCode 5379) are Windows background activity, present before, during, and after the attack. Not the theft moment.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 5: Credential Access |
| MITRE ATT&CK | T1555, Credentials from Password Stores |
| Host filter | `BACKOFFICE-PC1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

268 events that span the entire window are baseline OS behaviour, not an attack indicator. The real credential theft is a different event type entirely.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventCode == 5379
| summarize count() by bin(EventTime, 1h)
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate suspicious LSASS access, exposed credentials on process command lines and abnormal account use.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 5.3: Which process actually touches credential memory?</strong></summary>


#### Objective

Which process actually touches credential memory.


#### Finding

spoolsv.exe accessing lsass.exe, the injected Print Spooler process reaches into LSASS memory. This is where credentials are actually extracted, not Credential Manager.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 5: Credential Access |
| MITRE ATT&CK | T1003.001, LSASS Memory |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `10` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

LSASS holds cached domain credentials in memory. Direct process access to LSASS is the definitive credential theft indicator.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 10
| where EventData_Xml has "lsass"
| extend SourceImage = extract("SourceImage'>([^<]+)", 1, EventData_Xml)
| extend TargetImage = extract("TargetImage'>([^<]+)", 1, EventData_Xml)
| project EventTime, SourceImage, TargetImage, granted_access
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate suspicious LSASS access, exposed credentials on process command lines and abnormal account use.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 5.4: What does that access level actually mean?</strong></summary>


#### Objective

What does that access level actually mean.


#### Finding

0x1fffff = PROCESS_ALL_ACCESS, full read/write/execute access to another process's memory. No legitimate reason for the Print Spooler to need this level of access to LSASS.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 5: Credential Access |
| MITRE ATT&CK | T1003.001, LSASS Memory |
| Event ID | `10` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

This access mask is the definitive signature of a credential dump. Anything less than full access wouldn't be sufficient to read credential memory.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 10 and EventData_Xml has "lsass"
| where EventData_Xml has "spoolsv"
| project EventTime, granted_access
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate suspicious LSASS access, exposed credentials on process command lines and abnormal account use.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 5.5: Which account, and what&#x27;s the password?</strong></summary>


#### Objective

Which account, and what's the password.


#### Finding

Emily.Grant with password [REDACTED], the compromised domain credential extracted from LSASS. First seen in plaintext in a net use command for lateral movement.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 5: Credential Access |
| MITRE ATT&CK | T1078, Valid Accounts |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

A weak, predictable password on a standard user account. The credential appears in plaintext in the command line, confirming it was successfully extracted.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 1 and CommandLine has "/user:"
| where EventTime > datetime(2026-02-04 03:30:00)
| project EventTime, CommandLine, host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate suspicious LSASS access, exposed credentials on process command lines and abnormal account use.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-6"></a>

### Stage 6: Lateral Movement


The first SMB hop targeted `172.16.0.8` about 03:33–03:34, and the second reached `172.16.0.7` about 04:28:22. A later WMIC command from the DC targeted the file server.


<details>
<summary><strong>🚩 Flag 6.1: Credential Reach Test</strong></summary>


#### Objective

Credential Reach Test.


#### Finding

b) Try it against one adjacent host first. Correct. Testing a stolen credential on one target limits failed-logon noise that could trigger detection. Operational security over speed.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 6: Lateral Movement |
| MITRE ATT&CK | T1078, Valid Accounts |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect workstation-to-server SMB admin-share access and WMI execution from unexpected sources; segment networks.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 6.2: Where does the credential go first?</strong></summary>


#### Objective

Where does the credential go first.


#### Finding

BACKOFFICE-PC1 → HL-FS01 (172.16.0.8), around 03:33-03:34, hop one. The compromised credential moves to the file server via SMB/admin shares.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 6: Lateral Movement |
| MITRE ATT&CK | T1021.002, SMB/Admin Shares |
| Host filter | `BACKOFFICE-PC1` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The file server is the first lateral movement target, tested before the attacker attempts the domain controller.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 1
| where CommandLine has "net use" and CommandLine has "172.16.0.8"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect workstation-to-server SMB admin-share access and WMI execution from unexpected sources; segment networks.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 6.3: Where does it go from there?</strong></summary>


#### Objective

Where does it go from there.


#### Finding

HL-FS01 → ADDC01 (172.16.0.7), around 04:28:22, hop two. The file server becomes the pivot to the domain controller, two hops deep within an hour.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 6: Lateral Movement |
| MITRE ATT&CK | T1021.002, SMB/Admin Shares |
| Host filter | `HL-FS01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The attacker uses each compromised host as a stepping stone, not connecting directly from the workstation to the DC.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "HL-FS01" and EventID == 1
| where CommandLine has "net use" and CommandLine has "172.16.0.7"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect workstation-to-server SMB admin-share access and WMI execution from unexpected sources; segment networks.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 6.4: Does the traffic only flow one way?</strong></summary>


#### Objective

Does the traffic only flow one way.


#### Finding

WMIC command from the DC back to a previously compromised host, traffic is bidirectional. The attacker operates the network as a mesh, not a linear chain.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 6: Lateral Movement |
| MITRE ATT&CK | T1047, WMI |
| Host filter | `ADDC01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Bidirectional command flow means the DC is being used as an operational hub, issuing commands back down to compromised hosts.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID == 1
| where CommandLine has "wmic"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect workstation-to-server SMB admin-share access and WMI execution from unexpected sources; segment networks.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 6.5: Lateral Movement Prevention</strong></summary>


#### Objective

Lateral Movement Prevention.


#### Finding

Network segmentation (also: micro-segmentation in zero-trust contexts). The practice of dividing a network into isolated segments or zones, with firewall rules, ACLs, or software-defined policies controlling traffic between them.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 6: Lateral Movement |
| MITRE ATT&CK | T1021.002 - Remote Services: SMB/Windows Admin Shares |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect workstation-to-server SMB admin-share access and WMI execution from unexpected sources; segment networks.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-7"></a>

### Stage 7: Credential Access (again)


On `ADDC01`, `ntdsutil` with Install-From-Media was used to export a copy of `NTDS.dit`. This expands the credential exposure beyond the initial user.


<details>
<summary><strong>🚩 Flag 7.1: What does the attacker take from the DC itself?</strong></summary>


#### Objective

What does the attacker take from the DC itself.


#### Finding

ntdsutil with IFM (Install From Media), creates a full copy of the Active Directory database containing every domain account's password hash.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 7: Credential Access (again) |
| MITRE ATT&CK | T1003.003, NTDS |
| Host filter | `ADDC01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

IFM is a legitimate DC provisioning feature. Using it extracts every account's secrets at once, the highest-value target in any domain.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID == 1
| where CommandLine has "ntdsutil"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on ntdsutil IFM usage and unusual Active Directory database export activity.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-8"></a>

### Stage 8: Defence Evasion (again)


All three compromised hosts were subjected to log-clearing commands. The Security channel was targeted on every host; a staggered 16-channel wipe occurred around 05:18–05:20.


<details>
<summary><strong>🚩 Flag 8.1: Post-Extraction Pivot</strong></summary>


#### Objective

Post-Extraction Pivot.


#### Finding

b) Clear logs. Correct. After reaching the DC and extracting the directory database, the attacker's next priority is destroying the evidence trail. Log-clearing buys time before responders can reconstruct the chain.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 8: Defence Evasion (again) |
| MITRE ATT&CK | T1070.001, Clear Windows Event Logs |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Forward Security logs off-host and alert on wevtutil cl commands, particularly multi-host or multi-channel bursts.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 8.2: Which hosts get their logs cleared?</strong></summary>


#### Objective

Which hosts get their logs cleared.


#### Finding

ADDC01, BACKOFFICE-PC1, and HL-FS01: all three compromised hosts get their logs wiped. The attacker cleans every machine they've touched.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 8: Defence Evasion (again) |
| MITRE ATT&CK | T1070.001, Clear Windows Event Logs |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Wiping logs on all hosts, not just the DC, shows systematic evidence destruction across the full lateral movement path.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 1 and CommandLine has "wevtutil cl"
| summarize channels=count() by host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Forward Security logs off-host and alert on wevtutil cl commands, particularly multi-host or multi-channel bursts.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 8.3: Is there one channel cleared everywhere, without exception?</strong></summary>


#### Objective

Is there one channel cleared everywhere, without exception.


#### Finding

Security, the one log channel cleared on every host without exception. Security logs contain authentication events and process audit trails documenting the entire intrusion.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 8: Defence Evasion (again) |
| MITRE ATT&CK | T1070.001, Clear Windows Event Logs |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Clearing the Security channel destroys the authentication trail that maps the attacker's movement across the domain.


#### KQL Query Used


```kql
HarborlightDental_CL
| where CommandLine has "wevtutil cl Security"
| project EventTime, host, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Forward Security logs off-host and alert on wevtutil cl commands, particularly multi-host or multi-channel bursts.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 8.4: Which wipe is the most thorough?</strong></summary>


#### Objective

Which wipe is the most thorough.


#### Finding

16-channel wipe across all three hosts, the most thorough burst clears 16 distinct log channels on each machine, not just targeted deletion but wholesale evidence destruction.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 8: Defence Evasion (again) |
| MITRE ATT&CK | T1070.001, Clear Windows Event Logs |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

A 16-channel wipe around 05:18-05:20 is staggered across hosts, indicating scripted/automated cleanup rather than manual commands.


#### KQL Query Used


```kql
HarborlightDental_CL
| where CommandLine has "wevtutil cl"
| where EventTime between (datetime(2026-02-04 05:17:00) .. datetime(2026-02-04 05:21:00))
| summarize channels=count() by host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Forward Security logs off-host and alert on wevtutil cl commands, particularly multi-host or multi-channel bursts.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-9"></a>

### Stage 9: Exfiltration


The hunt linked masqueraded `rclone` activity to a MEGA target `mega:HARBORLIGHT-exfil` and a configured account. The command-level evidence supports an exfiltration attempt/path; independent successful delivery volume was not supplied.


<details>
<summary><strong>🚩 Flag 9.1: Exfil Timing</strong></summary>


#### Objective

Exfil Timing.


#### Finding

c) During, overlapping. Correct. The telemetry shows exfiltration and log-wiping happening concurrently. The attacker compresses dwell time by running both operations in parallel rather than sequentially.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 9: Exfiltration |
| MITRE ATT&CK | T1567.002, Exfiltration to Cloud Storage |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor renamed executable paths, rclone configuration and cloud-storage uploads; corroborate transfers with flow logs.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 9.2: What&#x27;s leaving the network, disguised as what?</strong></summary>


#### Objective

What's leaving the network, disguised as what.


#### Finding

rclone.exe masquerading as C:\ProgramData\Microsoft\MsMpEng.exe, the exfiltration tool disguised as Windows Defender's service binary.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 9: Exfiltration |
| MITRE ATT&CK | T1036.005, Match Legitimate Name |
| Host filter | `HL-FS01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

By borrowing the name and path of a legitimate security product, the attacker makes the exfiltration process invisible to casual inspection.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "HL-FS01" and EventID == 1
| where Image has "MsMpEng"
| project EventTime, Image, CommandLine, ParentImage
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor renamed executable paths, rclone configuration and cloud-storage uploads; corroborate transfers with flow logs.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 9.3: What moves, and where to?</strong></summary>


#### Objective

What moves, and where to.


#### Finding

C:\Shares exfiltrated to mega:HARBORLIGHT-exfil, the entire shared-drive content copied to a MEGA cloud account. The destination label shows this was planned, not opportunistic.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 9: Exfiltration |
| MITRE ATT&CK | T1567.002, Exfiltration to Cloud Storage |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The named destination (HARBORLIGHT-exfil) proves pre-planning specific to this target organisation.


#### KQL Query Used


```kql
HarborlightDental_CL
| where CommandLine has "rclone" or CommandLine has "mega"
| project EventTime, host, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor renamed executable paths, rclone configuration and cloud-storage uploads; corroborate transfers with flow logs.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 9.4: Whose account receives it?</strong></summary>


#### Objective

Whose account receives it.


#### Finding

jwilson.vhr@proton.me, the MEGA account configured to receive the stolen data. Proton email for registration anonymity.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 9: Exfiltration |
| MITRE ATT&CK | T1567.002, Exfiltration to Cloud Storage |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

This is the attacker's collection point, configured via an echo command building rclone.conf.


#### KQL Query Used


```kql
HarborlightDental_CL
| where CommandLine has "rclone" or CommandLine has "proton"
| where CommandLine has "echo"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor renamed executable paths, rclone configuration and cloud-storage uploads; corroborate transfers with flow logs.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-10"></a>

### Stage 10: Impact (Anti-Recovery)


On `HL-FS01`, three anti-recovery mechanisms were used (`vssadmin`, `bcdedit`, `wbadmin`); `ADDC01` showed only shadow-copy deletion. The file-server sequence ran twice.


<details>
<summary><strong>🚩 Flag 10.1: Double-Extortion Next Move</strong></summary>


#### Objective

Double-Extortion Next Move.


#### Finding

b) Destroy recovery options, then encrypt. Correct. Double-extortion groups eliminate recovery paths (shadow copies, backups) before deploying the encryptor, so the victim has no alternative but to pay.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 10: Impact (Anti-Recovery) |
| MITRE ATT&CK | T1490, Inhibit System Recovery |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect vssadmin, wbadmin and bcdedit recovery inhibition, particularly in clusters.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 10.2: Which host loses its recovery options, and which doesn&#x27;t?</strong></summary>


#### Objective

Which host loses its recovery options, and which doesn't.


#### Finding

HL-FS01 gets the full treatment (vssadmin + bcdedit + wbadmin). ADDC01 gets only vssadmin, partial. The file server holds the business data that's being ransomed.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 10: Impact (Anti-Recovery) |
| MITRE ATT&CK | T1490, Inhibit System Recovery |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The attacker prioritises anti-recovery on the host with the most valuable data, not the host with the most privilege.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 1
| where CommandLine has_any ("vssadmin", "bcdedit", "wbadmin")
| summarize tools=make_set(extract("(vssadmin|bcdedit|wbadmin)", 0, CommandLine)) by host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect vssadmin, wbadmin and bcdedit recovery inhibition, particularly in clusters.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 10.3: What techniques get used together?</strong></summary>


#### Objective

What techniques get used together.


#### Finding

vssadmin, bcdedit, wbadmin, three distinct anti-recovery techniques: shadow copy deletion, boot recovery disabled, and backup catalogue wiped.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 10: Impact (Anti-Recovery) |
| MITRE ATT&CK | T1490, Inhibit System Recovery |
| Host filter | `HL-FS01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Using all three eliminates every standard Windows recovery path simultaneously.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "HL-FS01" and EventID == 1
| where CommandLine has_any ("vssadmin", "bcdedit", "wbadmin")
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect vssadmin, wbadmin and bcdedit recovery inhibition, particularly in clusters.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 10.4: Does it only happen once?</strong></summary>


#### Objective

Does it only happen once.


#### Finding

The anti-recovery sequence runs twice, repeated execution around 04:05:26, roughly 80 seconds after the first pass. Deliberate redundancy to ensure nothing was missed.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 10: Impact (Anti-Recovery) |
| MITRE ATT&CK | T1490, Inhibit System Recovery |
| Host filter | `HL-FS01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Double-execution confirms this is scripted/automated, not manual. The attacker's tooling doesn't trust a single pass.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "HL-FS01" and EventID == 1
| where CommandLine has_any ("vssadmin", "bcdedit", "wbadmin")
| summarize count() by bin(EventTime, 30s)
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect vssadmin, wbadmin and bcdedit recovery inhibition, particularly in clusters.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-11"></a>

### Stage 11: Persistence


The hunt reported separate persistence across hosts: workstation `taskhostw.exe`, DC `OneDriveSync.exe`, and file-server `wsync.exe`.


<details>
<summary><strong>🚩 Flag 11.1: Persistence Hunt</strong></summary>


#### Objective

Persistence Hunt.


#### Finding

b) Additional backdoors/persistence. Correct. A competent attacker never relies on a single way back in. While recovery options are being destroyed, the analyst should look for additional persistence mechanisms planted across the environment.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 11: Persistence |
| MITRE ATT&CK | T1547, Boot or Logon Autostart Execution |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on new autostart entries, scheduled tasks and masqueraded executables across multiple servers.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 11.2: Is there a second way back in?</strong></summary>


#### Objective

Is there a second way back in.


#### Finding

OneDriveSync.exe at C:\Users\Public\OneDriveSync.exe, a second backdoor on ADDC01, disguised as OneDrive sync. Same masquerade pattern as MsMpEng.exe.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 11: Persistence |
| MITRE ATT&CK | T1036.005, Match Legitimate Name |
| Host filter | `ADDC01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Independent backdoors on separate hosts ensure the attacker retains access even if one host is remediated.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID in (1, 3)
| where Image has "OneDriveSync"
| project EventTime, EventID, Image, CommandLine, DestinationIp
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on new autostart entries, scheduled tasks and masqueraded executables across multiple servers.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 11.3: Is there a third?</strong></summary>


#### Objective

Is there a third.


#### Finding

wsync.exe dropped by taskhostw.exe on HL-FS01, a third independent backdoor on the file server. Three persistence mechanisms on three different hosts.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 11: Persistence |
| MITRE ATT&CK | T1543, Create/Modify System Process |
| Host filter | `HL-FS01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Full coverage: workstation (taskhostw.exe), DC (OneDriveSync.exe), file server (wsync.exe). Losing any single host doesn't eliminate access.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "HL-FS01" and EventID in (1, 11)
| where Image has "wsync" or TargetFilename has "wsync"
| project EventTime, EventID, Image, TargetFilename, ParentImage
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on new autostart entries, scheduled tasks and masqueraded executables across multiple servers.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-12"></a>

### Stage 12: Command and Control


Backdoor activity involved `cdn.cloud-endpoint.net` and HTTPS/443. The hunt reported callbacks continuing until 13:55:18Z, well after ransom-note activity near 05:23.


<details>
<summary><strong>🚩 Flag 12.1: Where do these backdoors actually phone home to?</strong></summary>


#### Objective

Where do these backdoors actually phone home to.


#### Finding

cloud-endpoint.net resolving through Cloudflare, the backdoors beacon to Cloudflare-fronted C2 infrastructure. Blocking the domain doesn't block the CDN IP.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 12: Command and Control |
| MITRE ATT&CK | T1568.001/T1090.004, Domain Fronting |
| Event ID | `22` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Domain fronting via Cloudflare makes C2 traffic indistinguishable from legitimate HTTPS to a CDN. Traditional domain blocking is ineffective.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 22
| where QueryName has "cloud-endpoint"
| project EventTime, host, QueryName, QueryResults
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect anomalous outbound beaconing by user-writable-path executables, including activity after encryption.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 12.2: Is this a one-off connection or something more sustained?</strong></summary>


#### Objective

Is this a one-off connection or something more sustained.


#### Finding

Persistent beaconing over port 443, not a one-off connection but a sustained channel. Encrypted HTTPS blending with normal web browsing.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 12: Command and Control |
| MITRE ATT&CK | T1071.001, Web Protocols |
| Event ID | `3` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Volume and regularity distinguish a live C2 channel from a single check-in. Sustained beaconing means the attacker maintains real-time control.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 3
| where Image has_any ("OneDriveSync", "wsync", "taskhostw")
| summarize count() by Image, DestinationPort
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect anomalous outbound beaconing by user-writable-path executables, including activity after encryption.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 12.3: Is it really over?</strong></summary>


#### Objective

Is it really over.


#### Finding

Not over, the loud phase finishes by ~05:23, but backdoor beaconing continues well past that. Two backdoors are still active at the literal end of the telemetry export.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 12: Command and Control |
| MITRE ATT&CK | T1071.001, Web Protocols |
| Event ID | `3` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The ransom note is what the victim sees. The backdoors maintaining access afterward are what the attacker keeps. The incident is not contained.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 3
| where Image has_any ("OneDriveSync", "wsync", "taskhostw")
| summarize min(EventTime), max(EventTime) by Image, host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Detect anomalous outbound beaconing by user-writable-path executables, including activity after encryption.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-13"></a>

### Stage 13: Persistence / Privilege Escalation (again)


A newly created `svc_sql` domain account and confirmed group-membership events indicated domain-level persistence. A separate ransomware-themed account name was queried but not created.


<details>
<summary><strong>🚩 Flag 13.1: Attacker End Goal</strong></summary>


#### Objective

Attacker End Goal.


#### Finding

b) Durable domain-level persistence. Correct. With NTDS.dit extracted and host-level backdoors planted, the attacker's next goal is persistence that survives a full host rebuild, using the domain credentials already stolen.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 13: Persistence / Privilege Escalation (again) |
| MITRE ATT&CK | T1558, Steal or Forge Kerberos Tickets |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor privileged group changes and new domain service accounts, with alerting on unapproved account creation.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 13.2: Is there a backdoor built into the domain itself?</strong></summary>


#### Objective

Is there a backdoor built into the domain itself.


#### Finding

svc_sql with password [REDACTED], a backdoor domain account disguised as a SQL service account. Survives a full host rebuild.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 13: Persistence / Privilege Escalation (again) |
| MITRE ATT&CK | T1136.002, Create Account: Domain Account |
| Host filter | `ADDC01` |
| Event ID | `1` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Domain-level persistence outlasts any host-level remediation. The generic service-account name avoids scrutiny.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID == 1
| where CommandLine has "net user" and CommandLine has "/add"
| project EventTime, CommandLine
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor privileged group changes and new domain service accounts, with alerting on unapproved account creation.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 13.3: Which privilege-escalation attempt actually worked?</strong></summary>


#### Objective

Which privilege-escalation attempt actually worked.


#### Finding

localgroup / Add-ADGroupMember, of four escalation attempts, only the ones that produce Security EventCode 4728/4732 (group membership change) actually succeeded.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 13: Persistence / Privilege Escalation (again) |
| MITRE ATT&CK | T1098, Account Manipulation |
| Host filter | `ADDC01` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Multiple techniques attempted in sequence shows the attacker adapting. Only the events with corresponding audit log confirmation actually took effect.


#### KQL Query Used


```kql
HarborlightDental_CL
| where host has "ADDC01" and EventCode in (4728, 4732)
| where EventTime between (datetime(2026-02-04 05:21:00) .. datetime(2026-02-04 05:23:00))
| project EventTime, EventCode, EventData_Xml
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor privileged group changes and new domain service accounts, with alerting on unapproved account creation.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 13.4: Right after confirming the backdoor account, a second name shows up. Is it real?</strong></summary>


#### Objective

Right after confirming the backdoor account, a second name shows up. Is it real.


#### Finding

akira_svc, queried once, never created. A red herring: the ransomware-branded name was either a decoy or a check that was never followed through.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 13: Persistence / Privilege Escalation (again) |
| MITRE ATT&CK | T1036, Masquerading |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

Not every command the attacker runs produces a result. Searching for account creation events for this name returns nothing, it doesn't exist in the domain.


#### KQL Query Used


```kql
HarborlightDental_CL
| where CommandLine has "akira_svc"
| project EventTime, host, CommandLine, EventID
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Monitor privileged group changes and new domain service accounts, with alerting on unapproved account creation.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-14"></a>

### Stage 14: Impact (Encryption)


The source reported 128 copies of `akira_readme.txt` and 27 distinct `.akira` paths, supporting ransomware encryption impact.


<details>
<summary><strong>🚩 Flag 14.1: Final Playbook Stage</strong></summary>


#### Objective

Final Playbook Stage.


#### Finding

b) The visible impact, encryption and ransom. Correct. The final step in a double-extortion playbook. Persistence and data theft are complete; the attacker now forces a decision by encrypting production data and dropping a ransom note.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 14: Impact (Encryption) |
| MITRE ATT&CK | T1486, Data Encrypted for Impact |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This reasoning step helps connect the surrounding evidence and prevents unsupported conclusions.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on bursts of ransomware extensions and ransom-note creation across multiple network shares.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 14.2: What&#x27;s the ransom note, and how many times does it land?</strong></summary>


#### Objective

What's the ransom note, and how many times does it land.


#### Finding

akira_readme.txt dropped 128 times across the estate, the the impact indicator placed in every directory where files were encrypted.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 14: Impact (Encryption) |
| MITRE ATT&CK | T1486, Data Encrypted for Impact |
| Event ID | `11` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

128 copies across all three hosts ensures the victim finds the ransom demand regardless of where they look.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 11 and TargetFilename has "akira_readme"
| summarize count() by host
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on bursts of ransomware extensions and ransom-note creation across multiple network shares.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<details>
<summary><strong>🚩 Flag 14.3: What&#x27;s actually encrypted, and how do you know?</strong></summary>


#### Objective

What's actually encrypted, and how do you know.


#### Finding

.akira extension on 27 distinct filenames, confirming Akira ransomware. The relatively low count suggests targeted encryption of high-value files, not blanket encryption.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 14: Impact (Encryption) |
| MITRE ATT&CK | T1486, Data Encrypted for Impact |
| Event ID | `11` |
| Timestamp field | `EventTime` (incident time; prefer to `TimeGenerated`) |


#### Why it matters

The extension confirms the ransomware variant. Low file count indicates selective targeting rather than mass encryption.


#### KQL Query Used


```kql
HarborlightDental_CL
| where EventID == 11 and TargetFilename endswith ".akira"
| summarize dcount(TargetFilename)
```


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Alert on bursts of ransomware extensions and ransom-note creation across multiple network shares.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


<a id="stage-15"></a>

### Stage 15: Judgement


The final stage reconciled the phishing-to-ransomware path, overlapping log wiping and cloud exfiltration, multiple persistence mechanisms, and continued attacker access after the visible incident.


<details>
<summary><strong>🚩 Flag 15.1: Can you put the whole chain in order?</strong></summary>


#### Objective

Can you put the whole chain in order.


#### Finding

Full kill chain: phishing (archive+ISO) → execution (rundll32+DLL) → injection (notepad, then spoolsv.exe) → UAC bypass (fodhelper) → LSASS credential theft → lateral movement (SMB, 3 hosts) → NTDS extraction → log wipes (16 channels, 3 hosts) → exfil (rclone/MEGA) → anti-recovery → 3 backdoors → domain persistence (svc_sql) → Akira ransomware.


#### Evidence

| Field | Value |
|---|---|
| Kill-chain stage | 15: Judgement |
| MITRE ATT&CK | TA0040, Impact |
| Event record | No dedicated query supplied for this reasoning flag |


#### Why it matters

This is the synthesis. Every stage connects through timestamps and process lineage already proven.


#### KQL Query Used


_No standalone KQL query was supplied for this conceptual flag. Consult the adjacent evidence-producing flags._


#### 🖼️ Screenshot

_[Insert a redacted screenshot of the corresponding hunt results; not supplied in the source.]_


#### 🛡️ Detection Recommendation

Correlate the full intrusion sequence into multi-stage high-confidence detections and verify containment before closing incidents.


**Hunting Tip:** Use `EventTime` and check complete hostname values; correlate the command line with process ancestry and adjacent events before attributing activity.

</details>


---

## Detection Gaps & Recommendations

| Priority | Gap | Recommendation |
|---|---|---|
| P1 | No SOC or alert queue | Deploy centralised alerting for high-confidence process injection, LSASS access, domain account changes, and mass ransomware indicators. |
| P1 | Flat 172.16.0.0/24 network | Segment workstation, file server and domain controller tiers; deny unnecessary SMB/WMI/admin-share traffic. |
| P1 | Compromised domain credentials / directory export | Reset compromised user and privileged credentials; assess KRBTGT and domain-wide secrets after NTDS extraction; validate any attacker-created accounts. |
| P1 | Active C2 beyond encryption | Isolate compromised hosts and block validated attacker destinations; investigate and remove `taskhostw`, `wsync`, and `OneDriveSync` implants and the `svc_sql` backdoor. |
| P1 | Recovery-inhibition commands | Protect offline/immutable backups and test clean restorations; alert on `vssadmin`, `wbadmin`, and `bcdedit` abuse. |
| P2 | Systematic event-log clearing | Forward Security/Sysmon events off-host with tamper-resistant storage; alert on `wevtutil cl` bursts. |
| P2 | Cloud exfiltration visibility | Correlate process command lines with network flows, DNS, cloud access logs and transferred-byte metrics. |
| P2 | Execution from user-writable directories | Implement application control, reduce local privilege and alert on masqueraded Windows/Microsoft executables outside trusted paths. |

**Response status:** The completed hunt demonstrates investigation results, not verified containment, eradication, restoration, or formal closure. Because connections continued after encryption, treating the incident as closed would be unsupported.


---

## Final Assessment

The completed hunt reconstructs an intrusion from a phishing archive and DLL execution through privilege escalation, credential access, SMB/WMI lateral movement, Active Directory database export, event-log clearing, cloud-exfiltration commands, recovery inhibition, persistence, and ransomware encryption. The source reports **3 compromised hosts, 27 encrypted `.akira` paths, and 128 ransom notes**.

The later command-and-control telemetry means the investigation does **not** establish successful containment or recovery. Cloud upload commands and account configuration are present, but independently verified transferred volumes or cloud receipts are not supplied.


---

## Analyst Notes

### Evidence Quality and Source Reconciliation

- **Timing:** All query windows use `EventTime`. The source does not independently confirm its timezone; `13:55:18Z` is reported explicitly for the latest C2 callback.
- **UAC registry target:** The Stage 3 submitted answer names `rundll32.exe`, but its feedback describes the `ms-settings` handler pointing to `C:\Users\Public\taskhostw.exe`. The exact target must be checked in the `TargetObject`/`Details` event. Both are preserved as investigation context, not reconciled by guesswork.
- **Third backdoor:** The Stage 11 submitted answer (`taskhostw.exe`, `fodhelper.exe`, workstation) conflicts with its feedback, which identifies `wsync.exe` dropped by `taskhostw.exe` on `HL-FS01`. The source feedback and supplied file/process query support the latter; verify raw events before making the statement definitive.
- **Masqueraded Defender path:** The submitted answer and feedback list slightly different `MsMpEng.exe` paths (`C:\ProgramData\Microsoft\Windows Defender\...` versus `C:\ProgramData\Microsoft\...`). Consult `Image` in the original process event for the exact path.
- **Group membership:** Event codes `4728` and `4732` indicate changes to different security-group scopes. Do not infer the successful target group from the event ID alone; parse event message/member/target group and check whether `svc_sql` is the affected member.
- **Cloud fronting:** DNS resolving to a CDN and TLS/443 traffic do not alone prove domain fronting, although the hunt labels the infrastructure as such. Verify HTTP/TLS hostnames and network traces where available.
- **LSASS:** `0x1FFFFF` indicates broad process access and is strongly suspicious from `spoolsv.exe`, but the mask alone does not prove a completed memory dump. The later plaintext `net use` command provides additional credential-compromise context.
- **Exfiltration:** An `rclone` command and remote account configuration are strong evidence of exfiltration intent/activity; without transfer records, successful transfer size and contents remain not determined from available logs.
- **Account naming:** A single lookup for `akira_svc` did not establish its creation. Do not equate a query with an added domain account.


### Skills Demonstrated

Sysmon and Windows Security analysis · KQL threat hunting · Incident timeline reconstruction · Phishing and LOLBin analysis · Process injection · Credential theft and Active Directory abuse · SMB/WMI lateral movement · Anti-forensics · Exfiltration investigation · Ransomware impact · MITRE ATT&CK mapping · Evidence quality assessment







