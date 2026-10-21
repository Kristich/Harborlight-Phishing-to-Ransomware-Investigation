# Harborlight-Phishing-to-Ransomware-Investigation
End-to-end SOC investigation of a phishing-initiated ransomware attack against Harborlight Dental &amp; Insurance. Reconstructs initial access, privilege escalation, credential theft, lateral movement, encryption and recovery inhibition using Microsoft Sentinel, KQL, Sysmon and MITRE ATT&amp;CK.



# 🛡️ Threat Hunt Report – Hunt 22: Harborlight Dental & Insurance

**Incident ID:** `HL-INC-2026-0204`  
**Incident Date:** 4 February 2026  
**Workspace:** `LAW-SilentCorridor`  
**Primary Table:** `HarborlightDental_CL`  
**Classification:** Ransomware Intrusion / Incident Reconstruction  
**Case Study:** Simulated Training Investigation

---

### 📌 Executive Summary

On 4 February 2026, Harborlight Dental & Insurance discovered ransom notes in shared folders following a multi-host intrusion.

The investigation reconstructed an attack beginning with a phishing-delivered archive on `BACKOFFICE-PC1`, followed by malicious DLL execution, privilege escalation, process injection, credential access and lateral movement to the file server and domain controller.

The investigation identified:

- **3 compromised hosts**
- **27 encrypted `.akira` files**
- **128 ransom notes**
- **0 security alerts triggered before discovery**

The attacker also carried out activities intended to prevent system recovery, including shadow copy deletion.

The incident highlights the consequences of insufficient endpoint monitoring, weak access controls and a flat network architecture.

---

### 🎯 Hunt Objectives

The investigation aimed to:

1. Identify the initial access vector and execution method.
2. Reconstruct the attacker’s privilege escalation and defense evasion techniques.
3. Investigate credential theft and lateral movement.
4. Identify data staging, ransomware execution and recovery inhibition.
5. Map the attack sequence to MITRE ATT&CK.
6. Identify security monitoring gaps and recommend defensive improvements.

---

### 🧭 Investigation Environment

| Field | Details |
|---|---|
| Organisation | Harborlight Dental & Insurance |
| IT Support | Coastal MSP |
| MSP Team Size | 5 contractors |
| Security Operations | No dedicated SOC or centralised alert queue |
| Initial Endpoint | `BACKOFFICE-PC1` |
| User Account | `HARBORLIGHT\Emily.Grant` |
| File Server | `HL-FS01` |
| Domain Controller | `ADDC01` |
| Network | `172.16.0.0/24` |
| File Server IP | `172.16.0.8` |
| Domain Controller IP | `172.16.0.7` |
| Log Analytics Workspace | `LAW-SilentCorridor` |
| Hunting Table | `HarborlightDental_CL` |

#### Environment Baseline

Prior to the incident:

- Emily Grant did not have administrative privileges.
- Emily Grant did not have software installation rights.
- Emily Grant was not authorised to access servers.
- Domain administrator credentials were maintained by Coastal MSP.
- The network was flat, allowing unrestricted communication between workstations and critical servers.

These environmental conditions were important when distinguishing legitimate activity from malicious behaviour.

---

### 🧠 Threat Hunt Overview

The investigation reconstructed a multi-stage ransomware intrusion.

The attack began with a phishing archive named `Vendor_Invoice_Review.7z`.

An ISO image was mounted as drive `D:`, allowing execution of a malicious DLL using `rundll32.exe`.

The attacker subsequently used process injection, a Windows UAC bypass and a masqueraded Windows executable to execute code within trusted system processes.

Credential access activity involved `lsass.exe`, followed by SMB and WMI-based lateral movement between the workstation, file server and domain controller.

The final stages involved archive staging, ransomware encryption, ransom-note distribution and the deletion of recovery mechanisms.

#### Reconstructed Attack Path

```text
Phishing Archive
       |
       v
BACKOFFICE-PC1
       |
       v
ISO Mount + Rundll32 DLL Execution
       |
       v
Notepad Process Injection
       |
       v
Fodhelper UAC Bypass
       |
       v
Masqueraded taskhostw.exe
       |
       v
Print Spooler Injection
       |
       v
LSASS Credential Access
       |
       v
SMB Lateral Movement
       |
       v
HL-FS01
       |
       v
Additional Credential Access
       |
       v
ADDC01
       |
       v
WMI / SMB Remote Execution
       |
       v
Archive Staging
       |
       v
Akira Ransomware Encryption
       |
       v
Shadow Copy Deletion
```

---

### 🧬 MITRE ATT&CK Mapping

| Attack Stage | Technique | MITRE ATT&CK ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Execution | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Execution | Process Injection | T1055 |
| Privilege Escalation | Bypass User Account Control | T1548.002 |
| Defense Evasion | Masquerading | T1036 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | Valid Accounts | T1078 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Windows Management Instrumentation | T1047 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Persistence | Scheduled Task | T1053.005 |
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Inhibit System Recovery | T1490 |

**Note:** The source report maps archive staging to T1041, Exfiltration Over C2 Channel. However, archive creation alone does not confirm successful external data exfiltration.

---

### 🔍 Detailed Threat Hunt Analysis

<details>
<summary><strong>🚩 Flag 1 – Initial Access: Phishing Archive</strong></summary>

**Objective:** Identify the initial compromise mechanism.

**Finding:**

A phishing archive named `Vendor_Invoice_Review.7z` was delivered to `BACKOFFICE-PC1` under the `HARBORLIGHT\Emily.Grant` user context.

The investigation also associated `offscreendocument_main.js` with the initial access stage.

**Evidence Source:**

- Host: `BACKOFFICE-PC1`
- Sysmon Event ID: `11`
- Artifact: `Vendor_Invoice_Review.7z`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventTime between (datetime("2026-02-04 02:00") .. datetime("2026-02-04 04:00"))
| where host has "BACKOFFICE-PC1" and EventID == 11
| where TargetFilename has "7z"
```

**Security Significance:**

An archive-based phishing lure can introduce executable content into a user environment and initiate the compromise.

**Evidence Screenshot:**

<img width="909" height="574" alt="Screenshot 2026-10-21 194110" src="https://github.com/user-attachments/assets/26ac71f7-9490-42b1-9386-443d3bc8b0a8" />


**Detection Recommendation:**

Monitor suspicious archive creation and subsequent executable or script activity within user sessions.

</details>

<details>
<summary><strong>🚩 Flag 2 – Execution: Rundll32 and Process Injection</strong></summary>

**Objective:** Identify the payload execution mechanism.

**Finding:**

The attacker mounted an ISO image as drive `D:` and executed the DLL `review.dll` using the legitimate Windows binary `rundll32.exe`.

The report also describes injection of the payload into `notepad.exe`.

**Execution Command:**

```text
rundll32.exe D:\review.dll,StartW
```

**Evidence Source:**

- Sysmon Event ID: `1`
- Process: `rundll32.exe`
- Payload: `D:\review.dll`
- Injection target: `notepad.exe`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventTime between (datetime("2026-02-04 02:00") .. datetime("2026-02-04 04:00"))
| where host has "BACKOFFICE-PC1" and EventID == 1
| where Image has "rundll32"
    and CommandLine has "review.dll"
```

**Security Significance:**

Using legitimate Windows binaries and process injection can conceal malicious execution within familiar system activity.

**Evidence Screenshot:**

<img width="836" height="506" alt="image" src="https://github.com/user-attachments/assets/0d81f6fa-7710-407a-853e-95c72d1a1222" />


**Detection Recommendation:**

Alert on unusual `rundll32.exe` execution involving DLLs located on mounted drives or user-accessible directories.

</details>

<details>
<summary><strong>🚩 Flag 3 – Privilege Escalation: UAC Bypass</strong></summary>

**Objective:** Determine how the attacker obtained elevated execution.

**Finding:**

The attacker modified the `ms-settings` Registry handler to trigger malicious DLL execution through `fodhelper.exe`.

The report identifies the following Registry location:

```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

Reported elevation time: `02:42:39`.

**Evidence Source:**

- Sysmon Event ID: `13`
- Registry modification
- `fodhelper.exe` execution

**KQL Query:**

```kql
HarborlightDental_CL
| where EventTime between (datetime("2026-02-04 02:00") .. datetime("2026-02-04 04:00"))
| where EventID == 13
| where TargetObject has "ms-settings"
```

**Security Significance:**

The `fodhelper.exe` auto-elevation mechanism can be abused through Registry hijacking to bypass normal UAC prompts.

**Evidence Screenshot:**

<img width="1052" height="647" alt="Screenshot 2026-10-21 194723" src="https://github.com/user-attachments/assets/c802e48c-118d-43f5-8b76-2ac6e3ceb62f" />


**Detection Recommendation:**

Correlate modifications to the `ms-settings` Registry handler with subsequent `fodhelper.exe` executions.

</details>

<details>
<summary><strong>🚩 Flag 4 – Defense Evasion: Print Spooler Injection</strong></summary>

**Objective:** Identify how attacker execution transitioned into a trusted Windows process.

**Finding:**

A masqueraded `taskhostw.exe` located under `C:\Users\Public\` injected into `spoolsv.exe`.

The legitimate Windows `taskhostw.exe` normally resides in the Windows system directory.

The report identifies `spoolsv.exe` as a central process involved in subsequent malicious operations.

**Evidence Source:**

- Sysmon Event ID: `8`
- Source: Masqueraded `taskhostw.exe`
- Target: `spoolsv.exe`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventTime between (datetime("2026-02-04 02:00") .. datetime("2026-02-04 04:00"))
| where EventID == 8
| where EventData_Xml has "spoolsv"
```

**Security Significance:**

Process injection into a trusted Windows service can obscure malicious activity and complicate process attribution.

**Evidence Screenshot:**

<img width="805" height="566" alt="image" src="https://github.com/user-attachments/assets/a6cad633-2822-4ce3-8d28-36b5c11570f4" />


**Detection Recommendation:**

Monitor unexpected access to Windows service processes and suspicious binaries using legitimate Windows executable names outside their expected directories.

</details>

<details>
<summary><strong>🚩 Flag 5 – Credential Access: LSASS Memory</strong></summary>

**Objective:** Identify credential access enabling lateral movement.

**Finding:**

The investigation describes an injected `spoolsv.exe` process accessing `lsass.exe` with full process access permissions.

The reported access mask was:

```text
0x1FFFFF
```

The report associates this activity with the acquisition of credentials subsequently used for SMB authentication.

The original report includes a plaintext password, which has been redacted for this public portfolio.

**Evidence Source:**

- Sysmon Event ID: `10`
- Target: `lsass.exe`
- Source: `spoolsv.exe`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventTime between (datetime("2026-02-04 02:00") .. datetime("2026-02-04 04:00"))
| where EventID == 10
| where EventData_Xml has "lsass"
```

**Security Significance:**

High-privilege access to LSASS memory is a significant indicator of possible credential dumping.

**Evidence Limitation:**

An LSASS process-access event alone does not establish successful credential extraction without additional corroboration.

**Evidence Screenshot:**

<img width="770" height="618" alt="image" src="https://github.com/user-attachments/assets/fec32feb-3f2e-43b3-84b9-913440d10bbf" />


**Detection Recommendation:**

Alert on unexpected full-access handles to `lsass.exe`, especially from processes that do not normally require such access.

</details>

<CodeBlock language="markdown" editable>
<details>
<summary><strong>🚩 Flag 6 – Lateral Movement: SMB Pivot</strong></summary>

**Objective:** Reconstruct lateral movement between compromised systems.

**Finding:**

The investigation identified lateral movement through SMB administrative shares using compromised credentials.

The reported movement sequence was:

```text
BACKOFFICE-PC1
      |
      v
HL-FS01 (172.16.0.8)
      |
      v
ADDC01 (172.16.0.7)
```

**Evidence Source:**

Network and authentication activity described in the investigation report.

A dedicated Stage 6 KQL query was not supplied.

**Security Significance:**

The flat network architecture enabled access between the initial workstation, file server and domain controller without adequate segmentation.

**Evidence Screenshot:**

_Add screenshot of SMB connections and corresponding authentication events._

**Detection Recommendation:**

Monitor workstation-originated SMB administrative-share access to critical servers and domain controllers.

</details>

<details>
<summary><strong>🚩 Flag 7 – Credential Access: Second LSASS Access</strong></summary>

**Objective:** Identify additional credential harvesting on the file server.

**Finding:**

The attacker reportedly repeated LSASS memory access on `HL-FS01` using injected Print Spooler contexts.

The report associates this activity with attempts to obtain additional administrative and domain credentials.

**Evidence Source:**

- Host: `HL-FS01`
- Sysmon Event ID: `10`
- Target: `lsass.exe`

**KQL Query:**

```kql
HarborlightDental_CL
| where host has "HL-FS01"
    and EventID == 10
| where EventData_Xml has "lsass"
```

**Security Significance:**

Repeated LSASS access across hosts can indicate an attempt to obtain further credentials and expand access to domain infrastructure.


**Detection Recommendation:**

Correlate suspicious LSASS process access with remote authentication, administrative activity and lateral movement.

</details>

<details>
<summary><strong>🚩 Flag 8 – Defense Evasion: Backup Policy Changes</strong></summary>

**Objective:** Identify attempts to interfere with system recovery.

**Finding:**

The investigation describes changes to Registry settings related to Windows Shadow Copies and backup policies.

These changes preceded the reported ransomware encryption activity.

**Evidence Source:**

- Sysmon Event ID: `13`
- Registry changes involving `ShadowCopy`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventID == 13
| where RegistryKey contains "ShadowCopy"
```

**Security Significance:**

Modifying backup and recovery configurations can reduce an organisation's ability to restore systems after ransomware encryption.

**Evidence Screenshot:**

_Add screenshot showing the modified Registry keys and associated processes._

**Detection Recommendation:**

Monitor unauthorised changes to Shadow Copy and backup configurations.

</details>

<details>
<summary><strong>🚩 Flag 9 – Exfiltration Staging: Archive Creation</strong></summary>

**Objective:** Identify data collection and staging before ransomware deployment.

**Finding:**

The report describes the aggregation of business documents, insurance claims, patient records and MSP-related files into `.zip` and `.7z` archives.

These archives were reportedly staged across shared folders before ransomware encryption.

**Evidence Source:**

- Sysmon Event ID: `11`
- File artifacts: `.zip` and `.7z`

**KQL Query:**

```kql
HarborlightDental_CL
| where EventID == 11
| where TargetFilename contains ".zip"
    or TargetFilename contains ".7z"
```

**Security Significance:**

Archive creation during an intrusion may indicate preparation for data theft or movement.

**Evidence Limitation:**

The supplied report establishes archive staging but does not independently confirm successful external exfiltration.

**Evidence Screenshot:**

_Add screenshot of archive creation events and associated process information._

**Detection Recommendation:**

Correlate suspicious archive creation with file access, unusual network activity and outbound data transfers.

</details>

<details>
<summary><strong>🚩 Flag 10 – Impact: Akira Ransomware Encryption</strong></summary>

**Objective:** Identify and quantify ransomware impact.

**Finding:**

The investigation reported:

- **27 distinct encrypted `.akira` files**
- **128 ransom notes**
- Ransomware impact across the affected environment

The attacker reportedly deployed Akira ransomware, encrypting files and distributing ransom notes across affected directories.

**Evidence Source:**

File creation and modification telemetry involving `.akira` extensions.

**KQL Query:**

```kql
HarborlightDental_CL
| where TargetFilename endswith ".akira"
```

**Security Significance:**

Mass file encryption and repeated ransom-note creation are strong indicators of ransomware impact.

**Evidence Screenshot:**

_Add screenshot of encrypted file records and ransomware note activity._

**Detection Recommendation:**

Configure alerts for mass file modifications, suspicious extension changes and rapid ransom-note creation.

</details>

<details>
<summary><strong>🚩 Flag 11 – Persistence: Registry Run Keys</strong></summary>

**Objective:** Identify malicious persistence mechanisms.

**Finding:**

The report describes Registry Run-key modifications across compromised hosts.

These changes were assessed as persistence mechanisms intended to execute malicious payloads during system startup or user logon.

**Evidence Source:**

- Sysmon Event ID: `13`
- Registry Run-key modifications

**KQL Query:**

```kql
HarborlightDental_CL
| where EventID == 13
| where RegistryKey contains "Run"
```

**Security Significance:**

Registry autorun mechanisms can allow malicious programs to execute after a system restart or user authentication.

**Evidence Screenshot:**

_Add screenshot of modified Run keys and associated processes._

**Detection Recommendation:**

Monitor new or modified Run-key entries, particularly those referencing user-writable directories or unfamiliar executables.

</details>

<details>
<summary><strong>🚩 Flag 12 – Command and Control: WMI Execution</strong></summary>

**Objective:** Identify remote execution and control activity.

**Finding:**

The attacker reportedly used Windows Management Instrumentation (`wmic`) and SMB to perform remote commands, file copying and execution activities.

The report describes bidirectional control involving the domain controller and file server.

**Evidence Source:**

Command-line telemetry involving `wmic`.

**KQL Query:**

```kql
HarborlightDental_CL
| where CommandLine has "wmic"
```

**Security Significance:**

Legitimate Windows administration tools can be abused for remote execution and lateral movement, making malicious activity harder to distinguish from normal administration.

**Evidence Screenshot:**

_Add screenshot of WMIC execution and related host activity._

**Detection Recommendation:**

Monitor unusual WMI execution originating from domain controllers and correlate with remote authentication and process creation.

</details>

<details>
<summary><strong>🚩 Flag 13 – Secondary Persistence</strong></summary>

**Objective:** Identify additional mechanisms used to maintain access.

**Finding:**

The investigation describes secondary persistence mechanisms established on `HL-FS01` and `ADDC01`.

Reported mechanisms included:

- Scheduled tasks created through WMI.
- Service-level process reinjection.
- Masqueraded executables in Public directories.
- Additional mechanisms intended to survive cleanup attempts.

**Evidence Source:**

The report provides a narrative finding but does not include specific task names, task triggers or supporting KQL for this stage.

**Security Significance:**

Multiple persistence mechanisms can make containment and eradication more difficult.

**Evidence Screenshot:**

_Add screenshot of scheduled tasks, service changes and suspicious executable paths._

**Detection Recommendation:**

Monitor unauthorised scheduled task creation, service modifications and executables launched from unexpected locations.

</details>

<details>
<summary><strong>🚩 Flag 14 – Recovery Inhibition and Final Encryption</strong></summary>

**Objective:** Identify actions intended to prevent recovery.

**Finding:**

The report describes the final encryption phase and attempts to remove Windows Volume Shadow Copies using native Windows administration utilities.

Reported utilities included:

```text
vssadmin
wmic shadowcopy
```

The objective was to eliminate local recovery points and make restoration more difficult.

**Evidence Source:**

The source report describes shadow-copy deletion but does not provide a dedicated Stage 14 KQL query or complete command-line evidence.

**Security Significance:**

Deleting shadow copies can prevent straightforward restoration of encrypted files and increase the impact of ransomware.

**Evidence Screenshot:**

_Add screenshot showing shadow-copy deletion commands and their results._

**Detection Recommendation:**

Alert on suspicious use of shadow-copy management commands, particularly when combined with mass file encryption activity.

</details>

<details>
<summary><strong>🚩 Flag 15 – Final Intrusion Reconstruction</strong></summary>

**Objective:** Correlate all identified stages into a complete attack sequence.

**Finding:**

The investigation reconstructed the following intrusion:

1. Phishing archive delivered to `BACKOFFICE-PC1`.
2. ISO-mounted DLL execution through `rundll32.exe`.
3. Process injection into `notepad.exe`.
4. UAC bypass through `fodhelper.exe`.
5. Masqueraded `taskhostw.exe` execution.
6. Process injection into `spoolsv.exe`.
7. LSASS credential access.
8. SMB-based movement to `HL-FS01` and `ADDC01`.
9. Additional credential access and WMI execution.
10. Data archive staging.
11. Akira ransomware encryption.
12. Shadow Copy deletion and recovery inhibition.

**Evidence Source:**

Cross-correlation of the preceding investigation stages.

No single telemetry record establishes the entire attack sequence.

**Security Significance:**

Reconstructing the full kill chain helps identify where defensive controls could have interrupted the intrusion.

**Evidence Screenshot:**

_Add reconstructed incident timeline and correlated KQL results._

**Detection Recommendation:**

Implement detection rules that correlate suspicious activity across endpoints, identity systems, network connections and critical infrastructure.

</details>

---

### 🚨 Detection Gaps and Recommendations

| Priority | Security Gap | Recommendation |
|---|---|---|
| P1 | No dedicated SOC or central alert queue | Implement Microsoft Defender XDR or Microsoft Sentinel with centralised monitoring and incident escalation |
| P1 | Flat network architecture | Segment workstations, file servers and domain controllers; restrict SMB and RPC/WMI access |
| P1 | Weak credential controls | Enforce stronger authentication requirements and MFA for privileged access |
| P1 | Limited detection of credential dumping | Monitor suspicious LSASS access and process injection |
| P2 | Abuse of legitimate Windows utilities | Monitor unusual `rundll32.exe`, `fodhelper.exe` and `wmic.exe` execution |
| P2 | Insufficient ransomware detection | Alert on mass file encryption, ransom-note creation and shadow-copy deletion |
| P2 | Limited visibility of potential data theft | Correlate archive creation with outbound network traffic |
| P2 | Recovery mechanisms targeted | Maintain protected offline or immutable backups and regularly test restoration |

---

### 🧾 Final Assessment

**Incident Classification:** Ransomware Intrusion

**Affected Organisation:** Harborlight Dental & Insurance

**Reported Impact:**

| Metric | Result |
|---|---|
| Compromised Hosts | 3 |
| Encrypted `.akira` Files | 27 |
| Ransom Notes | 128 |
| Security Alerts Triggered | 0 |
| Primary Ransomware Family | Akira |
| External Data Exfiltration | Not independently confirmed |

The investigation describes an intrusion beginning with phishing and progressing through privilege escalation, process injection, credential access and lateral movement.

The attacker reportedly used legitimate Windows utilities and trusted system processes to conduct malicious operations.

Insufficient network segmentation and the absence of centralised security monitoring allowed the reported attack to progress across critical infrastructure before discovery.

**Evidence Limitations:**

The portfolio report is based on the supplied incident reconstruction. Some stages are documented through narrative findings without full underlying event details.

Successful external exfiltration, containment actions and recovery outcomes were not established by the available report.

---

### 📎 Key Analyst Notes

**1. Account Access Restrictions**

Emily Grant's account was not authorised to access the file server or domain controller.

Authentication involving this user account and critical server infrastructure should be investigated and monitored.

**2. Print Spooler Abuse**

The investigation identified `spoolsv.exe` as a central process associated with credential access and subsequent attacker activity.

Unexpected Print Spooler process injection should be treated as a high-priority hunting lead.

**3. Credential Access**

The reported LSASS access mask `0x1FFFFF` indicates extensive process access permissions.

Correlating this activity with subsequent authentication is important when investigating credential-based lateral movement.

**4. Network Segmentation**

The flat `172.16.0.0/24` network increased the opportunity for movement between workstations and critical servers.

**5. Detection Coverage**

The absence of centralised alerting contributed to delayed discovery of the reported incident.

---

### 🎓 Skills Demonstrated

- Threat Hunting
- Incident Reconstruction
- Security Incident Analysis
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Windows Event Log Analysis
- Sysmon Telemetry Investigation
- MITRE ATT&CK Mapping
- Ransomware Investigation
- Credential Access Analysis
- Process Injection Detection
- Lateral Movement Investigation
- Windows Persistence Analysis
- Security Monitoring and Detection Engineering
- Incident Response Reporting

---

### 📚 Investigation Source

**Report:** Hunt 22 – Incident Reconstruction Report  
**Organisation:** Harborlight Dental & Insurance  
**Incident ID:** `HL-INC-2026-0204`  
**Incident Date:** 4 February 2026  
**Workspace:** `LAW-SilentCorridor`  
**Telemetry Table:** `HarborlightDental_CL`

