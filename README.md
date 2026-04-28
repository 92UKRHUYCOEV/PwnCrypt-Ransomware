# PwnCrypt - Ransomware
Microsoft Defender for Endpoint | Advanced Hunting (KQL) | documents a full ransomware investigation involving a newly reported zero-day strain: PwnCrypt.

<p align="center">
  <img src="https://img.shields.io/badge/Threat-Ransomware-critical?style=for-the-badge&logo=hackthebox&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Microsoft%20Defender%20for%20Endpoint-0078D4?style=for-the-badge&logo=microsoft&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-KQL-5C2D91?style=for-the-badge&logo=azuredataexplorer&logoColor=white" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1059%20%7C%20T1486-orange?style=for-the-badge&logo=target&logoColor=white" />
  <img src="https://img.shields.io/badge/SOC%20Focus-Detection%20Engineering-blueviolet?style=for-the-badge&logo=datadog&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Resolved-success?style=for-the-badge&logo=checkmarx&logoColor=white" />
</p>

## 📌 Overview

This project documents a full ransomware investigation into PwnCrypt, a PowerShell-based threat that encrypts files and simulates real-world ransomware behavior.

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate. This report documents a threat hunting investigation focused on identifying and analyzing ransomware-related activity within a monitored environment. The objective was to detect suspicious behaviors, assess impact, and determine whether ransomware execution or pre-encryption activity occurred.

The investigation leverages Microsoft Defender for Endpoint (MDE) telemetry and Kusto Query Language (KQL) to identify indicators aligned with ransomware tactics, techniques, and procedures (TTPs).

🎯 Objectives
- Detect potential ransomware execution or staging activity
- Identify affected systems, users, and processes
- Analyze attacker behavior and timeline
- Evaluate impact on the environment
- Recommend improvements for detection and prevention

🧠 Threat Context
Ransomware attacks typically follow a structured lifecycle:

1. Initial access (phishing, exploit, or credential abuse)
2. Execution of payload
3. Persistence establishment
4. Privilege escalation
5. Lateral movement
6. Data encryption and/or exfiltration

This investigation focuses primarily on execution, impact, and evidence of encryption behavior.


## 👀 PwnCrypt Attack Chain (Visual Overview)
<p align="center">
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/4e73dd10-4eb7-41e5-a783-5d5e9b38fe1c" />
</p>

---

## 🗝️ Investigation Flow Diagram
<p align="center">
<img width="1024" height="1536" alt="PwnCrypt Ransomware TH_contrast adjst_04-23-26" src="https://github.com/user-attachments/assets/69ce393d-423a-488d-8113-eb3250eb5e12" />
</p>

This attack demonstrates how legitimate tools (PowerShell) can be abused to execute ransomware, bypass security controls, and impact user data within seconds.
- PowerShell used as the execution engine  
- Execution policy bypass for defense evasion  
- `pwncrypt.ps1` as the ransomware payload  
- File encryption and renaming (.pwncrypt)  
- Ransom note creation  

---

## 📢 Attack-generated files with the .pwncrypt extension confirm encryption activity consistent with ransomware behavior.
<p align="center">
<img width="1715" height="611" alt="image" src="https://github.com/user-attachments/assets/3e11b28f-3c9e-45d9-9cd8-c41955e83d70" />
</p>

---

## 🕑 Attack Timeline – Full Lifecycle

| Time | Stage | Event | Data Source | Evidence |
|:-----|:------|:------|:------------|:---------|
| Day 1 – 08:24 AM | Initial Access | User logs in from unfamiliar IP/location | SigninLogs | Successful login without MFA |
| Day 1 – 08:35 AM | Initial Access | Authentication completed using single-factor | SigninLogs | AuthenticationRequirement = singleFactorAuthentication |
| Day 1 – 09:02 AM | Initial Access | Conditional Access marked as success | SigninLogs | ConditionalAccessStatus = success |
| Day 1 – 09:15 AM | Initial Access | Attacker establishes foothold | SigninLogs | Repeated successful logins |
| Day 2 – 10:12 AM | Lateral Movement | Internal system discovery begins | DeviceProcessEvents | Suspicious process activity |
| Day 2 – 10:28 AM | Lateral Movement | Remote execution initiated (PowerShell/PsExec) | DeviceProcessEvents | CommandLine contains remote execution |
| Day 2 – 11:03 AM | Lateral Movement | Same account accesses multiple systems | DeviceProcessEvents | AccountName across multiple DeviceNames |
| Day 2 – 01:47 PM | Lateral Movement | Privilege expansion / admin share usage | DeviceProcessEvents | Evidence of admin-level commands |
| Day 3 – 08:11 AM | Impact | Malicious script executed (pwncrypt.ps1) | DeviceProcessEvents | PowerShell execution with script |
| Day 3 – 08:12 AM | Impact | File encryption begins | DeviceFileEvents | Files renamed with .pwncrypt |
| Day 3 – 08:18 AM | Impact | Ransom note created | DeviceFileEvents | Decryption instructions file |
| Day 3 – 08:24 AM | Impact | Security alert triggered | Alerts/Incidents | Ransomware behavior detected |

[ 🔴 powershell.exe ] → ➡️Root cause [ 🔴 .pwncrypt files ] → ➡️Encryption evidence [ 🔴 ExecutionPolicy Bypass ] → ➡️Defense evasion

---

## 🧪 Data Sources
The following MDE tables were used:

- DeviceProcessEvents
- DeviceFileEvents
- DeviceNetworkEvents
- DeviceLogonEvents
- DeviceInfo

---

## 🔍 Detection Logic
```markdown
Purpose: Identify first and last observed ransomware file activity
Reviewed process execution within the suspected timeframe to establish initial and final indicators.

### 🔍 KQL Query

```kql
DeviceFileEvents
| where FileName contains "pwncrypt"
| where DeviceName == "windows-target-"
| summarize 
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp)
    by DeviceName
```

<img width="571" height="199" alt="image" src="https://github.com/user-attachments/assets/d6451a31-d8ab-4b8b-b754-f48346dca583" />

---

## 🔍 Look for Common Ransomware Indicators
```markdown
Process execution analysis identified commands associated with ransomware staging,
including shadow copy deletion and backup removal. The presence of PowerShell
and command-line activity further indicates the use of legitimate tools to
execute malicious actions. These behaviors strongly correlate with pre-encryption
activity commonly observed in ransomware attacks.
```

## 🔍 KQL Query
```markdown
DeviceProcessEvents
| where ProcessCommandLine contains "pwncrypt"
   or ProcessCommandLine contains "ExecutionPolicy Bypass"
| where DeviceName == "windows-target-"
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set",
    "cipher /w",
    "powershell",
    "cmd.exe"
)
| order by Timestamp desc
```

<img width="1240" height="144" alt="PERUSE22" src="https://github.com/user-attachments/assets/f4f6c329-b0ea-4fcd-b7b1-5b00941d6353" />

---

🚨 Why These Commands Matter
1. vssadmin delete shadows → Deletes shadow copies (prevents file recovery)
2. wbadmin delete catalog → Removes backup catalog
3. bcdedit /set → Can disable recovery/boot protections
4. cipher /w → Wipes free space (anti-forensics)
5. powershell / cmd.exe → Common execution tools (LOLBins)

---

## 🔍 File Modification and Encryption Behavior
```markdown
Ransomware typically performs large-scale file operations, including rapid file writes, renames,
and extension changes, resulting in abnormal spikes in file system activity.
These patterns are indicative of automated encryption processes and can be used
as a key behavioral indicator of ransomware execution
```kql
DeviceFileEvents
| where DeviceName == "windows-target-"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| summarize count() by DeviceName, bin(Timestamp, 5m)
| order by Timestamp desc
```
<img width="567" height="494" alt="image" src="https://github.com/user-attachments/assets/304115ad-fe3b-429e-a789-fd9463d4887e" />

🔎 Indicators include elevated file activity, mass file renaming, consistent with ransomware execution.

---

## 🔍 Evidence of encryption spreading
```markdown
// Encryption Confirmation
let ransomwareExtension = "pwncrypt";
DeviceFileEvents
| where DeviceName == "windows-target-"
| where FileName contains ransomwareExtension
| summarize 
    FileCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    AffectedFolders = dcount(FolderPath)
    by DeviceName, InitiatingProcessFileName
| where FileCount > 20   // threshold for mass activity (adjust if needed)
| project 
    DeviceName,
    InitiatingProcessFileName,
    FileCount,
    AffectedFolders,
    FirstSeen,
    LastSeen,
    Duration = LastSeen - FirstSeen
| order by FileCount desc
```
<img width="1316" height="354" alt="image" src="https://github.com/user-attachments/assets/ff665a3d-de12-4369-b148-d484a981cec5" />

---

🔎 Confirm encryption phase occurred -> Encryption = mass file changes + new extensions + rapid activity

---

## 🔍Check for Lateral Movement

Lateral movement is the phase where an attacker, after initial access, moves between systems to expand control, 
access more data, and position for impact (e.g., ransomware). In most real incidents, the damage happens after 
lateral movement—not at initial access. This sits between Initial Access → Ransomware Execution.

I detect lateral movement by identifying account reuse across multiple devices, remote execution activity, and administrative tool usage within a short timeframe.

## 🚧 Identify Account Reuse Across Devices
```markdown
DeviceProcessEvents
| summarize DeviceCount = dcount(DeviceName) by AccountName
| where DeviceCount > 2
```
<img width="294" height="477" alt="image" src="https://github.com/user-attachments/assets/5c6f1412-44bd-438d-957b-f142dc27304e" />

```markdown
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| summarize count() by AccountName, DeviceName
| order by count_ desc
```
<img width="511" height="496" alt="image" src="https://github.com/user-attachments/assets/56de710a-7543-4e7a-8432-0903746d125c" />


## 🤖 Admin Tool Abuse (LOLBins)
```markdown
DeviceProcessEvents
| where FileName in~ ("psexec.exe", "wmic.exe", "powershell.exe", "cmd.exe")
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```
<img width="2029" height="500" alt="image" src="https://github.com/user-attachments/assets/33572139-c6c9-4383-883e-f56a64f7e13e" />

🔎 Purpose:
- Identify compromised accounts
- Detect spread across systems

---

## 🪓 Network Communication Analysis (Lateral Movement)
Identify Internal Communication (Lateral Movement)
```Markdown
DeviceNetworkEvents
| where RemoteIPType == "Private"
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| order by ConnectionCount desc
```
<img width="694" height="558" alt="image" src="https://github.com/user-attachments/assets/68e9ddfb-c6b9-49b3-9312-26d42d401fff" />

👉 Detects:
- Device-to-device communication inside the network 
- Potential pivoting between systems

---

## 🪓 Detect External Connections (Potential C2) 
```markdown
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP
| order by ConnectionCount desc
```
<img width="304" height="371" alt="image" src="https://github.com/user-attachments/assets/403b8afb-e718-42db-91e4-0d28f507e259" />
👉 Detects:
- Communication to external IPs
- Identify command-and-control (C2) communication
- Detect data exfiltration or beaconing

---

## 🪓 Detect Ransom Note File Dropped - 
When a ransom note appears, you’re past “early warning” and into confirmed impact. The priority shifts to containment, preservation of evidence, and recovery—in that order. 

```markdown
DeviceFileEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where FileName has_any ("README", "DECRYPT", "RECOVER", "HOW_TO_RESTORE")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1788" height="250" alt="image" src="https://github.com/user-attachments/assets/13ca2ad9-7617-4e75-8dc5-3fb17e2be30a" />

🚨 Immediate Actions (First Minutes)
1) Isolate the affected system
* Remove from network (EDR isolation or pull the cable/Wi-Fi)
* Do not power it off unless encryption is still actively spreading and you can’t isolate

2) Stop the blast radius
* Disable shared drives / file shares if multiple systems are involved
* Temporarily block SMB/RDP if lateral movement is suspected

3) Preserve evidence
### Don’t delete the ransom note or files
* Capture:
** Process list
** Network connections
** Logged-on users
** In MDE, collect a live response package

---
🔎 Triage & Verification (First Hour)
* Confirm what happened
* Which hosts are affected?
* What files are encrypted (extensions, paths)?
* Is encryption still ongoing?

// Other hosts with same extension
```markdown
DeviceFileEvents
| where FileName has "pwncrypt"
| summarize count() by DeviceName
```
<img width="298" height="528" alt="image" src="https://github.com/user-attachments/assets/9767acee-9caa-4fb5-82a4-bf0c810e8701" />

---

// Ransom note artifacts
DeviceFileEvents
```markdown
DeviceFileEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where FileName has_any ("README","DECRYPT","INSTRUCTIONS")
```
<img width="1408" height="314" alt="image" src="https://github.com/user-attachments/assets/9aaf0b9f-afbe-4307-bc96-9cf7b1c475f6" />


// Suspected Execution Method
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-09T00:00:00Z) .. datetime(2025-12-23T23:59:59Z))
| where ProcessCommandLine has_any ("ExecutionPolicy Bypass",".ps1","vssadmin")


---
⚠️ Key Findings
- Suspicious process activity observed around the target timeframe
- Indicators of defense evasion, including shadow copy deletion
- Abnormal spike in file modifications consistent with encryption behavior
- Potential ransom note artifacts detected
- Signs of lateral movement across systems
- External network connections suggest possible attacker communication
- Strong evidence that a Ransom Note was dropped

---





💥 Impact Assessment
| Category           | Impact | Level  | Notes                                           |
|--------------------|--------|--------|-------------------------------------------------|
| Endpoint Systems   | High   | High   | Multiple devices show suspicious activity       |
| Data Integrity     | High   | High   | Likely file encryption or tampering             |
| User Accounts      | Medium | Medium | Possible credential compromise                  |
| Network Security   | Medium | Medium | External communication observed                 |

---

💡 Confirm Initiating Process and Command Line
<p align="center">
<img width="1427" height="178" alt="image" src="https://github.com/user-attachments/assets/d7022fc7-3dbe-4fa4-8f08-5d071dc515b4" />
</p>

---

💡 Confirm Timeline of Infection    
<img width="503" height="200" alt="image" src="https://github.com/user-attachments/assets/9b501cdb-42f1-4852-b956-2a16d323bf04" />

The provided timestamp in the lab instructions did not align with the dataset. Instead, timestamps were derived directly from observed .pwncrypt file events. Using these timestamps, process events were correlated, confirming that powershell.exe executed the ransomware script within the observed timeframe.

---

🔗🔴 Investigation Summary

The investigation followed a structured evidence-based approach:

- Detection – Identified .pwncrypt file artifacts
- Attribution – Linked file activity to powershell.exe
- Execution Analysis – Confirmed use of execution policy bypass
- Validation – Correlated process logs with file activity
- Conclusion – Established root cause as malicious script execution

🔗🔴 Why did this happen?
	• Identity → MFA not enforced
	• Lateral → valid credentials abused
 	• Ransomware → PowerShell script with -ExecutionPolicy -Bypass

---

🔗🔴 MITRE ATT&CK Mapping – Full Attack Lifecycle
   ####  Mapped using the MITRE ATT&CK framework

| Stage            | Tactic              | Technique ID | Technique Name                | How It Appears in Your Lab                       |
|:-----------------|:--------------------|:-------------|:------------------------------|:-------------------------------------------------|
| Identity         | Initial Access      | T1078        | Valid Accounts                | Attacker logs in using legitimate credentials    |
| Identity         | Credential Access   | T1110        | Brute Force (optional)        | Multiple login attempts (if observed)            |
| Identity         | Defense Evasion     | T1556        | Modify Authentication Process | MFA bypass / Conditional Access misconfiguration |
| Lateral Movement | Lateral Movement    | T1021        | Remote Services               | Remote execution (PsExec, WMI, PowerShell)       |
| Lateral Movement | Execution           | T1059.001    | PowerShell                    | PowerShell used for remote commands              |
| Lateral Movement | Persistence         | T1569        | System Services               | Remote service execution (PsExec behavior)       |
| Lateral Movement | Credential Access   | T1078        | Valid Accounts                | Same account used across multiple devices        |
| Ransomware       | Execution           | T1059.001    | PowerShell                    | Script execution (pwncrypt.ps1)                  |
| Ransomware       | Impact              | T1486        | Data Encrypted for Impact     | Files encrypted with .pwncrypt extension         |
| Ransomware       | Defense Evasion     | T1070        | Indicator Removal (optional)  | Cleanup behavior (if observed/logged)            |

---

## 🔴 Root Cause
#### 🔍 Command-Line Evidence
- powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
- Execution policy bypass allowed the malicious script to run without restriction.
- InitiatingProcessFileName = powershell.exe
- Command line showing:  ExecutionPolicy Bypass and pwncrypt.ps1 script reference
- Elevated file modification rates indicate automated encryption activity consistent with ransomware behavior.
- File events reveal PowerShell as the initiating process, confirming script-based ransomware execution.

---

## 🔍 Future Preventitive Measurses
This incident highlights a common modern attack pattern:
- Legitimate administrative tools (PowerShell) are abused to execute malicious payloads, bypass controls, and evade traditional signature-based detection.
- Detection strategies must therefore prioritize behavioral monitoring over static indicators.
- Strengthen MFA detection and action

---

## 🧯 Recommendations
Immediate Actions
* Isolate affected endpoints
* Disable compromised accounts
* Block malicious IPs and domains
* Initiate incident response procedures

---

## 🔍 Preventive Measures
* Enforce Multi-Factor Authentication (MFA)
* Apply least privilege access controls
* Regularly back up critical data (offline backups preferred)
* Patch vulnerabilities and update systems

---

## 📈 Lessons Learned
* Earlier detection of destructive commands could reduce impact
* Monitoring file activity spikes is critical for ransomware detection
* Centralized logging significantly improves investigation speed
* Detection rules should focus on behavior, not just signatures

---

## 🚨 Conclusion

This investigation revealed multiple indicators consistent with ransomware activity, including process execution patterns, file system changes, and possible attacker movement across the network.

---

✍️ Author Notes

This report represents a structured threat hunting workflow designed to simulate real-world ransomware detection and analysis using Microsoft Defender for Endpoint.

While full confirmation of encryption depends on additional forensic validation, the observed behaviors strongly suggest ransomware impact or pre-encryption staging.

Strengthening detection logic and response readiness will significantly reduce risk in future incidents.

---


