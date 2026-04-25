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


## PwnCrypt Attack Chain (Visual Overview)
<p align="center">
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/4e73dd10-4eb7-41e5-a783-5d5e9b38fe1c" />
</p>

---

## Investigation Flow Diagram
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

### 🔴Attack-generated files with the .pwncrypt extension confirm encryption activity consistent with ransomware behavior.
<p align="center">
<img width="1715" height="611" alt="image" src="https://github.com/user-attachments/assets/3e11b28f-3c9e-45d9-9cd8-c41955e83d70" />
</p>

# 🔴 Root Cause

## Command-Line Evidence
- powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
- Execution policy bypass allowed the malicious script to run without restriction.

- InitiatingProcessFileName = powershell.exe
- Command line showing:  ExecutionPolicy Bypass and pwncrypt.ps1 script reference
- Elevated file modification rates indicate automated encryption activity consistent with ransomware behavior.
- File events reveal PowerShell as the initiating process, confirming script-based ransomware execution.

---

## Attack Timeline – Full Lifecycle

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

## 🔍 Investigation Steps
1. Identify Suspicious Process Activity
We began by reviewing process executions around the suspected timeframe.

let t = datetime(2024-10-16T05:24:46.8334943Z);
DeviceProcessEvents
| where Timestamp between (t - 5m .. t + 5m)
| order by Timestamp desc

🔎 Purpose:
Identify unusual processes
Detect script execution (PowerShell, cmd)
Spot known ransomware tools or loaders

2. Look for Ransomware Execution Indicators
Common ransomware behaviors include:

Use of scripting engines
File encryption tools
Shadow copy deletion
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set",
    "cipher /w",
    "powershell",
    "cmd.exe"
)
| order by Timestamp desc

🔎 Findings:
Evidence of destructive commands may indicate pre-encryption staging
Shadow copy deletion strongly correlates with ransomware activity

---

3. File Modification and Encryption Behavior
Ransomware often performs mass file writes or renames.

DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| summarize count() by DeviceName, bin(Timestamp, 5m)
| order by Timestamp desc

🔎 Indicators:
Sudden spike in file activity
Multiple file extensions changed
Creation of ransom notes

---

4. Identify Ransom Note Artifacts
DeviceFileEvents
| where FileName has_any ("README", "DECRYPT", "RECOVER", "HELP")
| order by Timestamp desc

🔎 Purpose:
Detect ransom notes dropped by attackers
Confirm encryption phase occurred

---

5. Check for Lateral Movement
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| summarize count() by AccountName, DeviceName
| order by count_ desc

🔎 Purpose:
Identify compromised accounts
Detect spread across systems

---

6. Network Communication Analysis
DeviceNetworkEvents
| summarize count() by RemoteIP, DeviceName
| order by count_ desc

🔎 Purpose:
Identify command-and-control (C2) communication
Detect data exfiltration or beaconing

---





💡 Identify the Device

<p align="center">
<img width="633" height="200" alt="image" src="https://github.com/user-attachments/assets/7852e423-e3f2-4d9b-8197-a78887c4f31e" />
</p>

---

💡 Confirm Initiating Process and Command Line
<p align="center">
<img width="1427" height="178" alt="image" src="https://github.com/user-attachments/assets/d7022fc7-3dbe-4fa4-8f08-5d071dc515b4" />
</p>

---

💡 Confirm Timeline of Infection    
// where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))

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
 	• Ransomware → PowerShell script execution

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

## Future Preventitive Measurses
This incident highlights a common modern attack pattern:
- Legitimate administrative tools (PowerShell) are abused to execute malicious payloads, bypass controls, and evade traditional signature-based detection.
- Detection strategies must therefore prioritize behavioral monitoring over static indicators.
- Strengthen MFA detection and action
