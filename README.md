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

## 🔴Attack-generated files with the .pwncrypt extension confirm encryption activity consistent with ransomware behavior.
<p align="center">
<img width="1715" height="511" alt="image" src="https://github.com/user-attachments/assets/3e11b28f-3c9e-45d9-9cd8-c41955e83d70" />
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

## Future Preventitive Measurses
This incident highlights a common modern attack pattern:
- Legitimate administrative tools (PowerShell) are abused to execute malicious payloads, bypass controls, and evade traditional signature-based detection.
- Detection strategies must therefore prioritize behavioral monitoring over static indicators.
- Strengthen MFA detection and action

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

💡 Identify the Device

<img width="433" height="102" alt="image" src="https://github.com/user-attachments/assets/7852e423-e3f2-4d9b-8197-a78887c4f31e" />

---

💡 Confirm Initiating Process and Command Line

<img width="1427" height="178" alt="image" src="https://github.com/user-attachments/assets/d7022fc7-3dbe-4fa4-8f08-5d071dc515b4" />

---

💡 Confirm Timeline of Infection

<img width="503" height="200" alt="image" src="https://github.com/user-attachments/assets/9b501cdb-42f1-4852-b956-2a16d323bf04" />

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
