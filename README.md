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

📌 Overview

This project documents a full ransomware investigation into PwnCrypt, a PowerShell-based threat that encrypts files and simulates real-world ransomware behavior.

🖼️ PwnCrypt Attack Chain (Visual Overview)
---

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/4e73dd10-4eb7-41e5-a783-5d5e9b38fe1c" />

This attack demonstrates how legitimate tools (PowerShell) can be abused to execute ransomware, bypass security controls, and impact user data within seconds.
- PowerShell used as the execution engine  
- Execution policy bypass for defense evasion  
- `pwncrypt.ps1` as the ransomware payload  
- File encryption and renaming (.pwncrypt)  
- Ransom note creation  


## 🔗 Multiple files with .pwncrypt extension confirm encryption activity consistent with ransomware behavior.

<img width="1715" height="511" alt="image" src="https://github.com/user-attachments/assets/3e11b28f-3c9e-45d9-9cd8-c41955e83d70" />

---

🔬 Process Attribution (Root Cause)

🧠 InitiatingProcessFileName = powershell.exe
Command line showing:  
ExecutionPolicy Bypass
pwncrypt.ps1

📝 Caption
File events reveal PowerShell as the initiating process, confirming script-based ransomware execution.

---

## 🔴 Command-Line Evidence
📝 powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1

📝 Execution policy bypass allowed the malicious script to run without restriction.

---

⏱️ 4. Timeline Correlation

🧠 Highlight
Cluster of events within seconds
File creation burst
Matching timestamps across logs

📝 Caption
Rapid file activity confirms automated encryption behavior typical of ransomware.

🎯 How to Annotate Screenshots (IMPORTANT)
Use any of these tools:

Snipping Tool (Windows)
PowerPoint (best for clean arrows)
Paint / Paint.NET
Canva (cleanest visuals)
🔥 Best Practice (What Recruiters Notice)

Add:

🔴 Red boxes → key evidence
➡️ Arrows → point to fields
📝 Small labels:
“IOC: .pwncrypt”
“Process: powershell.exe”
“Execution Bypass”
🧾 Example Annotation Style

Instead of raw screenshot ❌
Make it look like this ✅:

[ 🔴 powershell.exe ]  → Root cause
[ 🔴 .pwncrypt files ] → Encryption evidence
[ 🔴 ExecutionPolicy Bypass ] → Defense evasion
📂 Screenshots Folder Structure
/screenshots
│
├── 01_file_events.png
├── 02_process_attribution.png
├── 03_command_line.png
├── 04_timeline.png
🚀 Pro-Level Upgrade (Optional)

If you want to go even further:

Add Before/After Section
Before Infection
No .pwncrypt files
Normal activity
After Infection
Mass file creation
PowerShell execution

## 🔗 Investigation Flow Diagram

<img width="500" height="600" alt="Investigative Flow_GOOD" src="https://github.com/user-attachments/assets/aef72ff3-1f61-4733-86df-d7f95eac9b36" />

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







You:

Tell a visual story
Highlight evidence clearly
Show analyst thinking


👉 That’s what gets attention.

🧾 Final Tip

Your README should answer this visually in under 10 seconds:

“What happened, how do you know, and why does it matter?”

If your screenshots + captions do that → you’re at SOC-ready level.

