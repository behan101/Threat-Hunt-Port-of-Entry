# Threat Hunt: Port of Entry

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/f6352076-3a19-4fc9-abdb-a2a3060c1ca7" />

# 📚 Table of Contents

- [Threat Hunt: "Port of Entry"]
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [Flag 1: INITIAL ACCESS - Remote Access Source](#-flag-1-initial-access---remote-access-source)
  - [Flag 2: INITIAL ACCESS - Compromised User Account](#-flag-2-initial-access---compromised-user-account)
  - [Flag 3: DISCOVERY - Network Reconnaissance](#-flag-3-discovery---network-reconnaissance)
  - [Flag 4: DEFENCE EVASION - Malware Staging Directory](#-flag-4-defence-evasion---malware-staging-directory)
  - [Flag 5: DEFENCE EVASION - File Extension Exclusions](#-flag-5-defence-evasion---file-extension-exclusions)
  - [Flag 6: DEFENCE EVASION - Temporary Folder Exclusion](#-flag-6-defence-evasion---temporary-folder-exclusion)
  - [Flag 7: DEFENCE EVASION - Download Utility Abuse](#-flag-7-defence-evasion---download-utility-abuse)
  - [Flag 8: PERSISTENCE - Scheduled Task Name](#-flag-8-persistence---scheduled-task-name)
  - [Flag 9: PERSISTENCE - Scheduled Task Target](#-flag-9-persistence---scheduled-task-target)
  - [Flag 10: COMMAND & CONTROL - C2 Server Address](#-flag-10-command--control---c2-server-address)
  - [Flag 11: COMMAND & CONTROL - C2 Communication Port](#-flag-11-command--control---c2-communication-port)
  - [Flag 12: CREDENTIAL ACCESS - Credential Theft Tool](#-flag-12-credential-access---credential-theft-tool)
  - [Flag 13: CREDENTIAL ACCESS - Memory Extraction Module](#-flag-13-credential-access---memory-extraction-module)
  - [Flag 14: COLLECTION - Data Staging Archive](#-flag-14-collection---data-staging-archive)
  - [Flag 15: EXFILTRATION - Exfiltration Channel](#-flag-15-exfiltration---exfiltration-channel)
  - [Flag 16: ANTI-FORENSICS - Log Tampering](#-flag-16-anti-forensics---log-tampering)
  - [Flag 17: IMPACT - Persistence Account](#-flag-17-impact---persistence-account)
  - [Flag 18: EXECUTION - Malicious Script](#-flag-18-execution---malicious-script)
  - [Flag 19: LATERAL MOVEMENT - Secondary Target](#-flag-19-lateral-movement---secondary-target)
  - [Flag 20: LATERAL MOVEMENT - Remote Access Tool](#-flag-20-lateral-movement---remote-access-tool)
- [MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [Conclusion](#-conclusion)
- [Lessons Learned](#-lessons-learned)
- [Recommendations for Remediation](#%EF%B8%8F-recommendations-for-remediation)

---

# 🕵️‍♂️ Threat Hunt: *"Port of Entry"*

## Scenario
INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

### Company:
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

### Compromised Systems:
AZUKI-SL (IT admin workstation)

### Available Evidence:
Microsoft Defender for Endpoint logs
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
```

This report includes:

- 📅 Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration of data on the device **``**
- 📜 Detailed queries using Microsoft Defender Advanced Hunting (KQL)
- 🎯 MITRE ATT&CK mapping to understand TTP alignment
- 🧪 Evidence-based summaries supporting each flag and behavior discovered

---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

---

## 📔 Summary of Findings (Flags)

| Flag | Objective | Finding | TimeStamp |
|------|------------------------------------|---------|-----------|
| 1 | Identify the source IP address of the Remote Desktop Protocol connection | `88.97.178.12` was the IP address accessing the compromised account | `2025-11-19T00:57:18.3409813Z` |
| 2 | Identify the user account that was compromised for initial access | The account `kenji.sato` has been compromised | `2025-11-19T00:57:18.3409813Z` |
| 3 |                           |         |           |
| 4 |                           |         |           |
| 5 |                           |         |           |
| 6 |                           |         |           |
| 7 |                           |         |           |
| 8 |                           |         |           |
| 9 |                           |         |           |
| 10 |                          |         |           |
| 11 |                          |         |           |
| 12 |                          |         |           |
| 13 |                          |         |           |
| 14 |                          |         |           |
| 15 |                          |         |           |
| 16 |                          |         |           |
| 17 |                          |         |           |
| 18 |                          |         |           |
| 19 |                          |         |           |
| 20 |                          |         |           |

---
### 🚩 Flag 1: INITIAL ACCESS - Remote Access Source

**Objective:**
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks. Identify the source IP address of the Remote Desktop Protocol connection.

**Flag Value:**
`88.97.178.12`
`2025-11-19T00:57:18.3409813Z`

**Detection Strategy:**
Query logon events for interactive sessions from external sources during the incident timeframe. Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName
```
**Evidence:**
<img width="949" height="307" alt="image" src="https://github.com/user-attachments/assets/7d342911-eb06-401a-917f-bf12cc205cf7" />

**Why This Matters:**
Finding the RemoteIP that was accessed by the compromised account `kenji.sato` is essential to discovering the scope of the compromise accounts and activities.

---

### 🚩 Flag 2: INITIAL ACCESS - Compromised User Account

**Objective:**
Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews. Identify the user account that was compromised for initial access.

**Flag Value:**
`kenji.sato`
`2025-11-19T00:57:18.3409813Z`

**Detection Strategy:**
In the investigation, the RemoteIP was shown to have accessed the compromised account through the Remote Desktop Protocol.

**KQLQuery:**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "RemoteInteractive"
| project Timestamp, AccountName, RemoteIP, AdditionalFields
| sort by AccountName
```
**Evidence:**
<img width="949" height="307" alt="image" src="https://github.com/user-attachments/assets/7d342911-eb06-401a-917f-bf12cc205cf7" />

**Why This Matters:**
Identifying the compromised account along with the RemoteIP can pinpoint any attempts at discovery and other intents of the threat actor.

---

### 🚩 Flag 3: DISCOVERY - Network Reconnaissance

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 4: DEFENCE EVASION - Malware Staging Directory

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 5: DEFENCE EVASION - File Extension Exclusions
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 7: DEFENCE EVASION - Download Utility Abuse
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 8: PERSISTENCE - Scheduled Task Name
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 9: PERSISTENCE - Scheduled Task Target
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 10: COMMAND & CONTROL - C2 Server Address
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 14: COLLECTION - Data Staging Archive
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 15: EXFILTRATION - Exfiltration Channel
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 16: ANTI-FORENSICS - Log Tampering
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 17: IMPACT - Persistence Account
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 18: EXECUTION - Malicious Script
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 19: LATERAL MOVEMENT - Secondary Target
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique                    | ID                                                          | Description                                                             |
| ---- | ---------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------- |
| 1    |                                    |                                                             |                                                                         |
| 2    |                                    |                                                             |                                                                         |
| 3    |                                    |                                                             |                                                                         |
| 4    |                                    |                                                             |                                                                         |
| 5    |                                    |                                                             |                                                                         |
| 6    |                                    |                                                             |                                                                         |
| 7    |                                    |                                                             |                                                                         |
| 8    |                                    |                                                             |                                                                         |
| 9    |                                    |                                                             |                                                                         |
| 10   |                                    |                                                             |                                                                         |
| 11   |                                    |                                                             |                                                                         |
| 12   |                                    |                                                             |                                                                         |
| 13   |                                    |                                                             |                                                                         |
| 14   |                                    |                                                             |                                                                         |
| 15   |                                    |                                                             |                                                                         |
| 16   |                                    |                                                             |                                                                         |
| 17   |                                    |                                                             |                                                                         |
| 18   |                                    |                                                             |                                                                         |
| 19   |                                    |                                                             |                                                                         |
| 20   |                                    |                                                             |                                                                         |

---

## 🧾 Conclusion


---

## 🎓 Lessons Learned


---

## 🛠️ Recommendations for Remediation


