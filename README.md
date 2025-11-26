# Threat Hunt: Port of Entry

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/f6352076-3a19-4fc9-abdb-a2a3060c1ca7" />

# 📚 Table of Contents

- [Threat Hunt: ""]
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [Flag 1: ] INITIAL ACCESS - Remote Access Source
  - [Flag 2: ] INITIAL ACCESS - Compromised User Account
  - [Flag 3: ] DISCOVERY - Network Reconnaissance
  - [Flag 4: ] DEFENCE EVASION - Malware Staging Directory
  - [Flag 5: ] DEFENCE EVASION - File Extension Exclusions
  - [Flag 6: ] DEFENCE EVASION - Temporary Folder Exclusion
  - [Flag 7: ] DEFENCE EVASION - Download Utility Abuse
  - [Flag 8: ] PERSISTENCE - Scheduled Task Name
  - [Flag 9: ] PERSISTENCE - Scheduled Task Target
  - [Flag 10: ] COMMAND & CONTROL - C2 Server Address
  - [Flag 11: ] COMMAND & CONTROL - C2 Communication Port
  - [Flag 12: ] CREDENTIAL ACCESS - Credential Theft Tool
  - [Flag 13: ] CREDENTIAL ACCESS - Memory Extraction Module
  - [Flag 14: ] COLLECTION - Data Staging Archive
  - [Flag 15: ] EXFILTRATION - Exfiltration Channel
  - [Flag 16: ] ANTI-FORENSICS - Log Tampering
  - [Flag 17: ] IMPACT - Persistence Account
  - [Flag 18: ] EXECUTION - Malicious Script
  - [Flag 19: ] LATERAL MOVEMENT - Secondary Target
  - [Flag 20: ] LATERAL MOVEMENT - Remote Access Tool
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

| Flag | Objective Description | Finding | TimeStamp |
|------|------------------------|---------|-----------|
| 1 |                           |         |           |
| 2 |                           |         |           |
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
### 🚩 Flag 1:

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 2:

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 3:

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 4:

**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 5:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 6:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 7:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 8:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 9:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 10:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 11:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 12:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 13:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 14:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 15:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 16:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 17:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 18:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 19:
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 20:
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


