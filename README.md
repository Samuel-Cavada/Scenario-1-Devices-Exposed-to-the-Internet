<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 1: Devices Exposed to the Internet</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-00B388?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-PowerShell-2C5EA8?style=for-the-badge&logo=powershell&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Brute%20Force%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 📌 Project Objective
> Simulate a real-world scenario where a misconfigured virtual machine is exposed to the public internet, and investigate it for brute-force login attempts and potential unauthorized access using Defender for Endpoint and KQL queries.

---

## 🧰 Tools & Technologies
- **Platform:** Azure VM (windows-target-1 or custom)
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint, Log Analytics, PowerShell
- **Languages/Scripts:** KQL

---

## 🧠 Skills Gained / Focus Areas
- Identified failed and successful logon attempts from external IPs
- Correlated activity with brute force behavior
- Used MITRE ATT&CK framework to assess tactics and techniques
- Practiced incident response and documentation process

---

## 🧪 Environment Setup
> Used an Azure VM exposed to the internet. Let the VM run for ~90 minutes to attract brute force attempts from bots or bad actors. Alternatively, used `windows-target-1` honeypot for analysis.

![Environment Setup](assets/images/setup.jpg)

---

## 🛠️ Walkthrough
1. [Step 1: Preparation](#step-1-preparation)
2. [Step 2: Data Collection](#step-2-data-collection)
3. [Step 3: Data Analysis](#step-3-data-analysis)
4. [Step 4: Investigation](#step-4-investigation)
5. [Step 5: Response](#step-5-response)
6. [Step 6: Documentation](#step-6-documentation)
7. [Step 7: Improvement](#step-7-improvement)

---

### ✅ Step 1: Preparation
> Developed a hypothesis: Devices exposed to the public internet without lockout policies may be vulnerable to brute force attacks resulting in unauthorized access.

---

### ✅ Step 2: Data Collection
> Collected logs from the following MDE tables:
- `DeviceInfo`
- `DeviceLogonEvents`

> Ensured log ingestion was current and telemetry was available for both failed and successful logons.

---

### ✅ Step 3: Data Analysis
> Ran the following KQL queries:

```kql
// Top IPs by failed logons
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

```kql
// Check if any of those IPs later logged in successfully
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238","74.39.190.50"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

```kql
// Identify IPs with both failed and successful logons
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName;
let SuccessfulLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName;
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

---

### ✅ Step 4: Investigation
> Investigated whether successful logons followed a pattern of repeated failures  
> Checked timelines, account names, and source IPs  
> Mapped findings to TTPs in the **MITRE ATT&CK** framework (e.g., T1110 – Brute Force)

---

### ✅ Step 5: Response
> - Notified security team  
> - Recommended isolating affected VM if compromise confirmed  
> - Considered forcing password reset and disabling compromised accounts

---

### ✅ Step 6: Documentation
> Documented:
- Devices exposed
- Number and source of failed/successful logons
- Indicators of compromise
- Queries used
- Response taken

---

### ✅ Step 7: Improvement
> - Implemented account lockout policies  
> - Suggested use of just-in-time (JIT) VM access  
> - Recommended Azure Security Center hardening suggestions  
> - Created alert rules based on logon patterns

---

## 📝 Timeline Summary and Findings
- Brute-force attempts detected on multiple VMs  
- At least one successful logon traced to previously failing IP  
- Attack leveraged lack of lockout policy  
- Post-compromise activity was minimal but suspicious

---

## 📎 References
- [MITRE ATT&CK Brute Force Technique](https://attack.mitre.org/techniques/T1110/)
- [Microsoft Defender for Endpoint Hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/security/benchmark/azure/)
