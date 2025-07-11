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

##  Project Objective
> Simulate a real-world scenario where a misconfigured virtual machine is exposed to the public internet, and investigate it for brute-force login attempts and potential unauthorized access using Defender for Endpoint and KQL queries.

---

##  Tools & Technologies
- **Platform:** Azure VM (windows-target-1 or custom)
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint, Log Analytics, PowerShell
- **Languages/Scripts:** KQL

---

##  Skills Gained / Focus Areas
- Identified failed and successful logon attempts from external IPs
- Correlated activity with brute force behavior
- Used MITRE ATT&CK framework to assess tactics and techniques
- Practiced incident response and documentation process

---

##  Environment Setup
> Used an Azure VM exposed to the internet. Let the VM run for a few days to attract brute force attempts from bots or bad actors. Alternatively, used `Cavada-cyber-pc` honeypot for analysis.


---

##  Walkthrough
1. [Step 1: Preparation](#step-1-preparation)
2. [Step 2: Data Collection](#step-2-data-collection)
3. [Step 3: Data Analysis](#step-3-data-analysis)
4. [Step 4: Investigation](#step-4-investigation)
5. [Step 5: Response](#step-5-response)
6. [Step 6: Documentation](#step-6-documentation)
7. [Step 7: Improvement](#step-7-improvement)

---

### ✅ Step 1: Preparation
> Devices exposed to the public internet without lockout policies are vulnerable to brute force attacks, potentially leading to unauthorized access. In this case, the Azure NSG firewall rule allowed inbound traffic from all IPs, leaving the device open to repeated login attempts.

---

### ✅ Step 2: Data Collection
> Collected logs from the following MDE tables:
- `DeviceInfo`
- `DeviceLogonEvents`

> Ensured log ingestion was current and telemetry was available for both failed and successful logons.

---

## ✅ Step 3: Data Analysis

> Ran the following KQL queries to investigate **external login attempts**, **internet exposure window**, and **failed brute-force activity** on `cavada-cyber-pc`.

---

###  Cavada-cyber-pc – Bad Actor Login Attempts

```kql
DeviceLogonEvents
| where DeviceName == "cavada-cyber-pc"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![Raw Image - Cavada-cyber-pc – Bad Actor Login Attempts)](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Devices-Exposed-to-the-Internet/main/images/S1DE6.png)

 **Purpose:** Identify external IP addresses that repeatedly failed to log into `cavada-cyber-pc`.

---

###  Cavada-cyber-pc – Internet Exposure Window (July 1–7, 2025)

```kql
DeviceInfo
| where DeviceName == "cavada-cyber-pc"
| where IsInternetFacing == true
| order by Timestamp desc
```

 **Result:**
- **Exposed Start:** `Jul 1, 2025 10:34:38 AM`
- **Exposed End:** `Jul 7, 2025 11:11:52 PM`

![Raw Image - Cavada-cyber-pc – Internet Exposure Window (July 1–7, 2025)](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Devices-Exposed-to-the-Internet/main/images/S1DE4.png)


 **Purpose:** Confirms the timeframe when the device was externally reachable—critical context for login attempt analysis.

---

###  Cavada-cyber-pc – Failed Public Logon Attempts (Past 7 Days)

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIPType == "Public"
| where Timestamp > ago(7d)
| summarize
   FailedAttempts = count(),
   FirstSeen = min(Timestamp),
   LastSeen = max(Timestamp)
   by
   DeviceName,
   RemoteIP,
   RemoteDeviceName,
   AccountName
| order by FailedAttempts desc
```
![Raw Image - Failed Public Logon Attempts (Past 7 Days) Screenshot](https://raw.githubusercontent.com/Samuel-Cavada/Scenario-1-Devices-Exposed-to-the-Internet/main/images/S1DE3.png)


 **Purpose:** Surfaces the number of failed logins per external IP, device name, and account—helpful in spotting brute-force activity targeting `cavada-cyber-pc`.

---

### ✅ Step 4: Investigation
> Investigated whether successful logons followed a pattern of repeated failures  
> Checked timelines, account names, and source IPs  
> Mapped findings to TTPs (Tactics, Techniques, and Procedures) in the **MITRE ATT&CK** framework 

####  Initial Access

- **T1078.001 – Valid Accounts: Local Accounts**  
  Repeated login attempts suggest an attempt to discover or abuse valid local credentials.

- **T1110 – Brute Force**  
  Generic brute force technique used to gain unauthorized access.

- **T1110.001 – Brute Force: Password Guessing**  
  Numerous failed login attempts from a public IP imply password guessing.

- **T1110.003 – Brute Force: Password Spraying**  
  If multiple usernames are tried with a few common passwords.



#### Defense Evasion *(If Successful Logins Detected)*

- **T1078 – Valid Accounts**  
  An attacker may use valid credentials to evade detection and maintain access without triggering alerts.



####  Discovery *(If Enumeration Behavior Is Present)*

- **T1087 – Account Discovery**  
  Brute-force attempts across many account names may indicate account probing or enumeration behavior.

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
- Attack leveraged lack of lockout policy  
- Post-compromise activity was minimal but suspicious

---

## 📎 References
- [MITRE ATT&CK Brute Force Technique](https://attack.mitre.org/techniques/T1110/)
- [Microsoft Defender for Endpoint Hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/security/benchmark/azure/)
