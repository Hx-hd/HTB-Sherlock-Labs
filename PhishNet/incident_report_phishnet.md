# Incident  Report - Phishing Attempt Unsuccessful

## Executive Summary

- Incident ID: PhishNet

- Incident Severity: Medium (P3)

- Incident Status: Resolved

- Incident Overview: On the morning of February 26, 2025, at perciseley 10:15:00, the accounting team recieved an suspicious emial at 'accounts@globalaccounting.com' from a known vendor requesting a payment of $4,750.00. The message claimed to be an urgent overdue invoice notice and attempted to coerce the recipient into downloading a ZIP attachment. After further analysis, it was determined that the email contained a malicious ZIP attachment designed to deliver malware disguised as a PDF document. This phishing attempt was identified before any user interaction occured. No links were clicked, no attachments were executed, and no credentials were submitted.

---



## Severity Assessment Rationale

This incident was assessed as **P3 (Medium)** because:

- The phishing email was successfully delivered to the user’s inbox  
- The email contained a malicious attachment and a phishing URL  
- No user interaction occurred  
- No systems, credentials, or data were compromised  

---



## Affected Systems & Data

- **Targeted Recipient:** Accounting Department mailbox  
- **Affected Systems:** None  
- **Data Impact:** None confirmed  

No internal systems were compromised, and no sensitive data was accessed or exfiltrated.

---

## Evidence Sources & Analysis

### Email Header Analysis

![](/home/harrison/.var/app/com.github.marktext.marktext/config/marktext/images/2026-01-21-11-43-43-image.png)

Key findings from the email headers:

- **Originating IP Address:** `45.67.89.10`  
- **Relaying Mail Server:** `203.0.113.25`  
- **SPF Result:** Pass  
- **DKIM Result:** Pass  
- **DMARC Result:** Pass  

Despite passing authentication checks, the email was determined to be malicious due to social-engineering indicators and malicious payload delivery.

---

### Sender & Reply-To Discrepancy

![](/home/harrison/.var/app/com.github.marktext.marktext/config/marktext/images/2026-01-21-11-45-29-image.png)

- **From Address:** `finance@business-finance.com`  
- **Reply-To Address:** `support@business-finance.com`  

This mismatch is a common phishing tactic used to redirect responses to attacker-controlled inboxes.

---



## Malicious Content Analysis

### Phishing URL

![](/home/harrison/.var/app/com.github.marktext.marktext/config/marktext/images/2026-01-21-11-49-01-image.png)

- **Embedded URL Domain:** `secure.business-finance.com`  

The domain was crafted to resemble a legitimate vendor subdomain to increase credibility.

---



### Attachment Analysis

![](/home/harrison/.var/app/com.github.marktext.marktext/config/marktext/images/2026-01-21-11-50-06-image.png)

- **Attachment Name:** `Invoice_2025_Payment.zip`  
- **SHA-256 Hash:**  8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a

#### ZIP Contents

![](/home/harrison/.var/app/com.github.marktext.marktext/config/marktext/images/2026-01-21-11-51-16-image.png)

- **Malicious File:** `invoice_document.pdf.bat`

The file uses a double extension to masquerade as a PDF document while executing a Windows batch script if opened.

---

## MITRE ATT&CK Mapping

| Tactic         | Technique                                      |
| -------------- | ---------------------------------------------- |
| Initial Access | T1566.001 – Phishing: Spearphishing Attachment |

---

## Technical Timeline

| Time (UTC)    | Event                                   |
| ------------- | --------------------------------------- |
| 10:05         | Email sent from attacker infrastructure |
| 10:15         | Email delivered to Accounting mailbox   |
| Shortly after | Email flagged during analysis           |
| Same day      | Attachment and URL confirmed malicious  |
| Same day      | Incident closed as unsuccessful         |

---

## Impact Analysis

### Business Impact

- No operational disruption  
- No financial loss  

### Security Impact

- Demonstrates exposure to realistic phishing attempts  
- Highlights attacker use of valid email authentication to bypass filters  

---

## Response and Recovery

### Immediate Response Actions

- Phishing email reported and analyzed  
- Indicators of compromise documented  

### Eradication Measures

- Email deleted from mailbox  
- Attachment hash recorded for future detections  

### Recovery Steps

- No recovery actions required  

---

## Indicators of Compromise (IoCs)

- **Sender IP:** `45.67.89.10`  
- **Relay IP:** `203.0.113.25`  
- **Phishing Domain:** `secure.business-finance.com`  
- **Attachment SHA-256:**  8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a

---

## Root Cause Analysis

The attack relied on social-engineering techniques, including impersonation of a trusted vendor, urgent financial messaging, and a malicious attachment disguised as a legitimate invoice. The use of valid SPF, DKIM, and DMARC records increased the likelihood of successful delivery.

---

## Lessons Learned & Recommendations

- Reinforce user awareness regarding double-extension attachments  
- Emphasize that authentication pass does not guarantee legitimacy  
- Strengthen email filtering rules for ZIP attachments containing executables  
- Continue encouraging prompt reporting of suspicious emails  

---

## Conclusion

This incident represents a realistic phishing attempt that was successfully detected before user interaction occurred. Early identification and proper handling prevented compromise, validating existing detection and response procedures.
