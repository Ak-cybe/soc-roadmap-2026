# Project 1: Live SOC Alert Monitoring
**Platform:** LetsDefend | **Duration:** 2-3 weeks | **Difficulty:** Beginner

---

## Project Overview

Simulate real-world SOC Tier-1 analyst work by monitoring, triaging, and investigating security alerts in LetsDefend's simulated SOC environment. This project builds foundational skills in alert classification, log pivoting, and escalation decision-making.

---

## Learning Objectives

- Master the alert triage process (true positive, false positive, benign)
- Learn to use SIEM-like interfaces for log correlation
- Understand when to escalate vs. close alerts
- Document investigation findings professionally
- Build muscle memory for common attack patterns

---

## Tools & Technologies

- **Platform:** LetsDefend SOC Analyst path
- **Simulated Tools:** SIEM dashboard, endpoint security console, email gateway
- **Log Types:** Windows Event Logs, firewall logs, proxy logs, email headers
- **Frameworks:** Cyber Kill Chain, MITRE ATT&CK (basic)

---

## Step-by-Step Execution Plan

### **Week 1: Setup & Initial Triage Sessions**

#### Day 1-2: Platform Familiarization
1. Create LetsDefend account (free tier)
2. Complete the "SOC Analyst Learning Path" intro modules
3. Review the alert dashboard interface
4. Understand alert severity levels (Informational → Critical)

#### Day 3-7: First 20 Alerts (Variety Pack)
**Goal:** Work through 20 different alerts across multiple categories

**For EACH alert, follow this workflow:**

1. **Alert Review (2 min)**
   - Read alert title, severity, source IP, destination IP, timestamp
   - Note the alert type (e.g., "Suspicious PowerShell Execution", "Brute Force Attempt")

2. **Initial Hypothesis (1 min)**
   - Ask: "Is this consistent with known-good behavior?"
   - Examples:
     - Brute force from internal IP → likely compromised host
     - PowerShell from admin workstation → might be legitimate sysadmin
     - Download from sketchy domain → investigate further

3. **Evidence Gathering (5-10 min)**
   - Pivot into logs:
     - **Endpoint logs:** Check process tree, parent process, command-line arguments
     - **Network logs:** Examine connections, DNS queries, data transfer volumes
     - **Email logs:** Analyze headers, attachments, links (for phishing alerts)
   - Look for IOCs (Indicators of Compromise):
     - Suspicious file hashes
     - Known-bad IPs/domains (use VirusTotal, AbuseIPDB within platform)
     - Unusual processes or registry modifications

4. **Classification Decision (2 min)**
   - **True Positive (Malicious):** Clear evidence of attack → escalate
   - **False Positive (Misconfigured):** Legitimate activity flagged incorrectly → close with notes
   - **Benign Positive:** Authorized security testing or known-safe behavior → close
   
5. **Documentation (3 min)**
   - Fill out the investigation form:
     - Summary of findings
     - Evidence (screenshot references, log snippets)
     - Recommended action (escalate, block IP, isolate host, close)
   - Copy your notes to your local `triage-log.md` file (see template below)

**Daily Target:** 2-3 alerts/day (Week 1)

---

### **Week 2: Pattern Recognition & Speed**

#### Day 8-14: Work 30 More Alerts (Total: 50)
**Goal:** Increase speed and recognize common patterns

**Focus areas:**
- **Phishing alerts:** Learn to spot spoofed senders, malicious attachments, credential harvesting links
- **Brute force:** Identify failed login patterns, differentiate between password spray vs. targeted brute force
- **Malware execution:** Recognize suspicious process behavior (rundll32, regsvr32, PowerShell encodings)

**New challenge:** Aim for 4-5 alerts/day by end of Week 2

**Pattern Recognition Checklist:**
- [ ] Can identify phishing emails in < 2 minutes
- [ ] Recognize common malware families (Emotet, Cobalt Strike indicators)
- [ ] Differentiate between user error and actual compromise

---

### **Week 3: Advanced Scenarios & Capstone**

#### Day 15-18: Multi-Stage Attack Investigation
**Goal:** Investigate 2-3 complex, multi-alert incidents

LetsDefend provides linked alert chains (e.g., phishing email → malware download → C2 communication). Practice:

1. **Timeline reconstruction:**
   - Map events chronologically
   - Identify initial access → execution → persistence → exfiltration
   
2. **MITRE ATT&CK mapping:**
   - Tag each stage with relevant tactics/techniques
   - Example: Initial Access (T1566 Phishing) → Execution (T1059 PowerShell)

3. **Containment recommendations:**
   - Block malicious IPs/domains at firewall
   - Isolate affected endpoints
   - Force password reset for compromised accounts

#### Day 19-21: Documentation & Portfolio Prep
1. **Select your top 3 investigations:**
   - 1 phishing incident
   - 1 malware/endpoint incident
   - 1 brute force/network incident

2. **Create detailed case write-ups** (use template below)

3. **Capture evidence:**
   - Screenshots (REDACT sensitive data: real IPs, usernames, company names)
   - Alert details, log snippets, investigation timeline

4. **Reflect on lessons learned:**
   - What IOCs were most useful?
   - What would you do differently?
   - How did this improve your triage speed?

---

## Evidence to Capture

### Throughout the Project:
- [ ] Screenshot of your alert dashboard showing completed investigations
- [ ] 3 detailed case write-ups (see template)
- [ ] Your `triage-log.md` with all 50+ alert summaries
- [ ] List of common IOCs encountered (IP, domains, file hashes)

### Sensitive Data Handling:
**ALWAYS REDACT:**
- Real company names (replace with "Company X")
- Real IP addresses (use `192.0.2.x` or `10.x.x.x`)
- Real usernames (use `user@example.com`)
- Internal system names

---

## Triage Log Template

Create a file: `01-Live-SOC-Monitoring/triage-log.md`

```markdown
# SOC Alert Triage Log

## Alert #1
**Date:** 2026-01-10  
**Alert Title:** Brute Force Attempt Detected  
**Severity:** High  
**Source IP:** 203.0.113.45 (external)  
**Target:** user@company.com  

**Hypothesis:** External attacker attempting credential stuffing  

**Evidence:**
- 150 failed login attempts in 5 minutes
- Source IP flagged on AbuseIPDB (malicious score: 85%)
- No successful logins

**Classification:** True Positive - Malicious  
**Action Taken:** Blocked source IP, recommended MFA enforcement  
**Time to Triage:** 8 minutes  

---

## Alert #2
[Repeat for all alerts...]
```

---

## Case Write-Up Template

For your top 3 investigations, create detailed reports:

```markdown
# Case: Phishing Campaign Leading to Credential Compromise

## Executive Summary
Investigated a sophisticated phishing email that bypassed email filters and led to credential harvesting for 3 user accounts. Attack was contained within 2 hours of initial detection.

## Timeline
- **09:15 AM:** Phishing email delivered to 15 users
- **09:47 AM:** First user clicked malicious link
- **10:02 AM:** Alert triggered - suspicious login from new geolocation
- **10:15 AM:** Investigation started
- **11:30 AM:** Containment complete

## Investigation Steps
1. Analyzed email headers - identified spoofed sender domain
2. Examined URL - fake Office 365 login page hosted on attacker infrastructure
3. Reviewed proxy logs - confirmed 3 users submitted credentials
4. Checked authentication logs - detected logins from attacker IP
5. Traced attacker activity post-compromise - attempted mailbox access

## Indicators of Compromise (IOCs)
| Type | Value | Description |
|------|-------|-------------|
| Domain | secure-office365-login[.]com | Fake login page |
| IP Address | 185.220.101.X | Attacker infrastructure |
| File Hash | a3f2e1... | Malicious attachment (if applicable) |

## MITRE ATT&CK Mapping
- **T1566.002:** Phishing - Spearphishing Link
- **T1078:** Valid Accounts (compromised credentials)
- **T1114:** Email Collection (attempted)

## Containment Actions
- Blocked malicious domain at web proxy
- Reset passwords for 3 affected accounts
- Enabled MFA enforcement
- Quarantined remaining phishing emails

## Lessons Learned
- Email filters missed this due to new domain registration
- User security awareness training needed
- Faster detection possible with behavioral analytics

## Recommendations
1. Implement DMARC/SPF/DKIM enforcement
2. Deploy URL sandboxing for links
3. Conduct phishing simulation exercises
```

---

## Resume Bullets

Copy these and customize with your specific metrics:

### Version 1: Focused on Volume & Triage
> **SOC Analyst Simulation - LetsDefend Platform**  
> - Monitored and triaged **150+ security alerts** across phishing, malware, and brute-force categories, achieving 92% accurate classification rate (true/false positives)  
> - Investigated multi-stage attack scenarios including initial access, lateral movement, and data exfiltration using SIEM log correlation and EDR telemetry  
> - Documented incident findings with MITRE ATT&CK mappings and actionable containment recommendations, reducing average triage time from 15 to 6 minutes

### Version 2: Focused on Specific Skills
> **Live SOC Monitoring & Incident Triage**  
> - Performed Tier-1 SOC analyst duties in simulated environment, analyzing Windows Event Logs, firewall logs, and email headers to identify indicators of compromise (IOCs)  
> - Escalated 12 true-positive incidents with detailed evidence packages including timeline reconstruction, affected assets, and remediation steps  
> - Leveraged threat intelligence platforms (VirusTotal, AbuseIPDB) to validate malicious infrastructure and correlate IOCs across multiple alerts

### Version 3: Results-Oriented
> **Security Operations Monitoring Project**  
> - Detected and investigated **8 successful phishing attempts** and **5 malware infections** in a realistic SOC environment, documenting full incident lifecycle from detection to containment  
> - Achieved 85% reduction in false-positive alert noise through refined triage criteria and pattern recognition across 150+ security events  
> - Created standardized investigation playbooks for common attack types, improving team efficiency and consistency in alert handling

**Pick 2-3 bullets** that best match the job description you're applying to.

---

## Interview Talking Points

### Question: "Tell me about a time you investigated a security incident."

**STAR Method Answer:**

**Situation:**  
"During my SOC analyst training on LetsDefend, I was working through the alert queue and encountered a high-severity alert for suspicious PowerShell execution on a user workstation."

**Task:**  
"My job was to determine if this was malicious activity or a false positive, and if malicious, identify the scope and recommend containment actions."

**Action:**  
"I started by examining the alert details - I saw an encoded PowerShell command with the `-EncodedCommand` flag, which is often used by attackers to obfuscate malicious scripts. I pivoted into the endpoint logs to check the parent process and found it was spawned by Microsoft Word, which is a red flag for a malicious macro.

I then decoded the Base64 PowerShell command and discovered it was downloading a payload from an external IP. I checked that IP against threat intelligence feeds and confirmed it was associated with Emotet malware campaigns.

Next, I reviewed network logs and found the host had successfully downloaded the payload and established a C2 connection. I documented the full timeline, mapped it to MITRE ATT&CK techniques (T1059.001 for PowerShell, T1071 for C2), and compiled a list of IOCs."

**Result:**  
"I classified it as a true positive - active malware infection - and recommended immediate endpoint isolation, blocking the C2 IP at the firewall, and scanning other hosts for the same file hash. This investigation took me about 12 minutes and reinforced my understanding of how macros are weaponized and the importance of checking parent processes."

---

### Question: "How do you prioritize alerts in a busy SOC?"

**Strong Answer:**
"I use a combination of severity, context, and business impact:

1. **Severity first:** Critical and high alerts get immediate attention, but I don't blindly trust the initial classification
2. **Context matters:** A failed login from a known VPN country might be low priority, but 50 failed logins in 2 minutes is high priority regardless of source
3. **Asset criticality:** Alerts involving domain controllers, payment systems, or executive accounts jump to the top
4. **Kill chain stage:** An alert showing data exfiltration (later stage) is more urgent than initial reconnaissance

In my LetsDefend training, I learned to quickly scan for these factors in the first 30 seconds of opening an alert, which helped me work through 150+ alerts efficiently while catching all the critical ones."

---

### Question: "What's the difference between a true positive and false positive? How do you decide?"

**Strong Answer:**
"A **true positive** is when an alert correctly identifies actual malicious or unauthorized activity. A **false positive** is when legitimate activity triggers an alert due to overly broad detection rules or misconfiguration.

To decide, I follow a checklist:
1. **Verify the behavior:** Is the activity actually malicious or just unusual?
2. **Check context:** User role, time of day, known maintenance windows
3. **Correlate with other data:** Single suspicious event vs. pattern of IOCs
4. **Validate IOCs:** Check file hashes, IPs, domains against threat intel

For example, I investigated an alert for 'mass file deletion' that initially looked like ransomware. After checking, I found it was a developer cleaning up test files during business hours on their assigned dev server - context made it a clear false positive. I documented this as a tuning opportunity for the detection rule to exclude that specific server or require additional indicators before alerting."

---

## Skills Developed Checklist

By completing this project, you will demonstrate:

**Technical Skills:**
- [ ] Alert triage and classification
- [ ] Log analysis (Windows Event, network, email)
- [ ] SIEM navigation and log correlation
- [ ] IOC identification and validation
- [ ] Threat intelligence platform usage
- [ ] Incident documentation and reporting

**Frameworks & Methodologies:**
- [ ] Cyber Kill Chain
- [ ] MITRE ATT&CK Framework (basic tactics/techniques)
- [ ] Incident response phases (detection, analysis, containment)

**Soft Skills:**
- [ ] Time management under alert load
- [ ] Decision-making under uncertainty
- [ ] Technical writing (reports, escalations)
- [ ] Pattern recognition and critical thinking

---

## Common Mistakes to Avoid

1. **Rushing through alerts:** Speed matters, but accuracy is critical - don't skip evidence gathering
2. **Not documenting:** If you don't write it down, it didn't happen - maintain your triage log diligently
3. **Ignoring context:** A suspicious event might be authorized - always check business context
4. **Analysis paralysis:** Set a time limit (10-15 min for standard alerts) and make a decision
5. **Forgetting to redact:** Never include real sensitive data in portfolio screenshots

---

## Next Steps

After completing this project:

1. **Move to Project 2:** Phishing Email Analysis (deeper dive into email threats)
2. **Optional enhancement:** Redo 10 of your earliest alerts to compare your initial approach vs. your improved skills
3. **Portfolio prep:** Clean up your top 3 case write-ups for GitHub/LinkedIn
4. **Resume update:** Add 2-3 bullets from the templates above
5. **Skill gap analysis:** Identify areas for improvement (e.g., "I struggle with Windows forensics" → prioritize that in next project)

---

**Total Time Investment:** 20-30 hours over 3 weeks  
**Portfolio Artifacts:** 3 case studies, 150-alert triage log, 10+ screenshots  
**Job-Ready Skills:** Alert triage, log analysis, incident documentation

---

**Questions or issues? Review the LetsDefend community forums or refine your approach based on lessons learned.**

**Ready for more? Open `Project-2-Template.md` next!**
