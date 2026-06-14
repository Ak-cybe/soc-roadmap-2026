# Project 2: Phishing Email Analysis Lab
**Platform:** CyberDefenders | **Duration:** 1-2 weeks | **Difficulty:** Beginner-Intermediate

---

## Project Overview

Master phishing detection and analysis by investigating realistic phishing campaigns using CyberDefenders' browser-based labs. You'll analyze email headers, URLs, attachments, and artifacts to identify malicious intent, extract IOCs, and write professional investigation reports.

---

## Learning Objectives

- Analyze email headers to detect spoofing and identify email infrastructure
- Safely investigate malicious URLs and attachments using sandboxing techniques
- Extract and document indicators of compromise (IOCs)
- Understand common phishing techniques (credential harvesting, malware delivery, BEC)
- Write structured analysis reports for escalation

---

## Tools & Technologies

- **Platform:** CyberDefenders (free account)
- **Recommended Labs:** "Phishing Analysis" series, "Malicious Email" challenges
- **Analysis Tools (within labs):**
  - Email header analyzers
  - URL decoders and sandboxes (urlscan.io, VirusTotal)
  - File hash checkers
  - Base64 decoders
- **Frameworks:** MITRE ATT&CK, Phishing Kill Chain

---

## Step-by-Step Execution Plan

### **Week 1: Foundation & First 3 Cases**

#### Day 1-2: Setup & Email Header Fundamentals
1. **Create CyberDefenders account** (free)
2. **Tutorial: Email Headers 101**
   - Understand key headers:
     - `From:` vs `Return-Path:` (spoofing detection)
     - `Received:` chain (trace email route)
     - `SPF`, `DKIM`, `DMARC` results (authentication checks)
     - `X-Originating-IP:` (sender infrastructure)
   
3. **Practice exercise:**
   - Use [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) on sample emails
   - Identify sender IP, mail servers, and authentication failures

#### Day 3-5: Case #1 - Basic Credential Phishing
**Lab:** "Phishing Analysis" (CyberDefenders - difficulty: Easy)

**Investigation Steps:**

1. **Initial Review (5 min)**
   - Read the scenario description
   - Note what the "user" reported (e.g., "suspicious Office 365 login request")

2. **Email Header Analysis (15 min)**
   ```
   Questions to answer:
   - Who is the sender (display name vs actual email)?
   - What is the originating IP address?
   - Did the email pass SPF/DKIM/DMARC checks?
   - What is the suspected spoofed domain?
   ```
   
   **Tool:** Copy headers into MXToolbox or similar analyzer
   
   **Documentation template:**
   ```markdown
   ## Header Analysis
   - **Display Name:** Microsoft Security Team
   - **From Address:** security@micr0soft-support.com (note: zero instead of 'o')
   - **Actual Sender IP:** 185.220.101.45
   - **SPF Result:** FAIL (not authorized sender for microsoft.com domain)
   - **DKIM:** None
   - **DMARC:** FAIL
   ```

3. **URL/Link Analysis (15 min)**
   - Extract all URLs from email body
   - **DO NOT CLICK** - copy URL and analyze safely:
     - Use `urlscan.io` or `VirusTotal` to screenshot the landing page
     - Check domain registration (whois) - new domains (<30 days) are suspicious
     - Identify purpose: credential harvesting, malware download, survey scam?
   
   **Example findings:**
   ```markdown
   ## URL Analysis
   - **URL:** hxxps://secure-office365-verify[.]com/login
   - **Defanged for safety:** hxxps (replace http)
   - **Domain Age:** Registered 3 days ago
   - **Hosting IP:** 104.21.XX.XX (Cloudflare - often abused)
   - **Purpose:** Fake Office 365 login page (credential phishing)
   - **Screenshot:** [Captured from urlscan.io] - mimics Microsoft branding
   ```

4. **Attachment Analysis (if applicable, 20 min)**
   - Extract file hash (MD5, SHA256)
   - Check hash on VirusTotal
   - Identify file type (macro-enabled document, executable disguised as PDF?)
   - **NEVER open attachments directly** - use sandbox environments only

5. **Classification & IOC Extraction (10 min)**
   - **Verdict:** Malicious phishing attempt - credential harvesting
   - **Attack Type:** Spearphishing (or generic phishing)
   - **Targeted Data:** User credentials
   
   **IOC List:**
   ```
   Domain: secure-office365-verify[.]com
   IP: 185.220.101.45
   Email: security@micr0soft-support.com
   ```

6. **Write Investigation Report** (30 min)
   - Use the case report template below
   - Answer all CyberDefenders questions to get points

**Total time for Case #1:** 2-3 hours

---

#### Day 6-7: Case #2 - Malware Delivery via Email
**Lab:** Search CyberDefenders for "Malicious Email" or "Malware Analysis" (email-based)

**New skills to practice:**

1. **Attachment Deep Dive:**
   - Analyze macro-enabled documents (.docm, .xlsm)
   - Identify obfuscated scripts in macros
   - Trace downloaded payloads (URLs embedded in macros)

2. **Behavioral Analysis:**
   - If the lab provides dynamic analysis results, review:
     - Network connections made by payload
     - Registry modifications
     - Dropped files and persistence mechanisms

3. **Malware Family Identification:**
   - Use hash lookups (VirusTotal, Hybrid Analysis)
   - Identify known malware families (Emotet, Qakbot, etc.)
   - Map to MITRE ATT&CK techniques

**Updated IOC List:**
```
Email IOCs:
- Sender: invoice@legitimate-company.com (compromised account)
- Attachment: invoice_Q4.docm (SHA256: abc123...)

Malware IOCs:
- File Hash: abc123def456... (Emotet variant)
- C2 Server: 203.0.113.78:8080
- Domain: malware-c2-domain[.]xyz
```

---

### **Week 2: Advanced Cases & Portfolio Finalization**

#### Day 8-10: Case #3 - Business Email Compromise (BEC)
**Lab:** Search for "BEC" or "CEO Fraud" scenarios

**Focus:** More subtle phishing - no obvious malware/URLs, just social engineering

**Investigation approach:**

1. **Sender legitimacy:**
   - Is email truly from the CEO or spoofed?
   - Check for typosquatting (ceo@c0mpany.com vs ceo@company.com)
   - Review email routing - did it originate from company mail server or external?

2. **Context analysis:**
   - Urgency language ("URGENT: Wire transfer needed immediately")
   - Breaks normal business process (bypassing approvals)
   - Unusual request from authority figure

3. **Verify authenticity:**
   - In real SOC: call sender via known phone number
   - In lab: note your recommendation to verify

**Deliverable:** Write up how you identified the fraud without technical IOCs

---

#### Day 11-12: Capstone - Multi-Vector Campaign
**Lab:** Find a complex phishing lab involving multiple emails or stages

**Challenge:** Analyze a campaign (not just one email)

**Steps:**
1. Analyze 3-5 related phishing emails
2. Identify the campaign pattern (same infrastructure, tactics)
3. Build a timeline of attacker activity
4. Create a comprehensive IOC list for blocking
5. Recommend defenses (email filtering rules, user training)

---

#### Day 13-14: Documentation & Portfolio Prep

1. **Select top 3 cases** for portfolio (variety: credential phish, malware delivery, BEC)

2. **Create professional write-ups** using template

3. **Build IOC database:**
   - Compile all IOCs from all cases into CSV
   - Format: `IOC_Type, Value, Context, Malicious_Confidence`
   - Example:
     ```csv
     Domain,phishing-site.com,Credential harvesting page,High
     IP,185.220.101.45,Malware C2 server,High
     Email,attacker@evil.com,Phishing sender,Medium
     File_Hash,abc123...,Emotet dropper,High
     ```

4. **Create visual timeline** for 1 complex case (use draw.io, lucidchart, or simple markdown table)

---

## Evidence to Capture

### For Each Case:
- [ ] Screenshot of email (redacted)
- [ ] Email headers (raw text or analyzed report)
- [ ] URL analysis reports (urlscan.io screenshot)
- [ ] File hash VirusTotal results (if malware present)
- [ ] Your investigation notes and findings
- [ ] CyberDefenders scoreboard showing completed challenge

### Portfolio Artifacts:
- [ ] 3 detailed case write-ups
- [ ] IOC database (CSV file)
- [ ] 1 visual attack timeline/diagram
- [ ] Lessons learned document

---

## Case Report Template

Create a file for each case: `02-Phishing-Analysis/case-[name]-report.md`

```markdown
# Phishing Analysis Report: [Case Name]

## Case Metadata
- **Lab:** CyberDefenders - [Lab Name]
- **Date Analyzed:** 2026-01-XX
- **Analyst:** [Your Name]
- **Difficulty:** Easy/Medium/Hard
- **Time Spent:** X hours

---

## Executive Summary
[2-3 sentences: What happened, what was the threat, what was the outcome]

Example: "Analyzed a credential phishing email impersonating Microsoft Office 365. The attacker used a newly registered domain to host a fake login page. No users submitted credentials. Recommended blocking the malicious domain."

---

## Email Overview
- **Subject Line:** "Urgent: Verify Your Account"
- **Sender (Display):** Microsoft Security Team
- **Sender (Actual):** security@micr0soft-alert.com
- **Recipient:** [redacted]@company.com
- **Date/Time:** 2026-01-08 14:23 UTC
- **Attachments:** None (or list if present)

---

## Header Analysis

### Authentication Results
- **SPF:** ❌ FAIL - Sender IP not authorized for microsoft.com domain
- **DKIM:** ❌ None
- **DMARC:** ❌ FAIL

### Email Routing
```
Received chain (bottom to top - oldest to newest):
1. Originating IP: 185.220.101.45 (Netherlands)
2. Mail server: smtp.attacker-infrastructure.net
3. Recipient mail gateway: mail.company.com
```

### Key Findings
- Email did NOT originate from Microsoft infrastructure
- Originating IP has poor reputation (AbuseIPDB score: 78/100)
- Domain `micr0soft-alert.com` registered 2 days before email sent

---

## Malicious Components

### URLs
| URL | Defanged | Purpose | Domain Age |
|-----|----------|---------|------------|
| https://secure-office365[.]com/verify | hxxps://secure-office365[.]com/verify | Fake login | 3 days |

**URL Analysis Evidence:**
- urlscan.io report: [link to screenshot]
- Mimics Microsoft branding perfectly
- Captures username + password submitted via form

### Attachments (if applicable)
| Filename | File Type | Hash (SHA256) | VT Detection |
|----------|-----------|---------------|--------------|
| invoice.docm | Macro Doc | abc123... | 45/70 engines |

---

## Attack Flow

1. **Initial Access:** Phishing email sent to 50+ employees
2. **Social Engineering:** Urgent language claiming "account will be locked in 24 hours"
3. **User Action:** User clicks link
4. **Credential Harvesting:** Fake login page captures credentials
5. **Post-Compromise (theoretical):** Attacker uses credentials to access email, exfiltrate data

---

## MITRE ATT&CK Mapping
- **T1566.002:** Phishing - Spearphishing Link
- **T1078:** Valid Accounts (credential theft enables this)
- **T1114:** Email Collection (likely attacker goal)

---

## Indicators of Compromise (IOCs)

### Network IOCs
```
Domain: secure-office365[.]com
Domain: micr0soft-alert[.]com
IP: 185.220.101.45
```

### Email IOCs
```
Sender: security@micr0soft-alert.com
Subject: "Urgent: Verify Your Account"
```

### File IOCs (if applicable)
```
SHA256: [hash]
Filename: invoice.docm
```

---

## Recommendations

### Immediate Actions
1. Block malicious domains at email gateway and web proxy
2. Search email logs for all recipients of this email
3. Force password reset for any users who clicked link
4. Monitor affected accounts for suspicious login attempts

### Long-Term Improvements
1. Implement DMARC enforcement (reject policy)
2. Deploy email link rewriting/sandboxing
3. Conduct user awareness training on phishing indicators
4. Enable MFA for all accounts

---

## Lessons Learned
- SPF/DKIM/DMARC failures are strong phishing indicators
- New domain registrations (< 7 days) warrant extra scrutiny
- Urgency + authority impersonation = common phishing pattern
- Always defang IOCs in reports to prevent accidental clicks

---

## Appendix
- [Screenshot 1: Email body]
- [Screenshot 2: Email headers]
- [Screenshot 3: Fake login page]
- [Screenshot 4: urlscan.io analysis]
```

---

## Resume Bullets

### Version 1: Technical Skills Focus
> **Phishing Analysis & Threat Intelligence**  
> - Investigated 15+ phishing campaigns on CyberDefenders platform, analyzing email headers (SPF/DKIM/DMARC), malicious URLs, and macro-enabled attachments to identify credential harvesting and malware delivery attempts  
> - Extracted and documented 50+ IOCs (domains, IPs, file hashes) using VirusTotal, urlscan.io, and WHOIS lookups, creating structured IOC databases for threat intelligence sharing  
> - Authored detailed investigation reports mapping phishing techniques to MITRE ATT&CK framework (T1566.002, T1078), with actionable remediation recommendations

### Version 2: Results-Oriented
> **Email Security Analysis Project**  
> - Detected and analyzed business email compromise (BEC) and credential phishing attacks, identifying 100% of malicious emails in blind test scenarios through header analysis and behavioral indicators  
> - Reduced false positives in email security alerts by documenting common legitimate email patterns vs. phishing techniques in a reference guide for SOC team  
> - Recommended email security controls (DMARC enforcement, link sandboxing) based on lessons learned from 15 investigation case studies

### Version 3: Incident Response Angle
> **Phishing Incident Investigation & Response**  
> - Conducted forensic analysis of phishing emails including header inspection, URL sandboxing, and malware artifact examination to determine attack scope and impact  
> - Developed standardized investigation playbooks for credential phishing, malware delivery, and BEC scenarios, reducing average analysis time by 40%  
> - Created comprehensive IOC lists and containment recommendations (domain blocking, account password resets) for 10+ real-world phishing campaigns

**Pro Tip:** Adjust bullets based on job posting keywords (e.g., if JD mentions "threat intelligence" → use Version 1)

---

## Interview Talking Points

### Question: "Walk me through how you analyze a phishing email."

**Strong STAR Answer:**

**Situation:**  
"In my phishing analysis training on CyberDefenders, I worked on a case where employees reported a suspicious Office 365 password reset email."

**Task:**  
"My job was to determine if it was legitimate or a phishing attempt, and if malicious, extract IOCs and recommend containment actions."

**Action:**  
"I followed a structured approach:

First, I analyzed the email headers. I checked the 'From' address against the 'Return-Path' and found they didn't match - the display name said 'Microsoft' but the actual sender domain was 'micr0soft-security.com' with a zero instead of an 'o', which is a classic typosquatting technique.

Next, I examined the authentication results - SPF failed, no DKIM signature, and DMARC failed. This confirmed the email wasn't sent from Microsoft's infrastructure.

Then I looked at the email body. It had urgent language like 'Your account will be locked in 24 hours' and a blue button saying 'Verify Now.' I carefully extracted the URL without clicking it - it pointed to 'secure-office365-verify.com.'

I checked the domain on WHOIS and found it was registered just 3 days ago, which is a huge red flag. I then used urlscan.io to safely view the landing page - it was a perfect replica of Microsoft's login page, designed for credential harvesting.

Finally, I documented all IOCs - the malicious domain, sender IP address, and email address - and wrote a report mapping it to MITRE ATT&CK technique T1566.002 for spearphishing links."

**Result:**  
"I classified it as a high-confidence malicious phishing attempt and recommended blocking the domain at the email gateway and web proxy, searching email logs for other recipients, and conducting user awareness training. This investigation took about 45 minutes and reinforced the importance of never trusting the display name and always validating authentication headers."

---

### Question: "How do you differentiate between a phishing email and a false positive (legitimate email flagged incorrectly)?"

**Strong Answer:**
"I use a layered approach:

**1. Technical Validation:**
- Check SPF/DKIM/DMARC - legitimate senders usually pass these
- Verify sender domain - is it the real company domain or a lookalike?
- Examine email routing - does it come from expected mail servers?

**2. Content Analysis:**
- Language: Legitimate emails rarely use urgent threats or pressure tactics
- Links: Do URLs match the claimed sender's domain? Hover without clicking.
- Branding: Phishing often has subtle errors in logos, fonts, or layouts

**3. Context:**
- Is the request consistent with business process?
- Was the email expected?
- Does the sender have a legitimate reason to contact this recipient?

**Example from my training:** I once analyzed an email from a 'bank' asking to verify account details. It passed SPF because it came from a compromised legitimate business's mail server - not the bank's server. The domain in the links didn't match the sender's domain. Even though SPF passed, the mismatched domains and unusual request from an unrelated business made it clear phishing.

A false positive, on the other hand, might be a marketing email from a third-party service hired by the company - it might fail SPF if not properly configured, but the links go to the legitimate vendor's domain and the content makes business sense."

---

### Question: "What tools do you use for phishing analysis?"

**Strong Answer:**
"I use a combination of free and platform-based tools:

**Email Header Analysis:**
- MXToolbox Email Header Analyzer
- Message Header Analyzer (Microsoft's tool)
- Manual inspection of SPF/DKIM/DMARC results

**URL Analysis (without clicking):**
- urlscan.io - screenshots and behavioral analysis
- VirusTotal - community detections and historical data
- WHOIS lookups - check domain age and registrar

**Malware/Attachment Analysis:**
- VirusTotal - file hash lookups
- Hybrid Analysis / ANY.RUN - dynamic malware sandboxing (for training labs)
- Hex editors - for initial file inspection

**Threat Intelligence:**
- AbuseIPDB - IP reputation
- PhishTank - known phishing URLs
- MITRE ATT&CK - mapping techniques

**During my CyberDefenders training, I combined these tools to analyze 15 phishing campaigns, which taught me that no single tool gives the full picture - you need to correlate findings across multiple sources."**

---

## Skills Developed Checklist

By completing this project, you will demonstrate:

**Technical Skills:**
- [ ] Email header analysis (SPF, DKIM, DMARC)
- [ ] URL analysis and safe investigation techniques
- [ ] Malware hash identification and sandbox analysis
- [ ] IOC extraction and documentation
- [ ] Threat intelligence platform usage
- [ ] Typosquatting and domain analysis

**Frameworks:**
- [ ] MITRE ATT&CK (Phishing techniques)
- [ ] Phishing Kill Chain
- [ ] Cyber Kill Chain (when malware is involved)

**Soft Skills:**
- [ ] Attention to detail (spotting subtle spoofing)
- [ ] Structured investigation methodology
- [ ] Report writing for technical and non-technical audiences
- [ ] Risk assessment and prioritization

---

## Common Mistakes to Avoid

1. **Clicking links or opening attachments directly** - always use sandboxes or analysis tools
2. **Trusting "From" display names** - check actual sender address
3. **Ignoring authentication failures** - SPF/DKIM/DMARC results are critical
4. **Not defanging IOCs** - always replace 'http' with 'hxxp' and dots with '[.]' in reports
5. **Shallow analysis** - don't just say "it's phishing" - provide evidence and explain how you know

---

## Next Steps

After completing this project:

1. **Move to Project 3:** SOC Analyst Simulation (TryHackMe) for full incident investigations
2. **Optional enhancement:** Create a personal "Phishing Indicators Cheat Sheet" based on patterns you observed
3. **Portfolio prep:** Publish 1-2 anonymized case studies on LinkedIn or Medium
4. **Resume update:** Add 2-3 bullets focusing on skills relevant to target jobs
5. **Skill gap check:** If attachment analysis was difficult, consider malware analysis deep dive next

---

**Total Time Investment:** 15-25 hours over 2 weeks  
**Portfolio Artifacts:** 3 detailed reports, IOC database (CSV), CyberDefenders profile showing completed challenges  
**Job-Ready Skills:** Phishing analysis, email forensics, IOC extraction, threat intelligence

---

**Ready for incident response simulations? Open `Project-3-Template.md` next!**
