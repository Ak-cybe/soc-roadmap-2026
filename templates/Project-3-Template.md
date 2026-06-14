# Project 3: SOC Analyst Simulation - Incident Response
**Platform:** TryHackMe | **Duration:** 2-3 weeks | **Difficulty:** Intermediate

---

## Project Overview

Experience full-cycle incident investigations in simulated SOC environments using real SIEM (Splunk/ELK) and EDR tools. You'll detect threats, investigate attack chains, contain incidents, and document findings like a Tier-2 SOC analyst.

---

## Learning Objectives

- Navigate and query SIEM platforms (Splunk SPL / Elasticsearch KQL)
- Investigate multi-stage attacks using log correlation
- Use EDR tools for endpoint forensics and threat hunting
- Reconstruct attacker timelines and map to MITRE ATT&CK
- Write formal incident response reports
- Recommend containment and remediation actions

---

## Tools & Technologies

- **Platform:** TryHackMe (subscription recommended for premium rooms)
- **SIEM:** Splunk, Elastic Stack (ELK), Microsoft Sentinel (varies by room)
- **EDR:** Windows Defender ATP, Sysmon, OSQuery (simulated)
- **Log Types:** Windows Event Logs, Sysmon, DNS, proxy, firewall, authentication logs
- **Frameworks:** NIST IR Lifecycle, MITRE ATT&CK, Cyber Kill Chain

---

## Recommended TryHackMe Rooms (Path)

Complete these in order:

### **Phase 1: SIEM Fundamentals (Week 1)**
1. **Splunk 101** (Free) - Learn SPL query language
2. **Splunk: Exploring SPL** (Free) - Advanced searching, filtering, stats
3. **Investigating with Splunk** - First incident investigation

### **Phase 2: Endpoint Detection (Week 2)**
4. **Sysmon** - Understanding Windows advanced logging
5. **Windows Event Logs** - Security events, logon types, process creation
6. **Endpoint Security Monitoring** - EDR concepts

### **Phase 3: Full Incident Investigations (Week 3)**
7. **Incident Handling with Splunk** - Multi-stage attack reconstruction
8. **APT Campaign Simulation** (e.g., "Warzone" or similar advanced room)
9. **Cyber Kill Chain Analysis** - Map incidents to frameworks

**Alternative:** If using Elastic instead of Splunk, substitute with ELK-focused rooms

---

## Step-by-Step Execution Plan

### **Week 1: SIEM Mastery**

#### Day 1-2: Splunk Fundamentals
**Goal:** Learn SPL (Search Processing Language) basics

**Core SPL commands to master:**
```spl
# Basic search
index=main sourcetype=windows_security EventCode=4624

# Filtering and selecting fields
index=main EventCode=4625 | fields _time, user, src_ip, ComputerName

# Statistics and aggregation
index=main EventCode=4625 | stats count by user, src_ip | sort -count

# Timeline visualization
index=main user="admin" | timechart count by EventCode

# Subsearches for correlation
index=main [search index=main EventCode=4720 | fields user] EventCode=4732
```

**Practice Exercises:**
1. Find all failed login attempts (EventCode 4625) in last 24 hours
2. Identify top 5 users with most failed logins
3. Detect brute force: >10 failed logins from same IP in 5 min window

**Documentation:** Create a `spl-cheatsheet.md` with queries you find useful

---

#### Day 3-4: First Investigation - Brute Force Attack
**TryHackMe Room:** "Investigating with Splunk" or similar

**Scenario:** Alerts show suspicious login activity

**Investigation Workflow:**

**Step 1: Alert Review (5 min)**
- Read the scenario: What triggered the alert?
- Note timeframe, affected systems, alert type

**Step 2: Initial Scope (15 min)**
```spl
# Find all authentication events in timeframe
index=main EventCode=4624 OR EventCode=4625 earliest=-24h
| stats count by EventCode, user, src_ip
| sort -count
```

Look for:
- High volume of EventCode 4625 (failed logins)
- Unusual source IPs
- Service accounts being targeted

**Step 3: Deep Dive on Suspicious Activity (30 min)**
```spl
# Focus on top suspicious IP
index=main src_ip="192.168.1.100" EventCode=4625
| stats count by user, _time
| sort _time

# Check if any logins succeeded
index=main src_ip="192.168.1.100" EventCode=4624
```

**Questions to answer:**
- How many failed attempts before success?
- Which account was compromised?
- What time did it happen?
- What was the logon type? (Type 3=network, Type 10=RDP, etc.)

**Step 4: Post-Compromise Activity (30 min)**
```spl
# What did the attacker do after successful login?
index=main user="compromised_user" EventCode=4688 
| table _time, CommandLine, ParentProcess
```

Look for:
- Reconnaissance commands (whoami, net user, ipconfig)
- Lateral movement attempts (PsExec, remote WMI)
- Privilege escalation tools

**Step 5: Timeline Creation (20 min)**
Create a chronological timeline:

```markdown
## Attack Timeline
| Time | Event | Evidence |
|------|-------|----------|
| 14:23:05 | Brute force begins | 150 failed logins from 192.168.1.100 |
| 14:28:42 | Successful login | EventCode 4624, user=jsmith, Type 10 (RDP) |
| 14:29:15 | Reconnaissance | CMD: whoami, net user /domain |
| 14:35:22 | Lateral movement attempt | PsExec.exe to DC01 |
| 14:42:10 | Privilege escalation | Mimikatz execution detected |
```

**Step 6: MITRE ATT&CK Mapping (15 min)**
- **T1110:** Brute Force (Credential Access)
- **T1078:** Valid Accounts (post-compromise)
- **T1087:** Account Discovery (whoami, net user)
- **T1021.001:** Remote Desktop Protocol (lateral movement)
- **T1003:** OS Credential Dumping (Mimikatz)

**Step 7: Report & Containment (30 min)**
- Write incident report (template below)
- Recommend actions:
  - Disable compromised account
  - Block source IP at firewall
  - Force password reset
  - Enable account lockout policy
  - Investigate DC01 for lateral movement success

**Total time:** 3-4 hours

---

#### Day 5-7: Investigation #2 - Malware Execution
**Scenario:** EDR alert for suspicious PowerShell activity

**New skills:** Sysmon logs, process tree analysis, command-line forensics

**Key Sysmon Event IDs:**
- **Event 1:** Process Creation
- **Event 3:** Network Connection
- **Event 7:** Image/DLL Load
- **Event 11:** File Creation
- **Event 13:** Registry Modification

**Investigation approach:**

**Step 1: Identify Patient Zero (15 min)**
```spl
index=sysmon EventCode=1 "powershell" "-encodedcommand"
| table _time, User, ParentImage, CommandLine
```

**Step 2: Decode PowerShell (20 min)**
```bash
# In your notes, decode the Base64 command
echo "BASE64_STRING_HERE" | base64 -d
```

Typical malicious patterns:
- `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- `Invoke-Expression`, `Invoke-WebRequest`
- Obfuscated variable names

**Step 3: Network Activity (20 min)**
```spl
# Find C2 connections from the infected host
index=sysmon EventCode=3 Image="*powershell.exe"
| table _time, DestinationIp, DestinationPort
```

Look for:
- Non-standard ports (not 80/443)
- Connections to suspicious IPs (check threat intel)
- High-frequency beaconing

**Step 4: Persistence Mechanisms (20 min)**
```spl
# Check for registry Run keys
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"

# Check for scheduled tasks
index=windows EventCode=4698
```

**Step 5: Full Process Tree (30 min)**
Map out parent → child relationships:
```
winword.exe (user opens malicious doc)
  └─> powershell.exe -encodedcommand ... (macro execution)
      └─> rundll32.exe malicious.dll (payload download)
          └─> cmd.exe /c schtasks /create ... (persistence)
```

**Deliverable:** Visual process tree diagram (use draw.io or text-based)

---

### **Week 2: Advanced Incident Investigations**

#### Day 8-10: Investigation #3 - Ransomware Attack
**TryHackMe Room:** Search for "Ransomware" or "Incident Response" advanced rooms

**Scenario:** Multiple hosts encrypted, ransom note detected

**Investigation Goals:**
1. Identify initial access vector
2. Map ransomware deployment timeline
3. Determine scope (how many hosts affected)
4. Find patient zero
5. Assess if data was exfiltrated (double extortion)

**Key Queries:**

**Initial Access Detection:**
```spl
# Phishing email delivery
index=email attachment="*.zip" OR attachment="*.js"

# RDP brute force
index=windows EventCode=4625 | stats count by src_ip | where count > 50
```

**Ransomware Execution:**
```spl
# Mass file encryption activity
index=sysmon EventCode=11 TargetFilename="*.encrypted" OR "*.locked"
| stats dc(TargetFilename) as files_encrypted by Image, User

# Ransom note creation
index=sysmon EventCode=11 TargetFilename="*README*" OR "*DECRYPT*"
```

**Lateral Movement:**
```spl
# PsExec, WMI, or SMB activity
index=windows EventCode=5145 ShareName="\\\\*\\C$"
```

**Data Exfiltration (if applicable):**
```spl
# Large outbound transfers
index=proxy bytes_out > 100000000
| stats sum(bytes_out) by src_ip, dest_domain
```

**Critical Timeline Elements:**
1. Initial compromise time
2. Credential dumping / privilege escalation
3. Lateral movement to additional hosts
4. Ransomware deployment time
5. Scope of encryption

**Containment Actions:**
- Isolate affected hosts immediately
- Block C2 domains/IPs at firewall
- Disable compromised accounts
- Restore from backups (verify backups not encrypted)
- DO NOT pay ransom (document why in report)

---

#### Day 11-14: Investigation #4 - APT Campaign
**TryHackMe Room:** "Warzone" or similar advanced persistent threat scenario

**Scenario:** Multi-week compromise with data exfiltration

**New Complexity:**
- Multiple attack phases over days/weeks
- Sophisticated attacker with OpSec
- Use of living-off-the-land binaries (LOLBins)
- Blending in with normal traffic

**Investigation Approach:**

**Phase 1: Build Master Timeline (2 hours)**
Aggregate ALL suspicious activity across timeframe:
- Initial phish
- Malware C2 beaconing
- Credential dumping
- Lateral movement
- Data staging
- Exfiltration

**Phase 2: Attacker Attribution (1 hour)**
- Identify TTPs unique to specific threat actors (compare to APT reports)
- Check infrastructure (domain registration patterns, hosting providers)
- Malware family identification

**Phase 3: Scope Assessment (1 hour)**
```spl
# Find all hosts that connected to attacker C2
index=proxy dest_ip="KNOWN_C2_IP"
| stats values(src_ip) as infected_hosts

# Check each host for:
- Credential dumps
- Sensitive file access
- Data staging locations
```

**Phase 4: Comprehensive Report (2 hours)**
Full incident report with:
- Executive summary
- Technical detail for each phase
- Complete IOC list
- Eradication and recovery plan
- Lessons learned & recommendations

---

### **Week 3: Detection Engineering Introduction**

#### Day 15-17: Threat Hunting Exercise
**Goal:** Proactive threat hunting (not responding to alerts)

**Hypothesis-Driven Hunting:**

**Hypothesis 1:** "Attackers may be using legitimate tools for lateral movement"
```spl
index=sysmon EventCode=1 Image="*psexec.exe" OR Image="*wmic.exe"
| where User!="SYSTEM" AND User!="Administrator"
```

**Hypothesis 2:** "Credential dumping might be occurring"
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1010
| where SourceImage!="*svchost.exe"
```

**Hypothesis 3:** "Data staging before exfiltration"
```spl
index=sysmon EventCode=11 TargetFilename="C:\\Temp\\*.zip"
| stats sum(FileSize) by User | where sum > 500000000
```

**Deliverable:** Hunting report documenting:
- Hypotheses tested
- Queries used
- Findings (benign vs suspicious)
- New detection rules to create

---

#### Day 18-21: Create Custom Detection Rules
**Goal:** Write your own SIEM detection rules

**Example: Detect Credential Dumping**

**Splunk Alert:**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1010
| where SourceImage!="C:\\Windows\\System32\\svchost.exe"
| stats count by SourceImage, User, ComputerName
| where count > 0

Alert trigger: Any result
Severity: Critical
```

**Elastic (KQL) Alert:**
```
event.code: 10 AND process.executable.name: lsass.exe AND 
NOT process.parent.executable: "C:\\Windows\\System32\\svchost.exe"
```

**Create 3-5 custom rules for:**
1. Brute force detection (>10 failures in 5 min)
2. Unusual process execution (Office apps spawning CMD/PowerShell)
3. Lateral movement (PsExec, WMI from non-admin accounts)
4. Data exfiltration (large uploads to external domains)
5. Persistence (registry Run key modifications)

**Test your rules:** Run against lab data, validate true/false positive rate

---

## Evidence to Capture

### For Each Investigation:
- [ ] SIEM query screenshots showing key findings
- [ ] Attack timeline (table or diagram)
- [ ] MITRE ATT&CK mapping
- [ ] Full incident report (see template)
- [ ] IOC list
- [ ] TryHackMe room completion badge/certificate

### Portfolio Artifacts:
- [ ] 3 detailed incident reports (brute force, malware, ransomware/APT)
- [ ] SPL/KQL query cheatsheet
- [ ] Custom detection rules (with rationale)
- [ ] Threat hunting report
- [ ] Process tree diagrams (visual aids)

---

## Incident Report Template

Create: `03-Incident-Response-Sim/incident-[name]-report.md`

```markdown
# Incident Response Report: [Incident Name]

## Incident Metadata
- **Incident ID:** IR-2026-001
- **Date Detected:** 2026-01-XX 14:30 UTC
- **Date Investigated:** 2026-01-XX
- **Analyst:** [Your Name]
- **Severity:** Critical / High / Medium / Low
- **Status:** Contained | Eradicated | Recovered | Closed

---

## Executive Summary
[3-4 sentences for non-technical stakeholders]

Example: "On January 10, 2026, a brute force attack successfully compromised an employee account via RDP. The attacker performed reconnaissance and attempted lateral movement to the domain controller. The incident was contained within 2 hours with no data exfiltration. Estimated impact: Low."

---

## Incident Classification
- **Type:** Compromised Account / Malware Infection / Data Breach / DDoS / etc.
- **Attack Vector:** Brute force, phishing, vulnerability exploitation, etc.
- **Affected Systems:** [List of hosts, users, services]
- **Data Impacted:** None | PII | Financial | Intellectual Property | etc.

---

## Detection
- **Alert Source:** SIEM alert "Excessive Failed Logins"
- **Detection Time:** 2026-01-10 14:30 UTC
- **Initial Indicator:** 150 failed RDP login attempts from 192.168.1.100

---

## Timeline of Events

| Timestamp (UTC) | Phase | Event Description | Evidence |
|-----------------|-------|-------------------|----------|
| 14:23:05 | Initial Access | Brute force attack begins | EventCode 4625 (150 failures) |
| 14:28:42 | Initial Access | Successful RDP login | EventCode 4624, user=jsmith |
| 14:29:15 | Reconnaissance | Attacker executes `whoami` | Sysmon Event 1 |
| 14:30:10 | Reconnaissance | `net user /domain` executed | Sysmon Event 1 |
| 14:35:22 | Lateral Movement | PsExec to DC01 attempted | Security Event 5145 (SMB share access) |
| 14:36:00 | Detection | Analyst alerts fired | SIEM correlation rule |
| 14:42:10 | Privilege Escalation | Mimikatz execution | Sysmon Event 1, suspicious process |
| 15:15:00 | Containment | Account disabled, IP blocked | Incident response action |

---

## Technical Analysis

### Initial Access
**Attack Vector:** RDP brute force  
**Target:** user=jsmith, host=WORKSTATION-05  
**Source IP:** 192.168.1.100 (external IP - confirmed VPN exit node)  

**Evidence:**
```spl
index=windows EventCode=4625 user=jsmith src_ip=192.168.1.100
| stats count
# Result: 147 failed attempts

index=windows EventCode=4624 user=jsmith src_ip=192.168.1.100 Logon_Type=10
# Result: 1 successful RDP login at 14:28:42
```

### Post-Compromise Activity
**Reconnaissance:**
- Executed `whoami` and `net user /domain` to enumerate domain accounts
- Ran `ipconfig` to understand network topology

**Lateral Movement Attempt:**
- Used PsExec to connect to DC01 (domain controller)
- Failed - account `jsmith` did not have admin rights on DC01

**Privilege Escalation:**
- Downloaded and executed Mimikatz
- Attempted to dump credentials from LSASS process
- Unclear if successful before containment

### Network Activity
```spl
index=proxy src_ip=WORKSTATION-05 earliest="14:28:00" latest="15:15:00"
```
No unusual outbound connections detected → data exfiltration unlikely

---

## Scope Assessment
- **Affected Users:** 1 (jsmith)
- **Affected Hosts:** 1 (WORKSTATION-05)
- **Data Accessed:** Unknown (potential email access, no file server activity detected)
- **Privileges Obtained:** Standard user (no domain admin)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Evidence |
|--------|-----------|---------------|----------|
| Initial Access | T1078 | Valid Accounts (brute forced) | EventCode 4624 |
| Credential Access | T1110.001 | Brute Force - Password Guessing | 147 failed logins |
| Discovery | T1087.002 | Account Discovery - Domain Account | `net user /domain` |
| Discovery | T1033 | System Owner/User Discovery | `whoami` command |
| Lateral Movement | T1021.001 | Remote Services - RDP | Logon Type 10 |
| Lateral Movement | T1570 | Lateral Tool Transfer | PsExec copied to DC01 |
| Credential Access | T1003.001 | OS Credential Dumping - LSASS | Mimikatz execution |

---

## Indicators of Compromise (IOCs)

### Network IOCs
- Source IP: 192.168.1.100 (attacker infrastructure - VPN provider XYZ)

### Host IOCs
- **File:** C:\\Users\\jsmith\\Downloads\\mimikatz.exe
  - SHA256: a3e4f2b1c8d7...
  - VirusTotal: 58/70 detections
- **File:** C:\\Users\\jsmith\\AppData\\Local\\Temp\\psexec.exe
  - Legitimate Sysinternals tool (not inherently malicious)

### Account IOCs
- Compromised user: jsmith@company.local

---

## Containment Actions

1. **14:36:00** - Disabled account `jsmith` in Active Directory
2. **14:40:00** - Blocked source IP 192.168.1.100 at perimeter firewall
3. **14:45:00** - Isolated WORKSTATION-05 from network (VLAN quarantine)
4. **15:10:00** - Killed suspicious processes (mimikatz.exe) on WORKSTATION-05
5. **15:15:00** - Verified no lateral movement to DC01 (checked DC logs)

---

## Eradication & Recovery

### Eradication Steps
1. Wiped WORKSTATION-05 and re-imaged with clean OS
2. Scanned all domain controllers for signs of compromise (none found)
3. Forced password reset for all users (precautionary)
4. Removed attacker tools (Mimikatz, PsExec) from forensic image before recovery

### Recovery Steps
1. Restored WORKSTATION-05 from clean backup
2. Enabled MFA for user `jsmith` and all RDP-accessible accounts
3. Implemented account lockout policy (5 failed attempts = 30 min lockout)
4. Returned WORKSTATION-05 to production (verified clean state)

### Verification
- No further malicious activity detected after recovery
- User `jsmith` confirmed normal operations resumed
- Endpoint health checks passed (no indicators of reinfection)

---

## Root Cause Analysis

**Primary Cause:** Weak password policy + RDP exposed to internet

**Contributing Factors:**
- No MFA enabled for RDP access
- No account lockout policy to prevent brute force
- User `jsmith` had weak password ("Winter2025")
- Insufficient network segmentation (workstation could reach DC)

---

## Lessons Learned

**What Went Well:**
- SIEM alert triggered quickly (within 7 minutes of successful login)
- Containment achieved before significant lateral movement
- No data exfiltration occurred
- Clear audit trail in logs for reconstruction

**What Went Wrong:**
- RDP should not have been internet-accessible
- Weak password allowed brute force success
- Mimikatz execution should have been blocked by endpoint protection

**Unanswered Questions:**
- Was any credential dumping successful before containment?
- Why did endpoint protection not quarantine Mimikatz?
- Are there other compromised accounts from the same campaign?

---

## Recommendations

### Immediate (0-7 days)
1. **Disable direct RDP access from internet** - use VPN + MFA instead
2. **Enable MFA** for all remote access accounts
3. **Implement account lockout** policy (5 failures = 30 min lockout)
4. **Update EDR signatures** to detect Mimikatz and credential dumping tools
5. **Conduct user awareness training** on password security

### Short-Term (1-3 months)
1. **Network segmentation:** Workstations should NOT have direct access to domain controllers
2. **Deploy RDP gateway** with MFA and logging
3. **Implement application whitelisting** to prevent unauthorized tool execution
4. **Enhanced logging:** Enable PowerShell script block logging, Sysmon on all endpoints

### Long-Term (3-6 months)
1. **Password policy overhaul:** Minimum 12 characters, complexity, no reuse
2. **Privileged Access Workstations (PAWs)** for admin tasks
3. **Behavioral analytics** (UEBA) to detect anomalous user activity
4. **Regular penetration testing** to identify similar weaknesses

---

## Appendix

### A. SIEM Queries Used
```spl
# Brute force detection
index=windows EventCode=4625 | stats count by user, src_ip | where count > 50

# Post-compromise activity
index=sysmon EventCode=1 user=jsmith | table _time, CommandLine, ParentImage
```

### B. Screenshots
- [Screenshot 1: SIEM alert dashboard]
- [Screenshot 2: Failed login statistics]
- [Screenshot 3: Process execution timeline]

### C. Forensic Evidence Chain of Custody
- WORKSTATION-05 disk image: SHA256 checksum [...]
- Memory dump: Collected at 15:20 UTC, 8GB RAM
- Stored in: Evidence locker #42, secured with physical lock
```

---

## Resume Bullets

### Version 1: Technical Deep Dive
> **SOC Incident Response Simulations - TryHackMe Platform**  
> - Investigated 10+ security incidents including brute force attacks, ransomware, and APT campaigns using Splunk SIEM and Sysmon EDR telemetry, reconstructing attack timelines and identifying patient-zero hosts  
> - Performed log correlation across Windows Event Logs, network traffic, and endpoint behavior to map attacker tactics to MITRE ATT&CK framework (52 techniques identified)  
> - Authored comprehensive incident reports with root cause analysis, containment recommendations, and remediation steps, achieving 100% successful containment in simulated environments

### Version 2: SIEM/EDR Skills Focus
> **SIEM & EDR Investigation Project**  
> - Developed advanced SPL (Splunk) and KQL (Elastic) queries to detect lateral movement, credential dumping, and data exfiltration across 15 simulated network environments  
> - Analyzed Windows process trees, command-line arguments, and parent-child relationships to identify living-off-the-land (LOLBin) attack techniques  
> - Created 8 custom SIEM detection rules for ransomware, brute force, and persistence mechanisms with 90%+ true positive rate in validation testing

### Version 3: Incident Response Lifecycle
> **Full-Cycle Incident Response & Containment**  
> - Managed end-to-end incident response for simulated breaches: detection → investigation → containment → eradication → recovery → lessons learned  
> - Reduced average incident investigation time from 6 hours to 2 hours by developing standardized playbooks and SIEM query templates  
> - Recommended security controls (MFA, network segmentation, EDR tuning) based on post-incident analysis, preventing recurrence in 95% of test scenarios

**Customization Tip:** Match your bullets to job posting keywords (e.g., "Splunk experience" → use Version 2)

---

## Interview Talking Points

### Question: "Describe a complex incident you investigated."

**STAR Answer (Ransomware Example):**

**Situation:**  
"In a TryHackMe advanced incident response room, I was presented with a scenario where multiple file servers were encrypted by ransomware, and ransom notes were left on 15 hosts. The environment had Splunk SIEM with full Windows logs, Sysmon, and network telemetry."

**Task:**  
"My objectives were to: 1) Identify patient zero and initial access vector, 2) Map the full attack timeline, 3) Determine the scope of encryption, 4) Check for data exfiltration, and 5) provide containment and recovery recommendations."

**Action:**  
"I started by searching for the ransom note creation events in Sysmon logs - EventCode 11 for file creation with filenames like 'DECRYPT_ME.txt'. This gave me the encryption timeframe: approximately 3:00 AM. Working backwards, I looked for the ransomware executable using process creation logs (Sysmon Event 1) and found a suspicious process named 'update.exe' running from C:\\Temp.

I traced the parent process tree and discovered it was spawned by PowerShell, which was executed by a malicious macro in a phishing email attachment. I then verified initial access by searching email logs and found the phish was sent to the CFO 2 days prior.

Next, I investigated lateral movement. Using Windows Security logs (EventCode 5145 for SMB share access), I identified that the attacker had moved from the CFO's workstation to a file server using stolen credentials. I confirmed credential dumping by finding Mimikatz LSASS access patterns in the logs.

To check for data exfiltration, I analyzed proxy logs for large outbound transfers and found 2GB uploaded to a cloud storage service 4 hours before encryption - indicating a double-extortion ransomware.

Finally, I created a full timeline mapping 14 different MITRE ATT&CK techniques from initial phishing (T1566) through credential dumping (T1003) to data exfiltration (T1041) and impact (T1486 - encryption)."

**Result:**  
"I documented the full attack in a 12-page incident report, identified 8 compromised hosts, extracted 15 IOCs including malicious domains and file hashes, and recommended: immediate network isolation, credential resets for all administrative accounts, restoration from backups (verified unencrypted), and long-term controls like email sandboxing and endpoint application whitelisting. This investigation took 6 hours and reinforced my understanding of how ransomware operators conduct reconnaissance and the importance of early detection to prevent widespread encryption."

---

### Question: "How do you use MITRE ATT&CK in investigations?"

**Strong Answer:**
"MITRE ATT&CK is my framework for organizing evidence and understanding attacker behavior. During investigations, I use it in three ways:

**1. Hypothesis Generation:**  
When I detect one technique, I ask 'What typically comes next in the kill chain?' For example, if I see credential dumping (T1003), I immediately look for lateral movement techniques like RDP (T1021.001) or PsExec.

**2. Evidence Mapping:**  
As I find artifacts - say, a PowerShell encoded command - I tag it with the relevant technique (T1059.001). This helps me see the full attack picture and identify gaps in my investigation. If I have Initial Access and Impact but no Persistence, I know I need to hunt for registry Run keys or scheduled tasks.

**3. Detection Tuning:**  
After an investigation, I review the ATT&CK techniques and ask 'Could we have detected this earlier?' This drives new detection rule creation. For instance, after seeing T1003 in multiple incidents, I created a Splunk alert for any process accessing LSASS memory with specific permissions.

In my TryHackMe projects, I consistently mapped 10-15 techniques per incident, which not only made my reports more professional but also helped me communicate with other analysts using a common language."

---

## Skills Developed Checklist

By completing this project, you will demonstrate:

**Technical Skills:**
- [ ] Splunk SPL query development
- [ ] Elasticsearch KQL (if using ELK)
- [ ] Windows Event Log analysis
- [ ] Sysmon advanced logging
- [ ] EDR investigation techniques
- [ ] Network log correlation
- [ ] Process tree analysis
- [ ] PowerShell deobfuscation
- [ ] Timeline reconstruction

**Frameworks:**
- [ ] MITRE ATT&CK mapping
- [ ] Cyber Kill Chain
- [ ] NIST IR Lifecycle (Detect → Respond → Recover)

**Soft Skills:**
- [ ] Complex problem-solving
- [ ] Incident report writing
- [ ] Root cause analysis
- [ ] Recommendation development
- [ ] Working under pressure

---

## Common Mistakes to Avoid

1. **Tunnel vision** - Don't fixate on the initial alert; look for related activity
2. **Not documenting queries** - Save every SPL/KQL query you run for reproduc ability
3. **Ignoring "boring" logs** - DNS logs often reveal C2 activity
4. **Skipping verification** - Always verify findings with multiple log sources
5. **Poor time management** - Set investigation time limits to avoid rabbit holes

---

## Next Steps

After completing this project:

1. **Move to Project 4:** Ransomware Kill Chain Investigation (CyberDefenders) for deeper forensics
2. **Optional:** Take TryHackMe "Splunk BOTS" (Boss of the SOC) challenges for real-world datasets
3. **Portfolio:** Publish 1 incident report on LinkedIn/GitHub (sanitized/anonymized)
4. **Resume:** Add 2-3 bullets emphasizing SIEM/EDR skills
5. **Skill gap:** If you struggled with network analysis, consider dedicated packet analysis project

---

**Total Time Investment:** 30-40 hours over 3 weeks  
**Portfolio Artifacts:** 3-4 incident reports, custom detection rules, SPL/KQL cheatsheet  
**Job-Ready Skills:** SIEM investigation, EDR forensics, incident response, MITRE ATT&CK

---

**Continue building expertise? Open `Project-4-Template.md` for advanced forensics!**
