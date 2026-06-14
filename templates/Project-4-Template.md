# Project 4: Ransomware Kill Chain Investigation
**Platform:** CyberDefenders | **Duration:** 2 weeks | **Difficulty:** Intermediate-Advanced

---

## Project Overview

Conduct deep-dive forensic investigation of a ransomware incident using realistic datasets. Analyze Windows event logs, memory dumps, network captures, and filesystem artifacts to reconstruct the complete attack chain from initial compromise to encryption.

---

## Learning Objectives

- Perform digital forensics on Windows systems
- Analyze memory dumps for malware artifacts
- Extract evidence from PCAP (packet capture) files
- Reconstruct complex multi-day attack timelines
- Understand ransomware Tactics, Techniques, and Procedures (TTPs)
- Develop comprehensive forensic reports

---

## Tools & Technologies

- **Platform:** CyberDefenders (free challenges)
- **Recommended Labs:**
  - "RedLine" (ransomware investigation)
  - "DumpMe" (memory forensics)
  - Any ransomware-themed blue team challenge
  
- **Analysis Tools (you'll need these):**
  - **Log Analysis:** Event Log Explorer, Windows Event Viewer
  - **Memory Forensics:** Volatility Framework
  - **Network Analysis:** Wireshark, NetworkMiner
  - **File Analysis:** PEStudio, FLOSS (string extraction)
  - **Timeline Tools:** Plaso/log2timeline (optional)

---

## Prerequisites

### Tool Setup (Day 0)

Install forensic tools on your analysis VM (or use SIFT Workstation - free forensics Linux distro):

```bash
# Install Volatility 3 (memory forensics)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt

# Install Wireshark (GUI) or tshark (CLI)
# Windows: Download from wireshark.org
# Linux: sudo apt install wireshark

# Download SIFT Workstation (optional - has all tools pre-installed)
# https://digital-forensics.sans.org/community/downloads
```

---

## Step-by-Step Execution Plan

### **Week 1: Forensic Fundamentals & Initial Investigation**

#### Day 1-2: Lab Setup & Evidence Acquisition
**CyberDefenders Lab:** Download challenge files (typically includes):
- `memory.dmp` - RAM capture from infected host
- `disk.E01` or similar - filesystem image
- `network.pcap` - packet capture
- `eventlogs.evtx` - Windows event logs

**Evidence Handling Protocol:**
1. **Verify file integrity:**
   ```bash
   # Check MD5/SHA256 hashes match provided values
   sha256sum memory.dmp
  ```

2. **Create working copies:**
   - NEVER analyze original evidence
   - Work on copies to maintain forensic integrity

3. **Document evidence chain:**
   ```markdown
   ## Evidence Log
   - File: memory.dmp
   - Source: CyberDefenders "RedLine" challenge
   - Acquired: 2026-01-15 10:00 UTC
   - Hash (SHA256): abc123def456...
   - Custodian: [Your Name]
   ```

---

#### Day 3-5: Memory Forensics - Finding the Ransomware

**Objective:** Extract IOCs and malware behavior from memory dump

**Step 1: Determine OS Profile (5 min)**
```bash
python3 vol.py -f memory.dmp windows.info
```
Note the OS version (Windows 10 Build 19041, etc.)

**Step 2: List Running Processes (15 min)**
```bash
python3 vol.py -f memory.dmp windows.pslist
```

Look for suspicious processes:
- Unusual names (random characters: `aBcD123.exe`)
- Running from Temp folders
- Unsigned executables
- Processes without parent (orphaned)

Example suspicious finding:
```
PID   Process Name          Parent PID   User
1234  update.exe            5678         VICTIM\user
      Path: C:\Users\user\AppData\Local\Temp\update.exe
```

**Step 3: Network Connections (15 min)**
```bash
python3 vol.py -f memory.dmp windows.netscan
```

Identify C2 (Command & Control) connections:
- Connections to unusual IPs/ports
- ESTABLISHED connections to non-standard ports (not 80/443)
- High-frequency connections (beaconing)

**Step 4: Command-Line Arguments (20 min)**
```bash
python3 vol.py -f memory.dmp windows.cmdline
```

Look for:
- PowerShell with `-encodedcommand` (obfuscated scripts)
- `vssadmin delete shadows` (deleting backup copies - ransomware behavior)
- `bcdedit /set {default} recoveryenabled No` (disabling recovery mode)
- File deletion/encryption commands

**Step 5: Extract Malicious Executable (30 min)**
```bash
# Dump the suspicious process to disk
python3 vol.py -f memory.dmp windows.dumpfiles --pid 1234
```

Analyze the extracted file:
- Calculate file hash (SHA256)
- Check VirusTotal for malware family identification
- Use strings/FLOSS to extract readable text (C2 domains, ransom message)

**Deliverable:** Memory forensics report with:
- Suspicious processes identified
- Network IOCs (C2 IPs/domains)
- Command-line evidence of malicious behavior
- Extracted malware sample hash

---

#### Day 6-7: Windows Event Log Analysis

**Objective:** Build timeline of ransomware deployment

**Key Event IDs for Ransomware:**
- **4624/4625:** Successful/failed logins (initial access)
- **4688:** Process creation (Sysmon Event 1 if available)
- **4698:** Scheduled task created (persistence)
- **4719:** System audit policy changed (covering tracks)
- **7045:** Service installed (malware as a service)

**Step 1: Identify Initial Compromise (30 min)**

Look for suspicious logins:
```
# Open Event Viewer or use PowerShell
Get-WinEvent -Path Security.evtx | Where-Object {$_.Id -eq 4624} | 
  Select TimeCreated, @{N='User';E={$_.Properties[5].Value}}, 
  @{N='Source IP';E={$_.Properties[18].Value}}
```

Indicators:
- Logon Type 10 (RDP) from unusual IP
- Logon Type 3 (network) at odd hours
- Service accounts logging in interactively

**Step 2: Map Post-Compromise Activity (1 hour)**

Process execution audit:
```
Event ID 4688 -> Filter for:
- powershell.exe, cmd.exe, wmic.exe
- vssadmin.exe (shadow copy deletion)
- net.exe (reconnaissance)
```

**Step 3: Find Persistence (30 min)**
```
Event ID 4698 (Scheduled Task)
Event ID 7045 (Service Installation)
```

Example finding:
```
Scheduled Task Created: "Windows Update Service"
Task Action: C:\Temp\update.exe /encrypt
Time: 2026-01-10 02:00:00
```

**Step 4: Identify Encryption Activity (30 min)**

Look for massive file creation/modification events:
- Event ID 4663 (file access auditing if enabled)
- Sysmon Event 11 (file creation) - mass .encrypted file creation

**Deliverable:** Event log timeline spreadsheet

---

### **Week 2: Network Analysis & Full Timeline Reconstruction**

#### Day 8-10: PCAP Analysis - Finding C2 and Exfiltration

**Objective:** Analyze network traffic for attacker infrastructure

**Step 1: Initial PCAP Overview (10 min)**
```bash
# Open in Wireshark
wireshark network.pcap

# Or use tshark for CLI
tshark -r network.pcap -q -z endpoints,ip
```

Identify:
- Top talkers (IPs with most traffic)
- Unusual protocols (non-HTTP/HTTPS)
- Non-standard ports

**Step 2: Find C2 Communication (30 min)**

Filter for suspicious patterns:
```
# In Wireshark filter bar
# Look for C2 beaconing (repetitive connections)
http.request.method == "POST" && ip.dst == SUSPICIOUS_IP

# Check for DNS tunneling
dns && dns.qry.name.len > 50

# TLS/SSL to unusual CAs
ssl.handshake.server_name
```

**Step 3: Detect Data Exfiltration (30 min)**

Look for large outbound transfers:
```
# Conversations with high byte count
Statistics -> Conversations -> Sort by Bytes

# HTTP file uploads
http.content_type == "application/octet-stream"
```

**Step 4: Extract Artifacts (30 min)**

Use Wireshark to export objects:
```
File -> Export Objects -> HTTP
```

Look for:
- Downloaded payloads (malware stage 2)
- Uploaded data (stolen files)
- C2 commands in HTTP body

**Step 5: GeoIP and Threat Intelligence (20 min)**

- Note all external IPs contacted
- Check IPs against:
  - AbuseIPDB
  - VirusTotal
  - Threat intelligence feeds
- Map IP geolocations (often Eastern Europe / Russia for ransomware)

**Deliverable:** Network IOC list with C2 infrastructure details

---

#### Day 11-12: Filesystem Artifacts & File Recovery

**Objective:** Analyze filesystem for ransomware artifacts

**Key Artifacts to Find:**

1. **Ransom Note:**
   - Typically in: Desktop, Documents, root of drives
   - Filenames: `README.txt`, `DECRYPT_FILES.txt`, `HELP_RECOVER_FILES.html`
   - Extract payment wallet addresses (Bitcoin), contact emails

2. **Dropped Files:**
   - Malware executables in Temp folders
   - Encrypted file extensions (`.locked`, `.encrypted`, `.crypted`)
   - Check file creation timestamps

3. **Prefetch Files (Windows):**
   ```
   Location: C:\Windows\Prefetch\
   Shows: Recently executed programs with run count and timestamp
   ```

4. **Browser History:**
   - Check if victim visited attacker's payment portal
   - Download history for malicious attachments

**Tools:**
```bash
# Autopsy (GUI forensics tool)
# Load disk image and analyze

# FTK Imager (mount disk image)
# Browse filesystem like normal drive
```

**Deliverable:** Artifact inventory with timestamps

---

#### Day 13-14: Complete Timeline & Final Report

**Objective:** Synthesize all findings into master timeline

**Timeline Construction:**

Create a spreadsheet/table combining ALL sources:

| Timestamp | Source | Event | Evidence | ATT&CK Technique |
|-----------|--------|-------|----------|------------------|
| 2026-01-08 09:15 | Email Logs | Phishing email delivered | attachment: invoice.zip | T1566.001 Spearphishing |
| 2026-01-08 09:47 | Event 4663 | User opened attachment | rundll32.exe executed | T1204.002 User Execution |
| 2026-01-08 09:48 | Memory | Malware process started | update.exe (PID 1234) | T1204.002 |
| 2026-01-08 09:50 | PCAP | C2 connection established | http://evil[.]com | T1071.001 Web Protocols |
| 2026-01-08 10:15 | Event 4688 | Credential dumping | Mimikatz executed | T1003 Credential Dumping |
| 2026-01-09 02:00 | Event 4698 | Scheduled task created | Persistence established | T1053 Scheduled Task |
| 2026-01-10 03:00 | Event 4688 | Shadow copies deleted | vssadmin delete shadows | T1490 Inhibit Recovery |
| 2026-01-10 03:05 | Memory | Ransomware deployed | Files encrypted | T1486 Data Encrypted |

**MITRE ATT&CK Kill Chain:**
1. **Initial Access:** T1566.001 (Phishing)
2. **Execution:** T1204.002 (User opens malicious file)
3. **Persistence:** T1053 (Scheduled Task)
4. **Privilege Escalation:** T1068 (Vuln exploitation) or T1078 (stolen creds)
5. **Credential Access:** T1003 (Mimikatz)
6. **Discovery:** T1083 (File/Directory Discovery)
7. **Lateral Movement:** T1021 (RDP/SMB)
8. **Command & Control:** T1071.001 (HTTP C2)
9. **Impact:** T1490 (Inhibit Recovery), T1486 (Encryption)

**Final Report Sections:**
1. Executive Summary
2. Incident Timeline
3. Attack Vector Analysis
4. Technical Deep Dive (Memory, Logs, Network)
5. IOC List (comprehensive)
6. Affected Systems & Data
7. Containment & Recovery Recommendations
8. Lessons Learned

---

## Full Forensic Report Template

Create: `04-Ransomware-Investigation/forensic-report.md`

```markdown
# Ransomware Forensic Investigation Report

## Investigation Metadata
- **Case ID:** CYBER-DEFEND-001
- **Incident Date:** 2026-01-10 03:00 UTC
- **Analysis Date:** 2026-01-15
- **Analyst:** [Your Name]
- **Evidence Sources:** Memory dump, Event logs, PCAP, Disk image
- **Ransomware Family:** Conti / LockBit / [Identified family]

---

## Executive Summary
[2-3 paragraphs for C-level executives]

On January 10, 2026, the organization experienced a ransomware attack that encrypted 15 file servers and 50 user workstations. Forensic analysis revealed the attack began with a phishing email on January 8, giving the attacker 2 days of network access before deploying ransomware. The attacker exfiltrated approximately 100 GB of sensitive data before encryption (double-extortion tactic).

The attack utilized the [Ransomware Family] malware, delivered via a macro-enabled Excel document. The attacker gained administrative credentials through credential dumping, enabled lateral movement across the network, and deployed ransomware via scheduled tasks. Total estimated downtime: 72 hours. Financial impact: $X in lost productivity + $Y potential ransom (not paid).

This report provides a complete forensic timeline, technical analysis of attacker tradecraft, and recommendations to prevent recurrence.

---

## Incident Classification
- **Incident Type:** Ransomware Attack (Double Extortion)
- **Ransomware Family:** [e.g., Conti, LockBit, Ryuk]
- **Affected Systems:** 15 file servers, 50 workstations, 1 domain controller (accessed but not encrypted)
- **Data Exfiltrated:** ~100 GB (finance, HR, customer data)
- **Ransom Demand:** 50 Bitcoin (~$2.5M USD)
- **Payment Status:** NOT PAID

---

## Evidence Summary

### Digital Evidence Collected
| Evidence ID | Type | Source | Hash (SHA256) | Acquired |
|-------------|------|--------|---------------|----------|
| EVIDENCE-001 | Memory Dump | File Server FS01 | abc123... | 2026-01-10 14:00 |
| EVIDENCE-002 | Event Logs | Domain Controller DC01 | def456... | 2026-01-10 14:15 |
| EVIDENCE-003 | Network PCAP | Firewall capture | ghi789... | 2026-01-10 12:00 |
| EVIDENCE-004 | Disk Image | Workstation WS-05 (patient zero) | jkl012... | 2026-01-10 15:30 |

---

## Attack Timeline (Detailed)

### Phase 1: Initial Access (Day 0 - Jan 8, 09:15)
**Vector:** Spearphishing email with malicious attachment

| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 09:15 | Phishing email delivered | Email logs | Subject: "Urgent Invoice Q4", From: finance@trusted-partner[.]com |
| 09:47 | User clicked attachment | Event ID 4663 (WS-05) | File: Q4_Invoice.xlsm opened by user@company.com |
| 09:48 | Macro enabled, payload dropped | Event ID 4688 (WS-05) | rundll32.exe spawned from EXCEL.exe |
| 09:50 | Stage 1 malware executed | Memory (EVIDENCE-001) | Process: update.exe (PID 1234), Parent: rundll32.exe |

**Malware Analysis:**
- **File:** update.exe
- **SHA256:** a1b2c3d4e5f6...
- **VirusTotal:** 62/70 detections (identified as Conti loader)
- **Functionality:** Establishes C2, downloads stage 2 payload

---

### Phase 2: Command & Control (Day 0 - Jan 8, 09:50)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 09:50 | C2 connection established | PCAP (EVIDENCE-003) | HTTP POST to hxxp://185.220.101[.]45:8080 |
| 10:05 | Stage 2 payload downloaded | PCAP, Memory | Download: ransomware.exe (encrypted blob) |
| 10:10-18:00 | Periodic C2 beaconing | PCAP | Every 10 minutes, HTTP POST with system info |

**C2 Infrastructure:**
- **IP:** 185.220.101.45 (Hosted in Netherlands, bulletproof hosting)
- **Domain:** update-services[.]xyz (registered 5 days before attack)
- **Protocol:** HTTP (plaintext - full commands visible in PCAP)

---

### Phase 3: Credential Access (Day 0 - Jan 8, 10:15)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 10:15 | Mimikatz executed | Event ID 4688, Memory | Dumped LSASS for credentials |
| 10:18 | Domain admin hash obtained | Memory analysis | Credential: COMPANY\da_admin (NTLM hash) |

**Stolen Credentials:**
- **Account:** da_admin (Domain Admin)
- **Method:** Pass-the-hash attack (used hash directly, no need to crack)

---

### Phase 4: Discovery & Lateral Movement (Day 0-1 - Jan 8-9)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 10:30 | Network reconnaissance | Event ID 4688 (WS-05) | Commands: `net view`, `nltest /dclist` |
| 11:00 | Domain controller accessed | Event ID 4624 (DC01) | Logon Type 3 (network), user: da_admin from WS-05 |
| 11:15 | File server enumeration | Event ID 5140/5145 (FS01) | SMB share access to \\FS01\Finance, \HR, \CustomerData |
| Jan 9, 02:00 | Lateral movement to file servers | Event ID 4624 (all FS) | Scheduled tasks deployed to all 15 file servers |

---

### Phase 5: Data Exfiltration (Day 1 - Jan 9)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 03:00-08:00 | Large data upload | PCAP, Firewall logs | 100 GB uploaded to mega[.]nz (cloud storage) |
| | Files targeted | Filesystem analysis | *.pdf, *.xlsx, *.docx from Finance, HR, Customer folders |

**Exfiltration Method:**
- **Service:** Mega[.]nz (encrypted cloud storage - attacker controlled account)
- **Data Volume:** 102.4 GB
- **Compression:** 7-zip archives (password protected)

---

### Phase 6: Defense Evasion (Day 2 - Jan 10, 02:00)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 02:45 | Event log clearing attempted | Event ID 1102 (Security log cleared) | Partial clearing on WS-05 only |
| 03:00 | Shadow copies deleted | Event ID 4688 (all FS) | `vssadmin delete shadows /all /quiet` |
| 03:02 | Windows Defender disabled | Registry analysis | HKLM\SOFTWARE\Policies\Microsoft\Windows Defender |

---

### Phase 7: Impact - Ransomware Deployment (Day 2 - Jan 10, 03:05)
| Time | Event | Evidence Source | Details |
|------|-------|-----------------|---------|
| 03:05 | Ransomware executed | Memory, Event ID 4688 | Process: encrypt.exe on all 15 file servers + 50 workstations |
| 03:05-03:45 | Mass file encryption | Sysmon Event 11 (file creation) | All files renamed: [original].conti |
| 03:45 | Ransom notes dropped | Filesystem | README_TO_DECRYPT.txt on all drives |

**Encryption Details:**
- **Algorithm:** AES-256 + RSA-2048 (per Conti TTP)
- **File Extension:** .conti
- **Files Affected:** ~2.5 million files
- **Ransom Note Content:**
  ```
  Your files are encrypted by Conti.
  To decrypt: Pay 50 BTC to [wallet address]
  Contact: [email on TOR network]
  Leak site: [conti_news[.]onion] (data will be published if not paid within 7 days)
  ```

---

## Technical Deep Dive

### Memory Forensics Findings

**Malicious Processes Identified:**
```
PID   Name            Parent       Command Line
1234  update.exe      rundll32.exe C:\Temp\update.exe /install
5678  mimikatz.exe    update.exe   privilege::debug sekurlsa::logonpasswords
9101  encrypt.exe     svchost.exe  C:\Windows\Temp\encrypt.exe /path:C:\ /skip:system
```

**Network Connections from Memory:**
```
Process         Remote IP          Remote Port  State
update.exe      185.220.101.45     8080         ESTABLISHED
encrypt.exe     185.220.101.45     443          ESTABLISHED
```

**DLL Injection Detected:**
- Malicious DLL injected into `svchost.exe` for stealthier execution
- DLL: `evil.dll` (SHA256: xyz789...)

---

### Event Log Analysis Highlights

**Authentication Anomalies:**
- 150+ failed logins (Event 4625) on Jan 7 (day before compromise) - suggests prior bruteforce attempt that failed
- Successful RDP login (Event 4624, Type 10) on Jan 8 at 09:00 from unknown IP (later found to be unrelated VPN user)

**Scheduled Task Abuse:**
```
Event 4698: Scheduled Task Created
Task Name: "WindowsUpdateCheck"
Task Action: C:\Windows\Temp\encrypt.exe
Trigger: Daily at 03:00
Creator: COMPANY\da_admin (compromised account)
Created on: All 15 file servers simultaneously (automated deployment)
```

---

### Network Traffic Analysis

**C2 Communication Pattern:**
```
Beacon Interval: Every 10 minutes
Request: HTTP POST to /api/update
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) [generic]
Payload: Base64-encoded system information (hostname, IP, user, privileges)
Response: Encrypted commands
```

**Data Exfiltration:**
```
Destination: mega.nz (104.18.XX.XX via Cloudflare)
Protocol: HTTPS (encrypted - only metadata visible)
Sessions: 47 separate uploads over 5 hours
Total Bytes Out: 109,234,567,890 bytes (~102 GB)
```

---

## Indicators of Compromise (IOCs)

### File Hashes
```
SHA256: a1b2c3d4e5f6... (update.exe - Conti loader)
SHA256: f6e5d4c3b2a1... (encrypt.exe - Conti ransomware)
SHA256: abc123def456... (evil.dll - injected DLL)
MD5: 5f4e3d2c1b0a... (Q4_Invoice.xlsm - phishing attachment)
```

### Network IOCs
```
IP: 185.220.101.45 (C2 server - Netherlands)
Domain: update-services[.]xyz (C2 domain)
Domain: conti_news[.]onion (leak site)
URL: hxxp://185.220.101[.]45:8080/api/update
URL: hxxps://mega[.]nz/file/XXXXXXX (exfiltration)
```

### Email IOCs
```
Sender: finance@trusted-partner[.]com (spoofed sender)
Subject: "Urgent Invoice Q4"
Attachment: Q4_Invoice.xlsm
```

### Registry IOCs
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  Value: "WindowsUpdateService" = C:\Temp\update.exe

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
  Value: "DisableAntiSpyware" = 1
```

### Ransom Note Identifiers
```
Bitcoin Wallet: 1A2B3C4D5E6F7G8H9I... (example)
Email Contact: decrypt_help@protonmail.com
TOR Site: conti_news[.]onion
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Evidence |
|--------|-----------|---------------|----------|
| Initial Access | T1566 | T1566.001 Spearphishing Attachment | Q4_Invoice.xlsm |
| Execution | T1204 | T1204.002 Malicious File | User enabled macros |
| Execution | T1059 | T1059.005 Visual Basic | Macro code |
| Persistence | T1053 | T1053.005 Scheduled Task | WindowsUpdateCheck task |
| Privilege Escalation | T1078 | T1078.002 Domain Accounts | da_admin compromised |
| Defense Evasion | T1070 | T1070.001 Clear Windows Event Logs | Event 1102 |
| Defense Evasion | T1562 | T1562.001 Disable/Modify Tools | Defender disabled |
| Credential Access | T1003 | T1003.001 LSASS Memory | Mimikatz |
| Discovery | T1087 | T1087.002 Domain Account Discovery | `net view /domain` |
| Discovery | T1083 | File and Directory Discovery | SMB share enumeration |
| Lateral Movement | T1021 | T1021.002 SMB/Windows Admin Shares | \\C$ access |
| Collection | T1005 | Data from Local System | File enumeration |
| Command and Control | T1071 | T1071.001 Application Layer Protocol (HTTP) | C2 beaconing |
| Exfiltration | T1567 | T1567.002 Exfiltration to Cloud Storage | Mega.nz upload |
| Impact | T1490 | Inhibit System Recovery | Shadow copy deletion |
| Impact | T1486 | Data Encrypted for Impact | Conti ransomware |

---

## Root Cause Analysis

**Primary Vulnerability:** Lack of email attachment filtering allowed macro-enabled documents

**Contributing Factors:**
1. **Email Security:** No sandbox detonation of attachments
2. **User Training:** User enabled macros despite warnings
3. **Endpoint Protection:** Windows Defender signatures outdated
4. **Privilege Management:** Service account had domain admin rights (unnecessary)
5. **Network Segmentation:** File servers accessible from user workstations
6. **Backup Strategy:** Shadow copies stored locally (deleted by attacker)
7. **MFA:** Not enabled for VPN/admin accounts

---

## Containment & Recovery Actions Taken

### Immediate Containment (Day 0 - Jan 10, 06:00)
1. Network isolation of all affected systems
2. Blocked C2 IP/domain at firewall
3. Disabled compromised account (da_admin)
4. Shut down file servers to halt encryption spread

### Short-Term Recovery (Day 1-3)
1. Restored file servers from offline backups (previous week)
2. Reimaged all 50 workstations
3. Forced password reset for all domain accounts
4. Deployed updated antivirus signatures

### Long-Term Remediation (Ongoing)
1. Implemented email attachment sandboxing (Proofpoint)
2. Enabled MFA for all VPN and privileged accounts
3. Network segmentation: isolated file servers to admin VLAN
4. Deployed EDR solution (CrowdStrike) on all endpoints
5. Migrated backups to immutable cloud storage (Azure w/ legal hold)

---

## Recommendations

### Technical Controls (Priority)

**P0 (Critical - Implement within 7 days):**
1. **Email Security:** Deploy attachment sandboxing and block macro-enabled files from external senders
2. **EDR Deployment:** Full endpoint visibility and automated response
3. **MFA Enforcement:** All remote access and privileged accounts
4. **Backup Hardening:** Immutable, off-site backups (3-2-1 rule)

**P1 (High - Implement within 30 days):**
5. **Network Segmentation:** Isolate critical assets (file servers, DC) from user workstations
6. **Least Privilege:** Remove unnecessary admin rights, implement PAM (Privileged Access Management)
7. **Application Whitelisting:** Block execution from Temp folders and user-writable directories
8. **Log Forwarding:** Centralize logs to SIEM with retention > 90 days

**P2 (Medium - Implement within 90 days):**
9. **Security Awareness Training:** Monthly phishing simulations
10. **Threat Hunting Program:** Proactive hunts for IOCs every quarter
11. **Incident Response Retainer:** Contract with forensics firm for rapid response

### Process Improvements
- Update incident response plan with ransomware playbook
- Conduct tabletop exercises quarterly
- Establish backup restoration testing schedule (monthly)

---

## Lessons Learned

**What Worked Well:**
- Offline backups existed and were viable for recovery
- Network logs retained long enough to reconstruct attack
- Quick decision NOT to pay ransom

**What Went Wrong:**
- Detection took 46 hours (attack started Jan 8, detected Jan 10)
- No alerting on credential dumping or lateral movement
- Backups were one week old (lost 7 days of data)

**Open Questions:**
- Was all exfiltrated data recovered? (Unknown - attacker may still possess)
- Were any additional backdoors planted? (Continue monitoring)

---

## Appendix A: Volatility Commands Used

```bash
# Profile identification
python3 vol.py -f memory.dmp windows.info

# Process listing
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.pstree

# Network connections
python3 vol.py -f memory.dmp windows.netscan

# Command-line arguments
python3 vol.py -f memory.dmp windows.cmdline

# DLL analysis
python3 vol.py -f memory.dmp windows.dlllist --pid 1234

# Dump process executable
python3 vol.py -f memory.dmp windows.dumpfiles --pid 1234

# Registry hives
python3 vol.py -f memory.dmp windows.registry.hivelist
```

---

## Appendix B: Wireshark Filters Used

```
# Find C2 traffic
http.request.method == "POST" && ip.dst == 185.220.101.45

# Large uploads (exfiltration)
http.content_length > 10000000

# TLS/SSL connections
ssl.handshake.type == 1

# DNS queries
dns.qry.name contains "update-services"
```

---

## Appendix C: Ransom Note (Full Text)

```
===========================================
     YOUR FILES HAVE BEEN ENCRYPTED
===========================================

Don't worry, you can return all your files!
All your files, documents, photos, databases and other important data 
are encrypted with strongest encryption and unique key.

The only method of recovering files is to purchase a private decryption key.
This key is stored on a secret server on the internet.

** HOW TO DECRYPT FILES? **

1. Visit our TOR website: conti_news[.]onion (use TOR Browser)
2. Enter your ID: XXXXXX-XXXXXX-XXXXXX
3. Pay 50 BTC to the provided wallet
4. After payment, download the decryption tool

** WARNINGS **

- Do NOT rename encrypted files
- Do NOT try to decrypt using third-party software (file damage risk)
- Do NOT contact police/FBI (your data will be leaked publicly on our blog)

** DATA LEAK NOTICE **

We have downloaded 100GB+ of your private data before encryption.
If ransom is not paid within 7 days, ALL data will be published on:
    http://conti_news[.]onion/company_name

This includes:
- Financial records (invoices, bank statements)
- Employee PII (SSNs, addresses, salaries)
- Customer database
- Intellectual property

Payment: 50 BTC (~$2,500,000 USD)
Wallet: 1A2B3C4D5E6F7G8H9I0J...

Contact (if issues): decrypt_help@protonmail.com
```

---

**End of Report**

---
```

---

## Resume Bullets

### Version 1: Forensic Skills Focus
> **Advanced Ransomware Forensic Investigation**  
> - Conducted end-to-end digital forensic analysis of Conti ransomware incident using Volatility (memory forensics), Wireshark (PCAP analysis), and Windows event log correlation to reconstruct 72-hour attack timeline  
> - Extracted 25+ IOCs from memory dumps, network traffic, and disk images, identifying C2 infrastructure, exfiltration channels, and ransomware deployment mechanisms  
> - Mapped attacker TTPs to 18 MITRE ATT&CK techniques spanning phishing (T1566) to data encryption (T1486), providing actionable threat intelligence for detection rule creation

### Version 2: Incident Response Angle
> **Ransomware Kill Chain Investigation & Recovery**  
> - Led forensic investigation of simulated ransomware attack affecting 65 systems, identifying initial access vector (phishing), credential theft, and 100GB data exfiltration in multi-day campaign  
> - Documented complete attack timeline from phishing email delivery through encryption deployment, enabling root cause analysis and remediation strategy development  
> - Recommended 11 security controls (EDR, email sandboxing, MFA, network segmentation) based on forensic findings, preventing recurrence in follow-up testing

### Version 3: Technical Tool Proficiency
> **Multi-Source Forensic Analysis Project**  
> - Performed memory forensics using Volatility 3 to identify malicious processes, injected DLLs, and network connections from ransomware-infected systems  
> - Analyzed 50GB network packet captures (PCAP) in Wireshark to detect C2 beaconing patterns, data exfiltration to cloud storage, and attacker infrastructure  
> - Correlated Windows event logs (Security, Sysmon) with memory/network artifacts to validate findings and eliminate false positives in forensic conclusions

---

## Interview Talking Points

### Question: "Describe a complex forensic investigation you conducted."

**STAR Answer:**

**Situation:**  
"I worked on a CyberDefenders ransomware case involving a simulated Conti ransomware attack that encrypted 15 file servers. I was provided with a memory dump, Windows event logs, network PCAP, and a disk image from the patient-zero workstation."

**Task:**  
"My objectives were to: reconstruct the full attack timeline, identify the initial access vector, determine if data was exfiltrated, extract all IOCs, and provide remediation recommendations."

**Action:**  
"I started with memory forensics using Volatility. I ran `windows.pslist` and identified a suspicious process called `update.exe` running from the Temp folder with no legit parent process. I used `windows.netscan` and found it had an active connection to an external IP on port 8080, which I flagged as potential C2.

I dumped the process executable and ran it through VirusTotal - 62 out of 70 engines flagged it as Conti malware. I then extracted the command-line history and found commands like `vssadmin delete shadows` and Mimikatz execution, which confirmed credential dumping occurred.

Next, I analyzed the event logs. I correlated Event ID 4624 (successful logins) with the timeline from memory and identified that a domain admin account was used for lateral movement to all 15 file servers via SMB (Event ID 5145). I found scheduled tasks (Event ID 4698) were created on all servers to deploy the ransomware executable.

For the network analysis, I opened the PCAP in Wireshark and filtered for the C2 IP. I saw periodic HTTP POST beacons every 10 minutes, and then a massive outbound transfer to Mega.nz - 102GB over 5 hours - indicating data exfiltration before encryption.

Finally, I built a master timeline combining all sources and mapped 18 MITRE ATT&CK techniques from initial phishing (T1566.001) all the way to encryption (T1486)."

**Result:**  
"I produced a 25-page forensic report with complete timeline, 25+ IOCs including file hashes, C2 IPs, and email indicators, and 11 prioritized recommendations including email sandboxing, EDR deployment, and MFA. The investigation took about 20 hours spread over a week and taught me how to correlate multiple data sources to tell a complete story of an attack."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] Memory forensics (Volatility)
- [ ] Network traffic analysis (Wireshark, tshark)
- [ ] Windows event log forensics
- [ ] Filesystem artifact analysis
- [ ] Timeline reconstruction
- [ ] Malware hash identification
- [ ] IOC extraction and documentation
- [ ] Disk imaging and analysis

**Frameworks:**
- [ ] MITRE ATT&CK (advanced mapping)
- [ ] Cyber Kill Chain
- [ ] Digital forensics best practices
- [ ] Evidence chain of custody

---

## Next Steps

1. **Move to Project 5:** Threat Hunting with SIEM (proactive defense)
2. **Optional:** Analyze additional CyberDefenders cases for variety
3. **Portfolio:** Create visual timeline diagram for your best case
4. **Resume:** Add 2 forensics-focused bullets
5. **Skill development:** Consider SANS FOR500 or similar training if interested in forensics career path

---

**Total Time:** 25-35 hours over 2 weeks  
**Artifacts:** Comprehensive forensic report, IOC database, timeline diagram  
**Skills:** Memory forensics, PCAP analysis, timeline reconstruction

---

**Ready for proactive defense? Open `Project-5-Template.md`!**
