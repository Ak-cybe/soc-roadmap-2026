# Project 14: Malware Reverse Engineering for Blue Teamers
**Platform:** FlareVM + Any.Run Free Tier + Wireshark | **Duration:** 2 weeks | **Difficulty:** Advanced

---

## Project Overview

Develop **practical malware analysis skills** focused on blue team outcomes — IOC extraction, YARA rule writing, and malware family identification. Perform static analysis (PEStudio, FLOSS, strings), dynamic analysis (ANY.RUN sandbox, FlareVM behavioral analysis), and network analysis (Wireshark C2 traffic capture) to produce actionable threat intelligence from real malware samples.

**This project proves you can:**
- Analyze malware to extract actionable IOCs for SOC operations
- Write YARA rules that detect malware families across the enterprise
- Identify C2 infrastructure through network traffic analysis
- Translate reverse engineering findings into detection rules
- Bridge the gap between malware analysis and SOC defense

**The Impact:** Extract 50+ IOCs and write 5+ YARA rules from real malware samples, enabling proactive detection of malware families before signature updates arrive.

---

## Learning Objectives

- Perform static malware analysis without executing samples
- Conduct dynamic behavioral analysis in isolated sandboxes
- Analyze C2 network traffic patterns using Wireshark
- Extract IOCs (hashes, IPs, domains, mutexes, registry keys)
- Write effective YARA rules for malware detection
- Identify malware families and their TTPs
- Create actionable intelligence reports from analysis findings

---

## Tools & Technologies

| Tool | Role | Function |
|------|------|----------|
| **FlareVM** | Analysis workstation | Windows-based malware analysis environment |
| **PEStudio** | Static analysis | PE header inspection, suspicious indicators |
| **FLOSS** | String extraction | Deobfuscate and extract strings from binaries |
| **Any.Run** | Online sandbox | Interactive malware detonation and analysis |
| **Wireshark** | Network analysis | Capture and analyze C2 traffic |
| **YARA** | Detection rules | Pattern matching for malware identification |
| **pestudio / pe-bear** | PE analysis | Import table, section analysis, entropy |
| **Process Monitor** | Behavioral | Real-time file/registry/process monitoring |
| **Procmon / API Monitor** | API tracking | Monitor Windows API calls during execution |
| **CyberChef** | Data decoding | Decode obfuscated strings, configs, shellcode |

### Infrastructure Requirements

| Component | Specs | Notes |
|-----------|-------|-------|
| **FlareVM** | 8GB RAM, 4 vCPU, 80GB | Windows 10 VM with analysis tools pre-installed |
| **Isolated Network** | Host-only adapter | NO internet access for dynamic analysis |
| **INetSim** | On host machine | Simulate internet services for malware |
| **REMnux (optional)** | 4GB RAM, 2 vCPU | Linux-based malware analysis toolkit |

### Sample Sources (Safe & Legal)

- **MalwareBazaar** (abuse.ch): https://bazaar.abuse.ch — Free malware samples
- **Any.Run Public Submissions**: https://app.any.run/submissions — Pre-analyzed samples
- **theZoo**: https://github.com/ytisf/theZoo — Curated malware repository (academic)
- **VirusTotal**: Download samples with API key
- **NEVER** use malware from unknown sources or run outside isolated environments

---

## Step-by-Step Execution Plan

### **Week 1: Static & Dynamic Analysis**

#### Day 1-2: FlareVM Setup & Static Analysis Fundamentals

**Step 1: Deploy FlareVM**

```powershell
# On a clean Windows 10 VM (snapshot BEFORE installing!)
# Take VM snapshot: "Clean-Windows-Pre-FlareVM"

# Install FlareVM
Set-ExecutionPolicy Unrestricted -Force
(New-Object net.webclient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    "$env:TEMP\install.ps1"
)
Unblock-File "$env:TEMP\install.ps1"
& "$env:TEMP\install.ps1"

# Installation takes 30-60 minutes
# Installs: PEStudio, FLOSS, x64dbg, Ghidra, YARA, CyberChef, etc.
# Take snapshot after: "FlareVM-Clean-Installed"
```

**Step 2: Download Malware Sample from MalwareBazaar**

```python
# download_sample.py — Run on HOST machine, transfer to FlareVM via shared folder
import requests
import hashlib

# Download a known sample (example: AgentTesla info-stealer)
SAMPLE_SHA256 = "get_hash_from_malwarebazaar"  # Replace with actual hash

response = requests.get(
    f"https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_file", "sha256_hash": SAMPLE_SHA256},
    timeout=30
)

if response.status_code == 200:
    # Save password-protected zip (password: "infected")
    with open(f"sample_{SAMPLE_SHA256[:8]}.zip", "wb") as f:
        f.write(response.content)
    print(f"Downloaded sample: {SAMPLE_SHA256[:16]}...")
else:
    print(f"Failed: {response.status_code}")
```

**Step 3: Static Analysis with PEStudio**

```markdown
## Static Analysis Report — Sample #1

### File Properties
- **Filename:** invoice_2026.exe
- **File Size:** 847,360 bytes
- **MD5:** a1b2c3d4e5f6...
- **SHA256:** 1234567890abcdef...
- **File Type:** PE32 executable (GUI) Intel 80386
- **Compilation Timestamp:** 2026-01-10 04:23:17 UTC
- **Compiler:** Microsoft Visual C++ 2019

### PEStudio Findings
| Indicator | Value | Suspicion |
|-----------|-------|-----------|
| Entropy | 7.2 (high) | Packed/encrypted content |
| Imports | CreateRemoteThread, VirtualAllocEx | Process injection |
| Imports | InternetOpenA, HttpSendRequestA | Network communication |
| Imports | RegSetValueExA | Registry persistence |
| Resources | Contains embedded PE (entropy 6.8) | Dropper behavior |
| Sections | .text entropy 7.8 | Likely packed |
| Strings | "Mozilla/5.0" user-agent | C2 communication |
| Certificate | None (unsigned) | Suspicious for "legitimate" software |

### Suspicious Indicators
- [ ] High entropy sections → likely packed
- [ ] Process injection APIs → may inject into legitimate processes
- [ ] Network APIs → communicates externally
- [ ] Registry APIs → establishes persistence
- [ ] Embedded PE in resources → drops additional payload
```

**Step 4: String Extraction with FLOSS**

```bash
# Run FLOSS (FLARE Obfuscated String Solver)
floss.exe sample.exe > floss_output.txt

# FLOSS extracts:
# 1. Static strings (like 'strings' command)
# 2. Stack strings (constructed at runtime)
# 3. Decoded strings (deobfuscated)
```

```markdown
## FLOSS String Analysis

### Interesting Static Strings
```
http://185.220.101[.]42/gate.php
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
%APPDATA%\svchost.exe
POST /submit.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
cmd.exe /c whoami
```

### Decoded/Stack Strings (Deobfuscated by FLOSS)
```
password
username
credit_card
bitcoin_wallet
keylog.txt
screenshot.png
```

### Extracted IOCs
| Type | Value | Context |
|------|-------|---------|
| URL | http://185.220.101[.]42/gate.php | C2 callback URL |
| IP | 185.220.101[.]42 | C2 server |
| User-Agent | Mozilla/5.0 (Windows NT 10.0...) | C2 beacon UA |
| File Path | %APPDATA%\svchost.exe | Dropped payload location |
| Registry | HKCU\...\Run | Persistence mechanism |
| Mutex | Global\MutexABC123 | Single-instance mutex |
```

---

#### Day 3-5: Dynamic Analysis

**Step 1: Any.Run Online Sandbox Analysis**

1. Go to https://app.any.run
2. Upload sample (or search public submissions for similar malware)
3. **Configure sandbox:**
   - OS: Windows 10 64-bit
   - Network: Simulated (tor/proxy)
   - Duration: 120 seconds
   - Interaction: Click popups, enable macros if prompted

4. **Observe and document:**
   - Process tree (what processes are created)
   - Network connections (DNS, HTTP, HTTPS)
   - File system changes (dropped files)
   - Registry modifications
   - Injected processes

```markdown
## Any.Run Dynamic Analysis Results

### Process Tree
```
invoice_2026.exe (PID: 1234)
├── cmd.exe (PID: 2345) → "whoami"
├── cmd.exe (PID: 2346) → "ipconfig /all"
├── svchost.exe (PID: 3456) → Dropped payload (NOT real svchost)
│   ├── Injected into: explorer.exe (PID: 4567)
│   └── Network: HTTP POST to 185.220.101[.]42
└── cmd.exe (PID: 5678) → "reg add HKCU\...\Run"
```

### Network Activity
| Time | Protocol | Destination | Request | Data |
|------|----------|------------|---------|------|
| 0:05 | DNS | 8.8.8.8 | A record for update-cdn[.]xyz | Resolved to 185.220.101.42 |
| 0:08 | HTTP | 185.220.101.42 | POST /gate.php | Base64-encoded system info |
| 0:15 | HTTP | 185.220.101.42 | POST /submit.php | Stolen credentials |
| 0:30 | HTTP | 185.220.101.42 | GET /commands.php | C2 commands (encoded) |

### File System Changes
| Action | Path | Description |
|--------|------|-------------|
| CREATE | %APPDATA%\svchost.exe | Dropped payload (copy of self) |
| CREATE | %TEMP%\keylog.txt | Keystroke log file |
| MODIFY | %APPDATA%\...\Run\WindowsUpdate | Persistence registry key |

### Behavioral Classification
- **Family:** AgentTesla (info-stealer)
- **Capabilities:** Keylogging, credential theft, screenshot capture
- **C2 Protocol:** HTTP POST with Base64-encoded data
- **Persistence:** Registry Run key
- **Evasion:** Process injection into explorer.exe
```

**Step 2: FlareVM Local Dynamic Analysis**

```markdown
## FlareVM Behavioral Analysis

### Pre-Execution Setup
1. Start Process Monitor (Procmon) — filter on sample.exe
2. Start Wireshark — capture on host-only adapter
3. Start FakeNet-NG — simulate DNS/HTTP responses
4. Take VM snapshot: "Pre-Execution"

### Execution Monitoring
# Run sample and observe for 5 minutes

### Procmon Findings (filtered)
| Operation | Path | Result | Detail |
|-----------|------|--------|--------|
| CreateFile | C:\Users\user\AppData\Roaming\svchost.exe | SUCCESS | Dropped payload |
| RegSetValue | HKCU\...\Run\WindowsUpdate | SUCCESS | Persistence |
| CreateProcess | cmd.exe | SUCCESS | Reconnaissance |
| WriteFile | C:\Users\user\AppData\Local\Temp\keylog.txt | SUCCESS | Keylogger output |
| TCP Connect | 185.220.101.42:80 | SUCCESS | C2 connection |
```

---

#### Day 6-7: Network Analysis with Wireshark

**Step 1: Capture C2 Traffic**

```markdown
## Wireshark C2 Traffic Analysis

### Capture Setup
- Interface: Host-only adapter (FlareVM)
- Filter: `ip.addr == 185.220.101.42`
- Duration: 5 minutes of malware execution
- Packets captured: 847

### C2 Communication Pattern

#### Initial Beacon (HTTP POST)
```
POST /gate.php HTTP/1.1
Host: 185.220.101[.]42
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/x-www-form-urlencoded
Content-Length: 342

data=dXNlcm5hbWU9YWRtaW4maG9zdG5hbWU9V0lOMTAtTEFCJm9zPVdpbmRvd3MgMTA...
```

#### Decoded Beacon (Base64 → plaintext)
```
username=admin&hostname=WIN10-LAB&os=Windows 10&ip=192.168.1.50
&antivirus=Windows Defender&cpu=Intel i7&ram=8GB
```

#### C2 Response (Commands)
```
HTTP/1.1 200 OK
Content-Type: text/plain

cmd=keylog_start|interval=30|upload_interval=300
```

### Wireshark Display Filters Used
```
# All HTTP traffic to C2
http.host contains "185.220.101"

# DNS queries for C2 domain
dns.qry.name contains "update-cdn"

# POST requests (data exfiltration)
http.request.method == "POST" && ip.dst == 185.220.101.42

# TLS traffic to C2 (if HTTPS)
tls.handshake.extensions_server_name contains "update-cdn"
```

### Network IOCs Extracted
| Type | Value | Confidence |
|------|-------|------------|
| IP | 185.220.101[.]42 | HIGH — direct C2 |
| Domain | update-cdn[.]xyz | HIGH — C2 domain |
| URL | /gate.php | HIGH — beacon endpoint |
| URL | /submit.php | HIGH — data exfil endpoint |
| User-Agent | Mozilla/5.0 (specific string) | MEDIUM — may match legit |
| JA3 Hash | abc123def456... | HIGH — TLS fingerprint |
```

---

### **Week 2: YARA Rules, IOC Reports & Portfolio**

#### Day 8-10: YARA Rule Writing

**Step 1: Write YARA Rules for Detected Malware**

```yara
// yara_rules/agenttesla_variant.yar

rule AgentTesla_InfoStealer_2026 {
    meta:
        author = "SOC Lab Analyst"
        date = "2026-01-20"
        description = "Detects AgentTesla info-stealer variant"
        reference = "MalwareBazaar sample SHA256: 1234567890abcdef..."
        mitre_attack = "T1056.001, T1555, T1041"
        confidence = "HIGH"
        family = "AgentTesla"
        
    strings:
        // C2 communication strings
        $c2_gate = "/gate.php" ascii wide
        $c2_submit = "/submit.php" ascii wide
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
        
        // Keylogger indicators
        $keylog1 = "keylog.txt" ascii wide
        $keylog2 = "GetAsyncKeyState" ascii
        $keylog3 = "SetWindowsHookEx" ascii
        
        // Credential theft
        $cred1 = "\\Credentials\\" ascii wide
        $cred2 = "\\Login Data" ascii wide  // Chrome
        $cred3 = "logins.json" ascii wide   // Firefox
        
        // Persistence
        $persist = "CurrentVersion\\Run" ascii wide
        
        // Anti-analysis
        $anti1 = "SbieDll.dll" ascii  // Sandboxie check
        $anti2 = "vmtoolsd.exe" ascii // VMware check
        
        // Mutex
        $mutex = "Global\\Mutex" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 2MB and
        (
            ($c2_gate and $c2_submit) or
            (2 of ($keylog*) and 1 of ($cred*)) or
            (3 of ($keylog*, $cred*, $persist, $mutex))
        )
}

rule Suspicious_InfoStealer_Generic {
    meta:
        author = "SOC Lab Analyst"
        date = "2026-01-20"
        description = "Generic detection for info-stealer behavior patterns"
        confidence = "MEDIUM"
        
    strings:
        $s1 = "password" ascii wide nocase
        $s2 = "credential" ascii wide nocase
        $s3 = "wallet" ascii wide nocase
        $s4 = "cookie" ascii wide nocase
        $s5 = "screenshot" ascii wide nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "VirtualAllocEx" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of ($s*) and
        2 of ($api*)
}
```

**Step 2: Test YARA Rules**

```bash
# Test against the sample
yara64.exe -s agenttesla_variant.yar sample.exe

# Expected output:
# AgentTesla_InfoStealer_2026 sample.exe
# 0x1a3f:$c2_gate: /gate.php
# 0x1a52:$c2_submit: /submit.php
# ...

# Test against clean files (false positive check)
yara64.exe -r agenttesla_variant.yar C:\Windows\System32\
# Should return: NO matches (0 false positives)

# Test against MalwareBazaar samples (detection rate)
yara64.exe -r agenttesla_variant.yar ./malware_samples/
# Target: detect related variants
```

**Step 3: Validate YARA Rule Quality**

| Metric | Target | Result |
|--------|--------|--------|
| True Positive Rate | >90% | Test against 10 AgentTesla variants |
| False Positive Rate | 0% | Test against System32, Program Files |
| Detection Specificity | Family-level | Detects AgentTesla specifically |
| Performance | <1 second per file | Acceptable for endpoint scanning |

---

#### Day 11-12: Complete IOC Report

```markdown
# Malware Analysis Report — AgentTesla Info-Stealer

## Executive Summary
Analyzed AgentTesla info-stealer variant targeting Windows endpoints.
Malware steals credentials from 20+ applications, captures keystrokes
and screenshots, and exfiltrates data via HTTP POST to attacker C2 server.
5 YARA rules and 50+ IOCs extracted for defensive deployment.

## Sample Information
| Field | Value |
|-------|-------|
| MD5 | a1b2c3d4e5f6g7h8i9j0... |
| SHA256 | 1234567890abcdef... |
| File Size | 847,360 bytes |
| File Type | PE32 executable |
| Family | AgentTesla |
| First Seen | 2026-01-10 |

## Kill Chain Analysis
| Phase | Technique | Evidence |
|-------|-----------|----------|
| Delivery | T1566.001 Phishing | Email attachment "invoice_2026.exe" |
| Execution | T1204.002 User Execution | User double-clicks executable |
| Persistence | T1547.001 Registry Run | HKCU\...\Run\WindowsUpdate |
| Evasion | T1055.001 Process Injection | Injects into explorer.exe |
| Collection | T1056.001 Keylogging | GetAsyncKeyState API |
| Collection | T1555 Credentials from Stores | Chrome, Firefox, Outlook |
| Exfiltration | T1041 Exfil Over C2 | HTTP POST to gate.php |

## Indicators of Compromise

### Network IOCs
| Type | Value | Context |
|------|-------|---------|
| IP | 185.220.101[.]42 | C2 server |
| Domain | update-cdn[.]xyz | C2 domain |
| URL | /gate.php | Beacon endpoint |
| URL | /submit.php | Data exfiltration |
| JA3 | abc123def456... | TLS fingerprint |

### Host IOCs
| Type | Value | Context |
|------|-------|---------|
| File | %APPDATA%\svchost.exe | Dropped payload |
| File | %TEMP%\keylog.txt | Keystroke log |
| Registry | HKCU\...\Run\WindowsUpdate | Persistence |
| Mutex | Global\MutexABC123 | Instance mutex |
| Hash (SHA256) | 1234567890abcdef... | Malware binary |

## YARA Rules
See: `yara_rules/agenttesla_variant.yar` (2 rules attached)

## Recommended Defensive Actions
1. Block C2 IP 185.220.101[.]42 at firewall
2. Block domain update-cdn[.]xyz at DNS/proxy
3. Deploy YARA rules to EDR endpoints
4. Create SIEM alert for HTTP POST to /gate.php pattern
5. Monitor for svchost.exe in %APPDATA% (abnormal location)
6. Hunt for Registry Run key "WindowsUpdate" pointing to AppData
```

---

#### Day 13-14: Portfolio Finalization

**Compile analysis artifacts:**
- 3 complete malware analysis reports (different families)
- 5+ YARA rules with validation results
- Wireshark PCAP analysis documentation
- IOC extraction spreadsheet (50+ IOCs)
- MITRE ATT&CK mapping for each sample

---

## Evidence to Capture

- [ ] 3 malware analysis reports (static + dynamic + network)
- [ ] PEStudio analysis screenshots
- [ ] FLOSS string extraction output
- [ ] Any.Run sandbox analysis screenshots (process tree, network)
- [ ] Wireshark C2 traffic capture and analysis
- [ ] 5+ YARA rules with validation results
- [ ] IOC extraction report (50+ indicators)
- [ ] MITRE ATT&CK mapping for each malware sample
- [ ] CyberChef decoding screenshots (Base64, XOR, etc.)

---

## Resume Bullets

### Version 1: Threat Intelligence & Detection (CISO-Path)
> **Malware Reverse Engineering & Threat Intelligence Production**  
> - Analyzed 10+ malware samples across info-stealer, RAT, and ransomware families using static (PEStudio, FLOSS) and dynamic (Any.Run, FlareVM) techniques, extracting 50+ actionable IOCs that were deployed to SIEM and EDR within 2 hours of analysis  
> - Authored 5+ YARA detection rules achieving 95% true positive rate with 0% false positives, enabling proactive malware family detection before vendor signature updates — reducing detection gap from 48 hours to 0  
> - Established malware analysis capability producing machine-readable threat intelligence (STIX IOCs, YARA rules, Sigma alerts) that integrated directly into automated TIP pipeline, eliminating manual IOC deployment bottleneck

### Version 2: Network Forensics Focus (CISO-Path)
> **Malware Network Analysis & C2 Infrastructure Mapping**  
> - Conducted Wireshark-based C2 traffic analysis identifying beacon patterns, data exfiltration protocols, and TLS fingerprints (JA3 hashes) across 5 malware families, creating network-layer detection signatures deployed to IDS/IPS infrastructure  
> - Reverse-engineered malware communication protocols including HTTP POST beaconing, DNS tunneling, and encrypted C2 channels, providing SOC team with behavioral indicators that detected C2 traffic independent of IOC blocklists  
> - Built malware analysis playbook adopted by 5-person SOC team, reducing average malware triage time from 4 hours to 45 minutes and enabling junior analysts to perform basic sample analysis independently

### Version 3: Strategic Security Impact (CISO-Path)
> **Organizational Malware Analysis Capability Development**  
> - Built in-house malware analysis capability reducing dependency on vendor threat intelligence by 60%, enabling same-day IOC extraction and detection rule deployment for zero-day malware campaigns targeting the organization  
> - Demonstrated CISO-level understanding of threat landscape by translating malware analysis findings into executive risk briefings, correlating malware families to threat actor campaigns and quantifying organizational exposure  
> - Created YARA rule library and IOC database integrated with MISP threat intelligence platform, establishing continuous feedback loop between malware analysis, detection engineering, and incident response teams

---

## Interview Talking Points

### Question: "How do you analyze a suspicious file?"

**STAR Answer:**

**Situation:**  
"Our SOC received an alert for a suspicious executable that bypassed email filters. No vendor had flagged it — we needed to determine if it was malicious and extract IOCs for blocking."

**Task:**  
"I needed to analyze the file safely, determine its capabilities, extract IOCs, and create detections — all within a 2-hour SLA."

**Action:**  
"I followed a three-phase approach:

**Static analysis first** — I never execute unknown files immediately. Using PEStudio, I checked the PE headers, imports, and entropy. High entropy sections indicated packing, and imports like CreateRemoteThread and InternetOpenA suggested process injection and C2 communication. FLOSS extracted obfuscated strings including a URL pattern and registry persistence path.

**Dynamic analysis second** — I detonated the sample in Any.Run sandbox and simultaneously in my FlareVM with Process Monitor running. I observed it drop a copy to AppData, create a registry Run key for persistence, inject into explorer.exe, and beacon to an IP over HTTP POST every 30 seconds.

**Network analysis third** — Using Wireshark, I captured the C2 traffic. The beacon was HTTP POST to /gate.php with Base64-encoded system info. I decoded the payload in CyberChef and confirmed it was sending hostname, username, and OS version.

I then wrote a YARA rule targeting the unique string combinations and C2 URL patterns, tested it against clean files for false positives (zero), and deployed the IOCs to our SIEM and firewall."

**Result:**  
"Within 90 minutes, I identified the malware as an AgentTesla variant, extracted 15 IOCs (IPs, domains, file paths, registry keys, hashes), wrote 2 YARA rules, and deployed blocking rules. The YARA rule later caught 3 more variants in the following week that no vendor had signatures for."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] PE file format analysis
- [ ] Static analysis (PEStudio, FLOSS, strings)
- [ ] Dynamic analysis (sandbox, behavioral monitoring)
- [ ] Network traffic analysis (Wireshark, C2 decoding)
- [ ] YARA rule authoring and validation
- [ ] IOC extraction and classification
- [ ] Malware family identification
- [ ] CyberChef data decoding (Base64, XOR, RC4)
- [ ] Process injection detection
- [ ] Anti-analysis technique identification

**Frameworks:**
- [ ] Malware analysis methodology (static → dynamic → network)
- [ ] MITRE ATT&CK (malware-specific techniques)
- [ ] Diamond Model of Intrusion Analysis
- [ ] Kill Chain mapping for malware behavior

**Soft Skills:**
- [ ] Technical report writing (malware analysis reports)
- [ ] IOC quality assessment (confidence scoring)
- [ ] Time-boxed analysis (SLA-driven triage)
- [ ] Cross-team communication (analysis → SOC → IR)

---

## Common Mistakes to Avoid

1. **Running malware on host machine:** ALWAYS use isolated VM with host-only networking
2. **Skipping static analysis:** Don't jump to execution — static analysis is safer and faster
3. **Ignoring network analysis:** C2 traffic provides the most actionable network IOCs
4. **Writing too-broad YARA rules:** Broad rules = false positives — test against clean files
5. **Not taking VM snapshots:** Snapshot before EVERY execution — revert for clean state
6. **Forgetting to defang IOCs:** Always defang in reports: `185.220.101[.]42` not `185.220.101.42`

---

**Total Time Investment:** 30-40 hours over 2 weeks  
**Portfolio Artifacts:** 3 analysis reports, 5+ YARA rules, Wireshark analysis, 50+ IOCs  
**Job Market Value:** Malware analysis is a rare skill — <10% of SOC analysts can write YARA rules

---

**This project completes your offensive-to-defensive skill set. You can now analyze the weapon, extract the fingerprints, and build the alarm — all before the attacker strikes again.** 🔬🦠🛡️
