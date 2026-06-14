# Project 13: Purple Team Exercise — APT Campaign Simulation
**Platform:** Any.Run + MITRE ATT&CK Navigator + Atomic Red Team + Splunk/Wazuh | **Duration:** 2 weeks | **Difficulty:** Advanced

---

## Project Overview

Select a **real APT campaign** (Lazarus Group or Scattered Spider), reproduce the full attack chain in an isolated lab — from initial access through lateral movement to data exfiltration — then build **detections for EVERY step** using Sigma rules and SIEM. Document the complete kill chain with ATT&CK mapping and a detection coverage matrix proving zero detection gaps.

**This project proves you can:**
- Analyze real-world APT campaigns and reproduce their TTPs
- Execute adversary emulation across the full kill chain
- Build detection rules that cover 100% of attack stages
- Create ATT&CK Navigator coverage heatmaps
- Think strategically about detection gaps and defensive architecture
- Operate as both red and blue team — the purple team CISO mindset

**The Impact:** Achieve 100% detection coverage for a real APT campaign with <5 minute MTTD per attack stage.

---

## Learning Objectives

- Research and decompose real APT campaigns into discrete TTPs
- Execute adversary emulation using Atomic Red Team tests
- Map every attack step to MITRE ATT&CK techniques with evidence
- Build Sigma detection rules for each attack stage
- Create detection coverage matrices quantifying defensive posture
- Use ATT&CK Navigator to visualize coverage and gaps
- Develop comprehensive purple team documentation

---

## Tools & Technologies

| Tool | Role | Function |
|------|------|----------|
| **MITRE ATT&CK Navigator** | Coverage visualization | Heatmap of detection coverage per technique |
| **Atomic Red Team** | Attack emulation | Pre-built tests for ATT&CK techniques |
| **Any.Run** | Malware sandbox | Analyze real APT malware samples safely |
| **Splunk Free / Wazuh** | SIEM | Detection rule deployment and alerting |
| **Sysmon** | Endpoint telemetry | Process, network, file, registry monitoring |
| **Sigma** | Detection rules | Portable detection format |
| **Caldera (optional)** | Automated emulation | MITRE's adversary emulation platform |

### APT Campaign Options

| APT Group | Campaign | Key TTPs | Difficulty |
|-----------|----------|----------|------------|
| **Scattered Spider** | MGM/Caesars 2023 | Social engineering, SIM swap, Entra ID abuse, ransomware | Advanced |
| **Lazarus Group** | 3CX Supply Chain 2023 | Supply chain, DLL side-loading, C2, crypto theft | Advanced |
| **APT29 (Cozy Bear)** | SolarWinds 2020 | Supply chain, Golden SAML, cloud abuse | Expert |
| **BlackCat/ALPHV** | Healthcare 2024 | Initial access broker, RaaS, data extortion | Advanced |

**This template uses Scattered Spider as the primary example.**

---

## Step-by-Step Execution Plan

### **Week 1: Campaign Research & Attack Emulation**

#### Day 1-2: APT Campaign Decomposition

**Step 1: Research Scattered Spider TTPs**

```markdown
## Scattered Spider (UNC3944) — Campaign Analysis

### Group Profile
- **Also known as:** UNC3944, 0ktapus, Starfraud
- **Targets:** Hospitality, gaming, telecom, tech companies
- **Motivation:** Financial gain (ransomware + data extortion)
- **Notable attacks:** MGM Resorts, Caesars Entertainment (2023)

### Kill Chain Decomposition

#### Phase 1: Initial Access (T1566 + T1078)
- **Technique:** Social engineering via help desk calls
- **Method:** Call IT help desk impersonating employee
- **Goal:** Reset MFA, gain initial credentials
- **Emulation:** Simulated phishing + credential harvesting

#### Phase 2: Persistence (T1136 + T1098)
- **Technique:** Create new accounts, modify existing accounts
- **Method:** Create federated identity provider in Entra ID
- **Goal:** Maintain access even if initial creds are reset
- **Emulation:** Create local admin account + scheduled task

#### Phase 3: Privilege Escalation (T1078.004 + T1484)
- **Technique:** Abuse cloud identity (Entra ID / Okta)
- **Method:** Escalate to Global Admin via PIM or policy modification
- **Goal:** Full administrative control of cloud environment
- **Emulation:** Simulate Entra ID privilege escalation

#### Phase 4: Discovery (T1087 + T1082 + T1083)
- **Technique:** Account enumeration, system info, file discovery
- **Method:** PowerShell scripts, ADFind, built-in commands
- **Goal:** Map environment for lateral movement targets
- **Emulation:** Run Atomic Red Team discovery tests

#### Phase 5: Lateral Movement (T1021 + T1550)
- **Technique:** RDP, SMB, Pass-the-Hash
- **Method:** Use compromised credentials to access servers
- **Goal:** Reach high-value targets (DC, file servers, databases)
- **Emulation:** PsExec, RDP with stolen creds

#### Phase 6: Collection & Exfiltration (T1560 + T1567)
- **Technique:** Archive data, exfil to cloud storage
- **Method:** 7zip compression, upload to Mega.nz / attacker-controlled cloud
- **Goal:** Steal sensitive data for extortion
- **Emulation:** Compress and upload test data

#### Phase 7: Impact (T1486)
- **Technique:** Ransomware deployment (BlackCat/ALPHV)
- **Method:** Deploy via GPO or PsExec to all endpoints
- **Goal:** Encrypt systems + double extortion
- **Emulation:** Simulated encryption (safe test files only)
```

**Step 2: Create ATT&CK Navigator Layer**

```json
{
    "name": "Scattered Spider - Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Purple Team Exercise - Detection Coverage Matrix",
    "techniques": [
        {"techniqueID": "T1566", "color": "#ff0000", "comment": "Phase 1: Social Engineering"},
        {"techniqueID": "T1078", "color": "#ff0000", "comment": "Phase 1: Valid Accounts"},
        {"techniqueID": "T1136", "color": "#ff6600", "comment": "Phase 2: Create Account"},
        {"techniqueID": "T1098", "color": "#ff6600", "comment": "Phase 2: Account Manipulation"},
        {"techniqueID": "T1078.004", "color": "#ffcc00", "comment": "Phase 3: Cloud Accounts"},
        {"techniqueID": "T1087", "color": "#00cc00", "comment": "Phase 4: Account Discovery"},
        {"techniqueID": "T1082", "color": "#00cc00", "comment": "Phase 4: System Info Discovery"},
        {"techniqueID": "T1021", "color": "#0066ff", "comment": "Phase 5: Remote Services"},
        {"techniqueID": "T1550", "color": "#0066ff", "comment": "Phase 5: Use Alt Auth Material"},
        {"techniqueID": "T1560", "color": "#9900cc", "comment": "Phase 6: Archive Collected Data"},
        {"techniqueID": "T1567", "color": "#9900cc", "comment": "Phase 6: Exfil Over Web Service"},
        {"techniqueID": "T1486", "color": "#cc0000", "comment": "Phase 7: Data Encrypted for Impact"}
    ]
}
```

---

#### Day 3-5: Red Side — Attack Emulation

**Step 1: Install Atomic Red Team**

```powershell
# On Windows lab machine (WS01)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

**Step 2: Execute Kill Chain — Phase by Phase**

```powershell
# ===== PHASE 1: INITIAL ACCESS =====

# T1566.001 - Spearphishing Attachment (simulated)
Invoke-AtomicTest T1566.001 -TestNumbers 1

# T1078 - Valid Accounts (simulated credential use)
Invoke-AtomicTest T1078 -TestNumbers 1

# ===== PHASE 2: PERSISTENCE =====

# T1136.001 - Create Local Account
Invoke-AtomicTest T1136.001 -TestNumbers 1
# Creates: net user /add art-test Password123!

# T1053.005 - Scheduled Task for Persistence
Invoke-AtomicTest T1053.005 -TestNumbers 1

# T1547.001 - Registry Run Key Persistence
Invoke-AtomicTest T1547.001 -TestNumbers 1

# ===== PHASE 3: PRIVILEGE ESCALATION =====

# T1548.002 - UAC Bypass
Invoke-AtomicTest T1548.002 -TestNumbers 1

# ===== PHASE 4: DISCOVERY =====

# T1087.001 - Local Account Discovery
Invoke-AtomicTest T1087.001 -TestNumbers 1

# T1082 - System Information Discovery
Invoke-AtomicTest T1082 -TestNumbers 1

# T1083 - File and Directory Discovery
Invoke-AtomicTest T1083 -TestNumbers 1

# T1016 - System Network Configuration Discovery
Invoke-AtomicTest T1016 -TestNumbers 1

# ===== PHASE 5: LATERAL MOVEMENT =====

# T1021.002 - SMB/Windows Admin Shares
Invoke-AtomicTest T1021.002 -TestNumbers 1

# T1570 - Lateral Tool Transfer
Invoke-AtomicTest T1570 -TestNumbers 1

# ===== PHASE 6: COLLECTION & EXFILTRATION =====

# T1560.001 - Archive via Utility (7zip/zip)
Invoke-AtomicTest T1560.001 -TestNumbers 1

# T1567.002 - Exfiltration to Cloud Storage
Invoke-AtomicTest T1567.002 -TestNumbers 1

# ===== PHASE 7: IMPACT =====

# T1486 - Data Encrypted for Impact (SAFE simulation only)
Invoke-AtomicTest T1486 -TestNumbers 1
```

**Step 3: Document Each Attack Step**

```markdown
## Attack Execution Log

### Phase 1: Initial Access
| Step | Technique | Command | Evidence | Timestamp |
|------|-----------|---------|----------|-----------|
| 1.1 | T1566.001 | Invoke-AtomicTest T1566.001 | Macro-enabled doc opened | 2026-01-15 09:00 |
| 1.2 | T1078 | runas /user:victim cmd | New session established | 2026-01-15 09:15 |

### Phase 2: Persistence
| Step | Technique | Command | Evidence | Timestamp |
|------|-----------|---------|----------|-----------|
| 2.1 | T1136.001 | net user /add art-test | New user visible in lusrmgr | 2026-01-15 09:30 |
| 2.2 | T1053.005 | schtasks /create | Task visible in Task Scheduler | 2026-01-15 09:45 |

[... continue for all 7 phases ...]
```

---

### **Week 2: Blue Side — Detection Engineering & Documentation**

#### Day 6-9: Build Detections for Every Attack Step

**Detection Rule for Each Phase:**

```yaml
# === PHASE 1: INITIAL ACCESS ===
# sigma_rules/purple_initial_access.yml
title: "Purple Team - Suspicious Office Macro Execution"
id: purple-01-macro
status: experimental
description: Detects Office application spawning suspicious child processes
tags:
  - attack.initial_access
  - attack.t1566.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: selection
level: high
```

```yaml
# === PHASE 2: PERSISTENCE ===
# sigma_rules/purple_persistence.yml
title: "Purple Team - Local Account Creation"
id: purple-02-account-creation
status: experimental
description: Detects creation of new local user accounts
tags:
  - attack.persistence
  - attack.t1136.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720  # User account was created
  condition: selection
level: high
```

```yaml
# === PHASE 4: DISCOVERY ===
# sigma_rules/purple_discovery.yml
title: "Purple Team - Reconnaissance Command Burst"
id: purple-04-recon
status: experimental
description: Detects rapid execution of multiple discovery commands
tags:
  - attack.discovery
  - attack.t1087.001
  - attack.t1082
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\net.exe'
      - '\whoami.exe'
      - '\systeminfo.exe'
      - '\ipconfig.exe'
      - '\nltest.exe'
      - '\dsquery.exe'
  timeframe: 5m
  condition: selection | count() > 5
level: medium
```

```yaml
# === PHASE 6: EXFILTRATION ===
# sigma_rules/purple_exfiltration.yml
title: "Purple Team - Data Archiving Before Exfiltration"
id: purple-06-archive
status: experimental
description: Detects compression utilities creating archives (pre-exfil staging)
tags:
  - attack.collection
  - attack.t1560.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\7z.exe'
      - '\7za.exe'
      - '\rar.exe'
      - '\WinRAR.exe'
    CommandLine|contains:
      - ' a '
      - ' -r '
  condition: selection
level: medium
```

```yaml
# === PHASE 7: IMPACT ===
# sigma_rules/purple_ransomware.yml
title: "Purple Team - Mass File Encryption (Ransomware Indicator)"
id: purple-07-ransomware
status: experimental
description: Detects high volume of file modifications typical of ransomware
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 11  # FileCreate
    TargetFilename|endswith:
      - '.encrypted'
      - '.locked'
      - '.crypt'
      - '.blackcat'
  timeframe: 1m
  condition: selection | count() > 50
level: critical
```

#### Day 10-11: Detection Coverage Matrix

**Complete Coverage Matrix:**

| Phase | MITRE Technique | Technique Name | Sigma Rule ID | Data Source | Detection Rate | MTTD | Status |
|-------|----------------|---------------|---------------|-------------|---------------|------|--------|
| 1 | T1566.001 | Spearphishing Attachment | purple-01-macro | Sysmon EID 1 | 100% | 1 min | ✅ |
| 1 | T1078 | Valid Accounts | purple-01-validaccts | Security 4624 | 90% | 3 min | ✅ |
| 2 | T1136.001 | Create Local Account | purple-02-account | Security 4720 | 100% | 1 min | ✅ |
| 2 | T1053.005 | Scheduled Task | purple-02-schtask | Security 4698 | 100% | 1 min | ✅ |
| 2 | T1547.001 | Registry Run Keys | purple-02-regrun | Sysmon EID 13 | 95% | 2 min | ✅ |
| 3 | T1548.002 | UAC Bypass | purple-03-uac | Sysmon EID 1 | 85% | 3 min | ✅ |
| 4 | T1087.001 | Account Discovery | purple-04-recon | Sysmon EID 1 | 100% | 2 min | ✅ |
| 4 | T1082 | System Info Discovery | purple-04-recon | Sysmon EID 1 | 100% | 2 min | ✅ |
| 5 | T1021.002 | SMB Admin Shares | purple-05-smb | Security 4624 | 90% | 3 min | ✅ |
| 6 | T1560.001 | Archive via Utility | purple-06-archive | Sysmon EID 1 | 100% | 1 min | ✅ |
| 6 | T1567.002 | Exfil to Cloud | purple-06-exfil | Proxy logs | 85% | 5 min | ✅ |
| 7 | T1486 | Data Encrypted | purple-07-ransomware | Sysmon EID 11 | 95% | 1 min | ✅ |

**Overall Detection Coverage: 12/12 techniques = 100%**
**Average MTTD: 2.1 minutes**

---

#### Day 12-14: Final Documentation & ATT&CK Heatmap

**Update ATT&CK Navigator Layer with Detection Status:**

| Color | Meaning |
|-------|---------|
| 🟢 Green | Detected — Sigma rule deployed and validated |
| 🟡 Yellow | Partially detected — needs tuning |
| 🔴 Red | Not detected — gap requiring new rule |

---

## Evidence to Capture

- [ ] APT campaign research document (complete kill chain decomposition)
- [ ] Atomic Red Team execution logs for all 12+ techniques
- [ ] 10+ Sigma detection rules (one per attack phase minimum)
- [ ] SIEM alert screenshots showing detection of each attack step
- [ ] ATT&CK Navigator heatmap (JSON + screenshot)
- [ ] Detection coverage matrix with MTTD metrics
- [ ] Attack execution timeline (chronological evidence)
- [ ] Purple team after-action report

---

## Resume Bullets

### Version 1: Purple Team Leadership (CISO-Path)
> **Purple Team APT Campaign Simulation & Detection Validation**  
> - Led purple team exercise emulating Scattered Spider APT campaign across 7 attack phases and 12 MITRE ATT&CK techniques, validating defensive controls from initial access through ransomware deployment in isolated enterprise lab environment  
> - Achieved 100% detection coverage for all emulated attack stages with average 2.1-minute mean time to detect, engineering 10+ Sigma rules that closed critical detection gaps in identity abuse, lateral movement, and data exfiltration phases  
> - Delivered ATT&CK Navigator coverage heatmap and detection matrix to leadership, enabling data-driven security investment decisions and reducing organizational detection gap from 40% to 0% for targeted APT TTPs

### Version 2: Adversary Emulation Expertise (CISO-Path)
> **Adversary Emulation & Detection Engineering Program**  
> - Decomposed real-world APT campaign (Scattered Spider/UNC3944) into 12 discrete MITRE ATT&CK techniques and reproduced full kill chain using Atomic Red Team framework, creating repeatable adversary emulation capability for quarterly security validation  
> - Built comprehensive Sigma detection rule library covering initial access (T1566), persistence (T1136, T1053), discovery (T1087), lateral movement (T1021), exfiltration (T1567), and impact (T1486) with validated detection rates of 85-100% per technique  
> - Established purple team methodology adopted as organizational standard for continuous detection validation, directly influencing $150K detection engineering investment and SOC team capability development roadmap

### Version 3: Strategic Security Validation (CISO-Path)
> **Enterprise Detection Coverage Assessment & Gap Analysis**  
> - Designed and executed purple team program that quantified organizational detection posture against real APT TTPs, providing CISO with actionable coverage metrics that informed board-level cybersecurity risk reporting and insurance negotiations  
> - Demonstrated that 100% detection coverage is achievable through systematic purple teaming, reducing mean time to detect from unknown baseline to <5 minutes for critical attack techniques and establishing measurable detection SLAs  
> - Created reusable purple team playbook framework enabling bi-monthly APT emulation exercises, continuously validating $500K+ security tool investment and ensuring ROI through demonstrated detection efficacy

---

## Interview Talking Points

### Question: "What is purple teaming and how does it differ from red/blue teaming?"

**STAR Answer:**

**Situation:**  
"Traditional red and blue team exercises operate in silos — red team attacks, writes a report, blue team reads it months later. This creates a gap where findings aren't immediately operationalized."

**Task:**  
"I conducted a purple team exercise where I played both roles simultaneously — executing each attack step and immediately building the detection for it."

**Action:**  
"I selected the Scattered Spider campaign because it's highly relevant — they compromised MGM Resorts using social engineering and identity abuse, which are the most common attack vectors in 2026.

I decomposed their campaign into 7 phases and 12 ATT&CK techniques. For each technique, I executed the attack using Atomic Red Team, observed the telemetry in my SIEM, then wrote a Sigma detection rule specifically targeting the indicators I saw.

For example, for their persistence technique of creating local accounts, I ran `net user /add`, observed Windows Event ID 4720 firing, and wrote a Sigma rule that triggers on any 4720 event from a non-administrative context. I then re-ran the attack to confirm the detection worked.

I repeated this for all 12 techniques and documented everything in a detection coverage matrix."

**Result:**  
"I achieved 100% detection coverage with an average 2.1-minute detection time. The ATT&CK Navigator heatmap gave clear visibility into our detection posture. The key insight: purple teaming is the fastest way to close detection gaps because you're building detections with the attack fresh in front of you."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] APT campaign research and TTP decomposition
- [ ] Atomic Red Team adversary emulation
- [ ] MITRE ATT&CK Navigator operation
- [ ] Sigma detection rule authoring (attack-specific)
- [ ] Kill chain reconstruction and timeline analysis
- [ ] Detection coverage quantification
- [ ] SIEM correlation rule development

**Frameworks:**
- [ ] MITRE ATT&CK (comprehensive technique mapping)
- [ ] Cyber Kill Chain (Lockheed Martin)
- [ ] Purple Team methodology
- [ ] Detection maturity model

**Soft Skills:**
- [ ] Adversary mindset (think like the attacker)
- [ ] Detection engineering prioritization
- [ ] Executive reporting (coverage heatmaps)
- [ ] Cross-functional collaboration (red + blue)

---

## Common Mistakes to Avoid

1. **Skipping research:** Understand the REAL APT TTPs before emulating
2. **Running on production:** ALWAYS use isolated lab network
3. **Not cleaning up:** Remove Atomic Red Team artifacts after each test
4. **Testing only easy techniques:** Include the hard-to-detect techniques too
5. **Ignoring false positives:** Validate each rule against normal activity baseline
6. **No coverage matrix:** Without metrics, you can't prove value to leadership

---

**Total Time Investment:** 30-40 hours over 2 weeks  
**Portfolio Artifacts:** Campaign analysis, 10+ Sigma rules, ATT&CK heatmap, coverage matrix  
**Job Market Value:** Purple team experience is the #1 differentiator for senior security roles — proves you understand both sides

---

**This project is the ultimate proof of security maturity — you attack like red, defend like blue, and report like a CISO.** 🟣⚔️🛡️
