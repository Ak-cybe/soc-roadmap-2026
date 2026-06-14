# Project 7: Automated Phishing Responder (SOAR Integration)
**Platform:** Wazuh + Shuffle + TheHive (Open-Source Stack) | **Duration:** 2-3 weeks | **Difficulty:** Advanced

---

## Project Overview

Transform from reactive alert monitoring to **proactive autonomous response** by building an end-to-end Security Orchestration, Automation, and Response (SOAR) pipeline. This project demonstrates the 2026 SOC capability: **humans design workflows, AI/automation executes them at machine speed**.

You'll integrate three powerful open-source tools to create a phishing response system that:
- **Detects** suspicious activity via endpoint telemetry (Wazuh)
- **Enriches** IOCs automatically using threat intelligence APIs (VirusTotal)
- **Manages** incident cases with structured workflows (TheHive)
- **Responds** autonomously with human-approved containment (Shuffle SOAR)

**This is your transition from "SOC analyst" to "Automation Architect."**

---

## Learning Objectives

- Master SOAR orchestration principles and playbook design
- Integrate multiple security tools via APIs and webhooks
- Build human-in-the-loop approval gates for autonomous actions
- Implement automated enrichment workflows (IOC reputation checks)
- Design secure, scalable incident response automation
- Understand the shift from manual execution to supervisory oversight

---

## Tools & Technologies

### Core Stack (All Free & Open-Source)

| Tool | Role | Function |
|------|------|----------|
| **Wazuh** | SIEM + EDR | Log collection, detection rules, agent management |
| **Shuffle** | SOAR Platform | Workflow orchestration, API integration, automation engine |
| **TheHive** | Case Management | Incident tracking, collaborative investigation, evidence storage |
| **VirusTotal API** | Threat Intelligence | IOC reputation (file hashes, IPs, URLs, domains) |

### Infrastructure Requirements

- **Wazuh Manager:** Ubuntu 22.04 VM (4 GB RAM, 2 vCPU, 50 GB disk)
- **Wazuh Agent:** Windows 10/11 VM (2 GB RAM, 1 vCPU)
- **Shuffle:** Cloud-hosted (free tier: shuffle.io) OR self-hosted Docker
- **TheHive:** Ubuntu VM (4 GB RAM, 2 vCPU) OR TheHive Cloud
- **Total:** 3-4 VMs (VirtualBox/VMware/Proxmox) OR cloud instances

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTOMATED PHISHING RESPONSE                   │
└─────────────────────────────────────────────────────────────────┘

   ┌──────────────┐
   │  Windows VM  │
   │ (Wazuh Agent)│──────① Suspicious Activity Detected
   └──────────────┘         (e.g., Mimikatz execution,
          │                  malicious URL access)
          │
          ▼
   ┌──────────────┐
   │Wazuh Manager │──────② Alert Generated (rule match)
   │   (SIEM)     │
   └──────────────┘
          │
          │ Webhook (HTTP POST)
          ▼
   ┌──────────────┐
   │   Shuffle    │──────③ Workflow Triggered
   │    (SOAR)    │         ↓
   └──────────────┘         ├─ Extract IOCs from alert
          │                 ├─ Query VirusTotal API
          │                 ├─ Create case in TheHive
          │                 ├─ Email analyst (approval request)
          ▼                 └─ Wait for YES/NO response
   ┌──────────────┐
   │ VirusTotal   │──────④ IOC Enrichment
   │     API      │         Returns reputation scores,
   └──────────────┘         malware families, detections
          │
          ▼
   ┌──────────────┐
   │   TheHive    │──────⑤ Case Created
   │ (CSIRT Tool) │         Incident #IR-2026-001
   └──────────────┘         - Observables (IPs, hashes)
          │                 - Severity, tags, timeline
          ▼
   ┌──────────────┐
   │   Analyst    │──────⑥ Human Review & Approval
   │   (Email)    │         "Isolate host? YES / NO"
   └──────────────┘
          │
          │ (YES clicked)
          ▼
   ┌──────────────┐
   │   Shuffle    │──────⑦ Execute Response Action
   │  Workflow    │         API call to Wazuh Manager
   └──────────────┘
          │
          ▼
   ┌──────────────┐
   │Wazuh Manager │──────⑧ Command Sent to Agent
   └──────────────┘         "active-response: host-deny"
          │
          ▼
   ┌──────────────┐
   │  Windows VM  │──────⑨ Containment Executed
   │  (Isolated)  │         • Firewall blocks all traffic
   └──────────────┘         • Process killed (if applicable)
                            • User notified

 Mean Time to Contain (MTTC): < 3 minutes (vs. 45 min manual)
```

---

## Step-by-Step Execution Plan

### **Week 1: Infrastructure Setup & Initial Integration**

#### Day 1-2: Wazuh Deployment

**Objective:** Deploy Wazuh Manager and install agent on Windows VM

**Step 1: Install Wazuh Manager (Ubuntu VM)**

```bash
# SSH into Ubuntu VM
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Save the generated admin password (shown in terminal output)
# Access Wazuh web UI: https://<manager-ip>
# Default user: admin
```

**Step 2: Install Wazuh Agent (Windows VM)**

```powershell
# Download agent from Wazuh dashboard: Agents > Deploy new agent
# Run installer, configure:
#   - Manager IP: <your-wazuh-manager-ip>
#   - Agent name: WINDOWS-ENDPOINT-01
#   - Group: default

# Verify agent is connected:
# In Wazuh dashboard: Agents > Active agents (should show 1 agent)
```

**Step 3: Configure Sysmon for Enhanced Logging**

```powershell
# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Install Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Configure Wazuh agent to forward Sysmon logs
# Edit: C:\Program Files (x86)\ossec-agent\ossec.conf
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

# Restart Wazuh agent
Restart-Service -Name wazuh
```

**Validation:** In Wazuh dashboard, search for Sysmon events (Event ID 1, 3, 11, etc.)

---

#### Day 3-4: Shuffle SOAR Setup

**Objective:** Deploy Shuffle and create your first workflow

**Step 1: Create Shuffle Account**

Option A: Cloud (Easiest)
- Visit: https://shuffler.io
- Sign up for free account
- Access workspace: https://shuffler.io/workflows

Option B: Self-Hosted (Docker)
```bash
# On Ubuntu VM
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
docker-compose up -d

# Access: http://<vm-ip>:3001
```

**Step 2: Create Basic Workflow**

1. In Shuffle UI: Click **"New Workflow"**
2. Name: "Wazuh Alert Handler"
3. **Add Trigger:**
   - Click **"Triggers"** → **"Webhook"**
   - Copy webhook URL (you'll use this in Wazuh)
   - Example: `https://shuffler.io/api/v1/hooks/webhook_abc123...`

4. **Test Webhook:**
   ```bash
   curl -X POST https://shuffler.io/api/v1/hooks/webhook_abc123 \
     -H "Content-Type: application/json" \
     -d '{"test": "data", "alert_id": "12345"}'
   ```
   Check Shuffle → Execution history → Should show successful trigger

---

#### Day 5-7: TheHive Deployment & API Integration

**Objective:** Set up case management system

**Step 1: Install TheHive**

```bash
# Ubuntu VM
wget -q -O /tmp/install.sh https://archives.strangebee.com/scripts/install.sh
sudo -v ; bash /tmp/install.sh

# Access: http://<vm-ip>:9000
# Default creds: admin@thehive.local / secret (change immediately!)
```

**Step 2: Create API Key**

- Login to TheHive → Click profile (top-right) → **"API Keys"**
- Click **"Create API Key"**
- Description: "Shuffle Integration"
- Copy API key (starts with `Bearer ...`)

**Step 3: Test API (Optional)**

```bash
curl -X GET http://<thehive-ip>:9000/api/v1/case \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Should return `[]` (empty list of cases) or existing cases.

---

### **Week 2: Workflow Development & Automation Logic**

#### Day 8-10: Build Core SOAR Workflow

**Objective:** Create multi-step automated response workflow in Shuffle

**Workflow Steps to Implement:**

**1. Webhook Trigger (Entry Point)**
- Already created in Days 3-4
- Receives JSON alert from Wazuh

**2. Parse Alert Data (Extract IOCs)**
- App: **"Shuffle Tools"** → **"Parse"**
- Extract fields:
  - `alert_id`
  - `rule_description`
  - `agent_name`
  - `srcip` (source IP if network alert)
  - `file_hash` (if file-based alert)
  - `url` (if phishing/web alert)

**Configuration:**
```json
{
  "alert_id": "$webhook.body.id",
  "rule": "$webhook.body.rule.description",
  "agent": "$webhook.body.agent.name",
  "srcip": "$webhook.body.data.srcip",
  "hash": "$webhook.body.data.win.eventdata.hashes"
}
```

**3. VirusTotal Enrichment**
- App: **"VirusTotal"** (from Shuffle app library)
- Action: **"Get IP Report"** OR **"Get File Report"** OR **"Get URL Report"**
- API Key: Get free key from virustotal.com/gui/join-us
- Input: Use parsed `srcip` or `hash` from Step 2

**Configuration:**
```
Resource: $parse.srcip
API Key: <your-vt-api-key>
```

**Output:** Saves to variable `$virustotal.malicious_score` (e.g., "45/70 vendors flagged as malicious")

**4. Risk Scoring Logic**
- App: **"Shuffle Tools"** → **"Execute Python"**
- Calculate severity based on VT score

**Python Code:**
```python
import json

def calculate_risk(vt_data):
    malicious = int(vt_data.get("malicious", 0))
    total = int(vt_data.get("total", 70))
    
    if malicious == 0:
        return "Low", "GREEN"
    elif malicious < 10:
        return "Medium", "YELLOW"
    elif malicious < 30:
        return "High", "ORANGE"
    else:
        return "Critical", "RED"

# Input from VirusTotal
vt_result = $virustotal.body.data.attributes.last_analysis_stats
severity, color = calculate_risk(vt_result)

return {"severity": severity, "color": color, "score": f"{malicious}/{total}"}
```

**5. Create TheHive Case**
- App: **"TheHive"** (configure with your API key + URL)
- Action: **"Create Case"**

**Configuration:**
```json
{
  "title": "Automated Alert: $parse.rule",
  "description": "## Alert Details\n- Agent: $parse.agent\n- Source IP: $parse.srcip\n- Rule: $parse.rule\n\n## VirusTotal Analysis\n- Malicious Score: $python.score\n- Severity: $python.severity",
  "severity": 3,
  "tags": ["automated", "phishing", "$python.color"],
  "tlp": 2
}
```

**Output:** Returns `case_id` (e.g., `~1234`)

**6. Analyst Notification (Email)**
- App: **"Email"** (configure SMTP server)
- Action: **"Send Email"**

**Configuration:**
```
To: analyst@company.com
Subject: [SOAR] Alert Requires Approval - Case #$thehive.case_number
Body:
A suspicious activity has been detected and enriched:

Alert ID: $parse.alert_id
Agent: $parse.agent
Rule: $parse.rule
Source IP: $parse.srcip
VirusTotal Score: $python.score

TheHive Case: http://<thehive-ip>:9000/cases/$thehive.case_id

RESPONSE REQUIRED:
Should we isolate this host?

YES: Click here → https://shuffler.io/api/v1/hooks/approve_YES_$parse.alert_id
NO:  Click here → https://shuffler.io/api/v1/hooks/approve_NO_$parse.alert_id

This workflow will wait 15 minutes for your response before auto-closing.
```

**7. Wait for Human Approval**
- App: **"Shuffle Tools"** → **"User Input"**
- Timeout: 15 minutes
- Options: ["YES - Isolate Host", "NO - False Positive"]

**8. Conditional Branch (If Approved)**
- App: **"Shuffle Tools"** → **"Condition"**
- If `$user_input == "YES - Isolate Host"` → Continue
- Else → Skip to Step 10 (Close case)

**9. Execute Active Response (Wazuh)**
- App: **"HTTP"** (REST API call)
- Method: PUT
- URL: `http://<wazuh-manager>:55000/active-response`
- Headers:
  ```
  Authorization: Bearer <wazuh-api-token>
  Content-Type: application/json
  ```
- Body:
  ```json
  {
    "command": "host-deny",
    "agent_id": "$parse.agent_id",
    "alert_id": "$parse.alert_id"
  }
  ```

**What this does:** Wazuh agent executes firewall rule to block all network traffic on the endpoint.

**10. Update TheHive Case (Final Status)**
- App: **"TheHive"** → **"Update Case"**
- Case ID: `$thehive.case_id`
- Status: "Resolved"
- Resolution: "Host isolated successfully via automated response" (if YES) OR "False positive, no action taken" (if NO)

---

#### Day 11-12: Wazuh Integration (Webhook Configuration)

**Objective:** Configure Wazuh to send alerts to Shuffle webhook

**Step 1: Edit Wazuh Integration Config**

```bash
# SSH to Wazuh Manager
sudo nano /var/ossec/etc/ossec.conf
```

Add this block inside `<ossec_config>`:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_abc123...</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

**Explanation:**
- `level>7`: Only forward alerts with severity ≥ 7 (High/Critical)
- `alert_format>json`: Send alerts as JSON (Shuffle-compatible)

**Step 2: Restart Wazuh Manager**

```bash
sudo systemctl restart wazuh-manager
```

**Step 3: Test End-to-End Flow**

On Windows VM, trigger a test alert:

```powershell
# Simulate Mimikatz execution (harmless test file)
# Wazuh has built-in rule to detect "mimikatz" in process names
Start-Process notepad.exe -ArgumentList "mimikatz.txt"
```

**Expected Flow:**
1. Wazuh agent detects process → sends to manager
2. Manager matches rule → generates alert
3. Integration sends JSON to Shuffle webhook
4. Shuffle workflow executes all steps
5. You receive email with approval links
6. Click "YES" → Host isolated (firewall blocks traffic)
7. TheHive case updated with resolution

**Check Results:**
- Shuffle: Execution history (should show successful run)
- TheHive: New case appears
- Email: Approval request received
- Windows VM: After approval, network is blocked (test with `ping 8.8.8.8`)

---

### **Week 3: Testing, Tuning & Portfolio Documentation**

#### Day 13-15: Advanced Testing Scenarios

**Test Case 1: Malicious File Download**

```powershell
# Windows VM: Download EICAR test file (harmless malware test)
Invoke-WebRequest -Uri http://www.eicar.org/download/eicar.com -OutFile C:\Temp\eicar.com
```

**Expected:**
- Wazuh detects suspicious download
- VirusTotal flags EICAR as malicious (100% detection)
- Severity: CRITICAL
- Automatic containment approved

**Test Case 2: False Positive (Legitimate Tool)**

```powershell
# Download legitimate tool that might trigger alert
Invoke-WebRequest -Uri https://live.sysinternals.com/PsExec64.exe -OutFile C:\Temp\psexec.exe
```

**Expected:**
- Wazuh detects admin tool download
- VirusTotal: Mixed results (some AV vendors flag sysint ernals tools)
- Analyst reviews → Clicks "NO" (false positive)
- Case closed with "Legitimate admin tool" note

**Test Case 3: Phishing URL Click**

```powershell
# Simulate user clicking phishing link (use test URL from URLhaus)
Start-Process "https://urlhaus.abuse.ch/url/..." # Use a known-bad test URL
```

**Expected:**
- Wazuh detects connection to malicious domain
- VirusTotal URL scan: flagged by multiple vendors
- Automated case creation
- Host isolation pending approval

---

#### Day 16-18: Performance Tuning & Optimization

**Metrics to Track:**

| Metric | Baseline (Manual) | Target (Automated) | Actual |
|--------|-------------------|--------------------|--------|
| Mean Time to Detect (MTTD) | 10-15 min | 1 min | ___ |
| Mean Time to Contain (MTTC) | 45 min | 3 min | ___ |
| False Positive Rate | 40% | <10% | ___ |
| Analyst Time per Alert | 20 min | 2 min (review only) | ___ |

**Tuning Actions:**

1. **Reduce False Positives:**
   - Add whitelist to Wazuh rules (e.g., exclude Sysinternals tools)
   - Adjust VirusTotal threshold (e.g., only alert if >20 vendors flag)

2. **Improve Response Speed:**
   - Reduce approval timeout from 15 min to 5 min
   - Implement auto-approval for Critical severity (optional, risky)

3. **Enhance Logging:**
   - Add Shuffle execution metadata to TheHive observables
   - Include screenshots/evidence links in case notes

---

#### Day 19-21: Documentation & Portfolio Prep

**Create Comprehensive Project Documentation:**

```markdown
# Automated Phishing Response System

## Executive Summary
Designed and deployed end-to-end SOAR pipeline integrating Wazuh SIEM, Shuffle orchestration, and TheHive case management, reducing Mean Time to Contain (MTTC) from 45 minutes to 3 minutes through autonomous IOC enrichment and endpoint isolation.

## Architecture
[Insert diagram from earlier in template]

## Technology Stack
- **Detection:** Wazuh 4.7 (SIEM/EDR)
- **Orchestration:** Shuffle (SOAR)
- **Case Management:** TheHive 5.x
- **Enrichment:** VirusTotal API
- **Response:** Wazuh Active Response (firewall containment)

## Workflow Logic
[Detailed step-by-step explanation with screenshots]

## Test Results
- **Total Test Alerts:** 25
- **True Positives:** 20 (80%)
- **False Positives:** 5 (20%)
- **Avg MTTC:** 2.8 minutes
- **Human Intervention Required:** 2 minutes per alert (review + approval)

## Metrics Improvement
| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| MTTC | 45 min | 3 min | **93% reduction** |
| Analyst Time/Alert | 20 min | 2 min | **90% reduction** |
| FP Rate | 40% | 20% | **50% reduction** |

## Lessons Learned
- **API rate limits:** VirusTotal free tier = 4 requests/min → added queue delay
- **Human approval bottleneck:** 15-min timeout too long → reduced to 5 min
- **Wazuh tuning:** Default rules too noisy → customized for environment

## Future Enhancements
1. Add Slack integration for mobile approval
2. Implement ML-based risk scoring (replace static VT threshold)
3. Expand to lateral movement detection (Sysmon Event ID 3 - network connections)
4. Integrate with EDR for memory forensics

## Evidence
- [Shuffle workflow export (JSON)]
- [Wazuh config files]
- [TheHive case screenshots (redacted)]
- [Test case execution logs]
```

---

## Evidence to Capture

### Must-Have Artifacts:

- [ ] **Architecture diagram** (draw.io or Lucidchart)
- [ ] **Shuffle workflow screenshot** (full workflow visible)
- [ ] **Shuffle workflow export** (JSON file - shareable)
- [ ] **Wazuh alert example** (screenshot from dashboard)
- [ ] **TheHive case example** (screenshot with observables redacted)
- [ ] **Email approval request** (screenshot)
- [ ] **Isolated host confirmation** (screenshot of blocked ping)
- [ ] **Performance metrics table** (before/after comparison)
- [ ] **Test case execution log** (CSV or table with all 25 test scenarios)

### Optional (Extra Credit):

- [ ] **Video walkthrough** (5-10 min demonstrating end-to-end flow)
- [ ] **Blog post** (Medium/Dev.to explaining architecture)
- [ ] **GitHub repository** (Shuffle workflow + configs, sanitized)

---

## Resume Bullets

### Version 1: Results-Oriented (For Traditional SOC Roles)
> **Automated Incident Response System Development**  
> - Architected and deployed SOAR pipeline integrating Wazuh SIEM, Shuffle orchestration, and TheHive case management, reducing Mean Time to Contain (MTTC) from 45 minutes to 3 minutes (93% improvement)  
> - Automated 90% of phishing alert triage workflow through API-driven IOC enrichment (VirusTotal), risk scoring, and human-in-the-loop approval gates, decreasing analyst time per alert from 20 minutes to 2 minutes  
> - Implemented autonomous endpoint containment via Wazuh active response, executing firewall isolation within seconds of analyst approval across 25+ test scenarios with 80% true positive rate

### Version 2: Technical Skills Focus (For Automation/Engineering Roles)
> **Security Orchestration & API Integration Project**  
> - Built multi-stage SOAR workflow in Shuffle orchestrating 10+ security tool integrations (Wazuh REST API, VirusTotal threat intelligence, TheHive case management) via webhooks, HTTP requests, and Python scripting  
> - Developed conditional logic and risk-based routing using Python-based enrichment layer, calculating dynamic severity scores from VirusTotal reputation data to prioritize critical threats  
> - Configured Wazuh SIEM integration engine to forward high-severity alerts (level ≥7) to SOAR platform in JSON format, enabling real-time autonomous response workflows with sub-minute latency

### Version 3: 2026 Automation-First (For AI SOC / Tier 4 Roles)
> **Autonomous Defense Architecture & Human-Agent Teaming**  
> - Designed supervised automation framework where AI/SOAR agents handle 90% of alert triage execution while humans validate strategic containment decisions, demonstrating shift from reactive monitoring to proactive orchestration  
> - Established human-in-the-loop governance for autonomous response actions, implementing time-bound approval mechanisms (5-min SLA) and audit trails in TheHive for compliance and post-incident review  
> - Proved concept of agentic security operations through open-source stack (Wazuh + Shuffle + TheHive), showcasing readiness for enterprise SOAR platforms (Torq, Palo Alto XSOAR) and AI-native SOC tools (Exaforce, Prophet Security)

---

## Interview Talking Points

### Question: "Tell me about a time you automated a security process."

**STAR Answer:**

**Situation:**  
"In my project to build a modern SOC capability, I identified that phishing response was a major bottleneck. Our manual process took 45 minutes on average: analyst receives alert, manually checks IP reputation on VirusTotal, creates a ticket, emails IT to isolate the host, waits for confirmation. This created a massive backlog."

**Task:**  
"I was tasked with designing an automated response system that could reduce response time while maintaining human oversight for critical actions like host isolation."

**Action:**  
"I built an end-to-end SOAR pipeline using open-source tools:

First, I deployed Wazuh as the SIEM to collect endpoint telemetry and generate alerts based on detection rules.

Next, I configured Wazuh to send high-severity alerts to Shuffle, an open-source SOAR platform, via webhooks in JSON format.

Inside Shuffle, I designed a multi-step workflow:
1. Parse the alert to extract IOCs - source IPs, file hashes, URLs
2. Automatically query the VirusTotal API to get reputation scores
3. Use Python to calculate a risk score based on how many vendors flagged it as malicious
4. Create a case in TheHive (our incident management system) with all the enriched data
5. Send an email to the SOC analyst with a simple YES/NO approval: 'Should we isolate this host?'
6. If the analyst clicks YES, Shuffle sends a command back to Wazuh, which instructs the agent on the compromised machine to execute a firewall rule blocking all traffic - instant containment.

The entire workflow, from detection to containment, takes under 3 minutes once approved."

**Result:**  
"I tested it with 25 scenarios - everything from EICAR malware downloads to false positives like legitimate admin tools. The system achieved:
- 93% reduction in Mean Time to Contain (from 45 minutes to 3 minutes)
- 90% reduction in analyst workload (they only spend 2 minutes reviewing instead of 20 minutes executing)
- 80% true positive rate

Most importantly, it demonstrated the 2026 SOC principle: let automation handle speed and scale, let humans handle judgment and approval. The analyst became a supervisor, not an executor."

---

### Question: "How do you ensure automated responses don't cause more harm than good?"

**Strong Answer:**

"Great question - automation without guardrails is dangerous. I implemented several safety mechanisms:

**1. Human-in-the-Loop for High-Impact Actions:**  
For anything that affects availability - like isolating a host - I require explicit human approval. The automation handles the enrichment and prepares the response, but a human makes the final call within a 5-minute SLA.

**2. Risk-Based Thresholds:**  
I don't just auto-isolate on any alert. The workflow calculates a risk score from VirusTotal data. Only if the score crosses a critical threshold (e.g., >30 out of 70 vendors flagging it) does it even prompt for isolation. Medium-risk alerts just create a case for investigation.

**3. Audit Trails:**  
Every action - automated enrichment, analyst decision, containment execution - is logged in TheHive with timestamps and evidence. If something goes wrong, we can replay the entire decision tree.

**4. Testing in Isolation:**  
Before deploying, I ran 25 test scenarios in a sandboxed environment. I intentionally triggered false positives (like downloading Sysinternals PsExec) to ensure the analyst could override the automation.

**5. Rollback Capability:**  
The Wazuh active response that isolates the host can be reversed with a single command. If we isolate the CFO's laptop by mistake, we can restore connectivity in 30 seconds.

This approach gave us the speed of automation with the safety of human judgment."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] SOAR workflow design and orchestration
- [ ] REST API integration (HTTP requests, authentication)
- [ ] Webhook configuration and event-driven architecture
- [ ] JSON parsing and data transformation
- [ ] Python scripting for security automation
- [ ] SIEM rule tuning and alert routing
- [ ] Incident case management workflows
- [ ] Active response mechanisms (endpoint containment)
- [ ] Threat intelligence API usage (VirusTotal)
- [ ] Linux server administration (Wazuh, TheHive)

**Frameworks & Methodologies:**
- [ ] SOAR operational model
- [ ] Human-in-the-loop governance
- [ ] Risk-based automation (dynamic thresholds)
- [ ] Incident response lifecycle automation
- [ ] Security tool integration patterns

**Soft Skills:**
- [ ] System architecture design
- [ ] Process optimization and efficiency analysis
- [ ] Risk assessment and mitigation planning
- [ ] Technical documentation and runbook creation

---

## Common Mistakes to Avoid

1. **Over-automating:** Don't bypass human approval for destructive actions (isolation, deletion)
2. **API rate limits:** VirusTotal free tier = 4 req/min → add delays in workflow
3. **Hardcoded credentials:** Use Shuffle's encrypted parameter storage for API keys
4. **No error handling:** Add "Catch" blocks in Shuffle for failed API calls
5. **Ignoring false positives:** Test with known-safe tools to validate whitelist logic
6. **Poor logging:** Always update TheHive case with workflow execution metadata

---

## Next Steps After Completion

1. **Expand Detection Coverage:**
   - Add lateral movement detection (Sysmon Event ID 3 - network connections)
   - Integrate PowerShell script block logging for obfuscated command detection

2. **Enhance Enrichment:**
   - Add AbuseIPDB for IP reputation
   - Add URLhaus for URL scanning
   - Implement MISP (threat intelligence platform) integration

3. **Advanced Response Actions:**
   - Memory dump collection (for forensics)
   - User session termination
   - Automated password reset via Active Directory API

4. **Enterprise SOAR Migration:**
   - Export workflow logic to Palo Alto Cortex XSOAR or Torq
   - Document migration guide in portfolio

5. **Contribute to Community:**
   - Share Shuffle workflow on GitHub
   - Write blog post on Medium/Dev.to
   - Present at local BSides conference

---

**Total Time Investment:** 30-40 hours over 3 weeks  
**Portfolio Value:** Flagship automation project demonstrating 2026 SOC readiness  
**Job Market Differentiation:** <5% of SOC analyst candidates have hands-on SOAR experience

---

**This is your proof you can architect autonomous defense. Now build it.** 🤖🔒⚡
