# Project 9: AI-Assisted Threat Hunting with Jupyter Notebooks
**Platform:** Jupyter + Python + LLM API (OpenAI/Claude) + Splunk/Elastic | **Duration:** 2-3 weeks | **Difficulty:** Advanced

---

## Project Overview

Build a **human-AI collaborative threat hunting framework** using Jupyter Notebooks as the operational workspace. An LLM agent retrieves security logs, performs autonomous statistical analysis, generates visualizations, and produces STIX-formatted intelligence — while you supervise, validate, and steer the investigation in real-time.

**This project proves you can:**
- Supervise AI agents performing security analysis (2026 Tier 4 skill)
- Apply prompt engineering to real security workflows
- Combine data science (pandas, matplotlib) with SOC operations
- Generate machine-readable threat intelligence (STIX 2.1)
- Operate as the strategic "human-in-the-loop" — the core 2026 SOC role

**The Impact:** Reduce hunt cycle time from 8 hours (manual) to 45 minutes (AI-assisted) while increasing detection coverage by 30%.

---

## Learning Objectives

- Master AI agent supervision for security operations
- Develop prompt engineering techniques for threat hunting tasks
- Build Python-based log analysis pipelines (pandas, numpy, matplotlib)
- Create STIX 2.1 threat intelligence objects from hunt findings
- Implement transparent human-AI collaboration workflows
- Understand AI limitations, hallucination risks, and validation techniques
- Generate actionable detection rules from AI-assisted analysis

---

## Tools & Technologies

| Tool | Role | Function |
|------|------|----------|
| **Jupyter Notebook** | Analysis workspace | Interactive Python environment for collaborative hunting |
| **OpenAI API / Claude API** | AI analyst agent | Autonomous log analysis, pattern recognition, hypothesis generation |
| **Python (pandas, numpy)** | Data processing | Log parsing, statistical analysis, correlation |
| **Matplotlib / Seaborn** | Visualization | Charts, heatmaps, timelines for hunt findings |
| **Splunk SDK / Elastic API** | Data source | Pull security logs into Jupyter for analysis |
| **python-stix2** | Intelligence output | Format findings as STIX 2.1 bundles |
| **Sigma CLI** | Detection output | Convert hunt findings to Sigma detection rules |

### Infrastructure Requirements

- Python 3.10+ with Jupyter Lab
- OpenAI API key (free tier: $5 credit) OR Anthropic Claude API key
- Splunk Free (local) or Elastic Stack with sample datasets
- MITRE ATT&CK STIX data (public GitHub repo)
- 8 GB RAM minimum, any OS

---

## Step-by-Step Execution Plan

### **Week 1: Framework Setup & First AI-Assisted Hunt**

#### Day 1-2: Environment Setup

**Step 1: Install Python Environment**

```bash
# Create virtual environment
python -m venv soc-ai-hunt
source soc-ai-hunt/bin/activate  # Linux/Mac
# or: soc-ai-hunt\Scripts\activate  # Windows

# Install dependencies
pip install jupyterlab pandas numpy matplotlib seaborn
pip install openai anthropic  # LLM APIs
pip install splunk-sdk elasticsearch  # SIEM connectors
pip install stix2 sigma-cli  # Intelligence output
pip install python-dotenv requests
```

**Step 2: Configure LLM Agent**

```python
# config.py — NEVER commit API keys
import os
from dotenv import load_dotenv

load_dotenv()

LLM_CONFIG = {
    "provider": "openai",  # or "anthropic"
    "api_key": os.getenv("OPENAI_API_KEY"),
    "model": "gpt-4o",
    "temperature": 0.1,  # Low creativity for security analysis
    "max_tokens": 4000
}

SPLUNK_CONFIG = {
    "host": "localhost",
    "port": 8089,
    "username": os.getenv("SPLUNK_USER"),
    "password": os.getenv("SPLUNK_PASS")
}
```

**Step 3: Create AI Hunting Agent Class**

```python
# ai_hunt_agent.py
import openai
import pandas as pd
import json

class ThreatHuntAgent:
    """AI-powered threat hunting assistant with transparent reasoning."""

    SYSTEM_PROMPT = """You are a senior SOC threat hunter. Your role:
    1. Analyze security log data provided as pandas DataFrames
    2. Identify anomalies, suspicious patterns, and potential threats
    3. Explain your reasoning step-by-step (chain-of-thought)
    4. Map findings to MITRE ATT&CK techniques
    5. Suggest detection rules for confirmed findings
    6. Flag uncertainty — say "I'm not sure" when confidence is low
    7. NEVER fabricate log data or IOCs — only analyze what's provided
    
    Output format: Markdown with code blocks for queries/rules."""

    def __init__(self, config):
        self.client = openai.OpenAI(api_key=config["api_key"])
        self.model = config["model"]
        self.conversation_history = [
            {"role": "system", "content": self.SYSTEM_PROMPT}
        ]

    def analyze(self, prompt, data_context=None):
        """Send analysis request with optional data context."""
        full_prompt = prompt
        if data_context is not None:
            full_prompt += f"\n\nData Summary:\n{data_context}"

        self.conversation_history.append({"role": "user", "content": full_prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.conversation_history,
            temperature=0.1,
            max_tokens=4000
        )

        assistant_message = response.choices[0].message.content
        self.conversation_history.append(
            {"role": "assistant", "content": assistant_message}
        )
        return assistant_message

    def validate_iocs(self, ioc_list, raw_data):
        """Cross-check AI-suggested IOCs against actual log data."""
        validated = []
        for ioc in ioc_list:
            if ioc in raw_data.values:
                validated.append({"ioc": ioc, "status": "CONFIRMED", "source": "raw_logs"})
            else:
                validated.append({"ioc": ioc, "status": "NOT_FOUND", "source": "ai_suggestion"})
        return validated
```

**Validation:** Jupyter Lab launches, agent responds to test prompt, Splunk/Elastic connection works.

---

#### Day 3-5: Hunt #1 — AI-Assisted Credential Abuse Detection

**Hypothesis:** "Compromised credentials are being used for lateral movement outside normal patterns."

**Step 1: Load Authentication Logs into Jupyter**

```python
# In Jupyter Notebook: Hunt-01-Credential-Abuse.ipynb

import pandas as pd
import splunklib.client as splunk_client
from ai_hunt_agent import ThreatHuntAgent
from config import LLM_CONFIG, SPLUNK_CONFIG

# Connect to Splunk
service = splunk_client.connect(**SPLUNK_CONFIG)

# Pull 7 days of authentication logs
query = """search index=windows EventCode=4624 earliest=-7d
| table _time, user, src_ip, dest, LogonType, ComputerName
| head 50000"""

results = service.jobs.oneshot(query)
auth_df = pd.DataFrame([dict(r) for r in results])
print(f"Loaded {len(auth_df)} authentication events")
print(auth_df.head())
```

**Step 2: AI Agent Baseline Analysis**

```python
# Initialize AI agent
agent = ThreatHuntAgent(LLM_CONFIG)

# Provide data summary (NOT raw data — too large)
data_summary = f"""
Authentication Log Summary (7 days):
- Total events: {len(auth_df)}
- Unique users: {auth_df['user'].nunique()}
- Unique source IPs: {auth_df['src_ip'].nunique()}
- Logon types distribution:
{auth_df['LogonType'].value_counts().to_string()}
- Hourly distribution:
{auth_df.groupby(auth_df['_time'].dt.hour).size().to_string()}
"""

analysis = agent.analyze(
    "Analyze this authentication data. Identify anomalous patterns "
    "that could indicate credential abuse, lateral movement, or "
    "compromised accounts. Explain your reasoning for each finding.",
    data_context=data_summary
)

print(analysis)  # Review AI's analysis in notebook
```

**Step 3: Human Validation Loop**

```python
# AI suggests suspicious patterns — YOU validate

# Example: Agent flags user "jsmith" with after-hours logins
suspicious_user = auth_df[auth_df['user'] == 'jsmith']
print(f"Events for jsmith: {len(suspicious_user)}")
print(suspicious_user[['_time', 'src_ip', 'LogonType']].to_string())

# YOUR JUDGMENT: Is this legitimate (on-call IT) or malicious?
# Document your decision in the notebook markdown cell

# Ask agent for deeper analysis
deep_analysis = agent.analyze(
    f"Here are the raw events for user jsmith:\n"
    f"{suspicious_user.to_string()}\n\n"
    f"Analyze: Is this consistent with credential abuse or legitimate activity? "
    f"What additional data would help determine the verdict?"
)
print(deep_analysis)
```

**Step 4: Generate Visualizations**

```python
import matplotlib.pyplot as plt
import seaborn as sns

# Heatmap: Login activity by hour and user
pivot = auth_df.pivot_table(
    index='user', columns=auth_df['_time'].dt.hour,
    values='src_ip', aggfunc='count', fill_value=0
)

plt.figure(figsize=(16, 8))
sns.heatmap(pivot.head(20), cmap='YlOrRd', annot=True, fmt='d')
plt.title('Authentication Heatmap: User vs Hour-of-Day')
plt.xlabel('Hour')
plt.ylabel('User')
plt.tight_layout()
plt.savefig('hunt01_auth_heatmap.png', dpi=150)
plt.show()
```

**Deliverable:** Jupyter notebook with full hunt workflow, AI analysis, human validation notes, and visualizations.

---

#### Day 6-7: Hunt #2 — AI-Powered Anomaly Detection in Network Traffic

**Hypothesis:** "C2 beaconing is hidden in normal HTTPS traffic."

```python
# Hunt-02-C2-Beaconing.ipynb

# Load proxy/network logs
proxy_query = """search index=proxy earliest=-7d
| table _time, src_ip, dest_domain, bytes_out, http_method, status
| head 100000"""

proxy_df = pd.DataFrame([dict(r) for r in service.jobs.oneshot(proxy_query)])

# Ask AI to perform statistical beaconing analysis
beacon_prompt = """
Analyze this network traffic for C2 beaconing indicators.
For each unique (src_ip, dest_domain) pair:
1. Calculate connection frequency (time between connections)
2. Compute standard deviation of intervals
3. Flag pairs with low std dev (regular intervals = beaconing)
4. Check for unusual data transfer patterns

Provide Python code to perform this analysis on the DataFrame 'proxy_df'.
"""

beacon_code = agent.analyze(beacon_prompt, 
    data_context=f"Columns: {list(proxy_df.columns)}, Rows: {len(proxy_df)}")

# CRITICAL: Review AI-generated code before executing
print("=== AI-GENERATED CODE (REVIEW BEFORE RUNNING) ===")
print(beacon_code)

# After manual review, execute the safe portions
# exec(beacon_code)  # Only after human validation!
```

---

### **Week 2: Advanced AI Hunting & STIX Output**

#### Day 8-10: Hunt #3 — AI-Driven LOLBin Detection

**Hypothesis:** "Attackers are using living-off-the-land binaries in ways the AI can distinguish from legitimate admin usage."

```python
# Hunt-03-LOLBin-AI.ipynb

# Load Sysmon process creation logs
sysmon_query = """search index=sysmon EventCode=1 earliest=-7d
| table _time, user, Image, ParentImage, CommandLine, ComputerName
| head 75000"""

process_df = pd.DataFrame([dict(r) for r in service.jobs.oneshot(sysmon_query)])

# AI analysis with specific LOLBin focus
lolbin_analysis = agent.analyze(
    """Analyze process creation logs for LOLBin abuse.
    Focus on these binaries: powershell, cmd, certutil, rundll32,
    regsvr32, mshta, wmic, bitsadmin, msiexec.
    
    For each:
    1. Count total executions
    2. Identify unusual parent processes (e.g., Word spawning PowerShell)
    3. Flag suspicious command-line patterns
    4. Rate each finding: HIGH/MEDIUM/LOW confidence of malicious intent
    5. Map to MITRE ATT&CK techniques
    
    Provide your analysis as a structured table.""",
    data_context=process_df.describe(include='all').to_string()
)

print(lolbin_analysis)
```

**AI Hallucination Check Protocol:**

```python
# MANDATORY: Validate every AI finding against raw data
def validate_ai_findings(agent_findings, raw_df):
    """Cross-reference AI claims with actual log data."""
    validation_report = []
    
    for finding in agent_findings:
        # Check if the process/user/IP actually exists in data
        match = raw_df[raw_df['Image'].str.contains(finding['process'], na=False)]
        
        validation_report.append({
            "claim": finding['description'],
            "verified": len(match) > 0,
            "actual_count": len(match),
            "ai_confidence": finding['confidence'],
            "human_verdict": "PENDING"  # YOU fill this in
        })
    
    return pd.DataFrame(validation_report)
```

---

#### Day 11-14: STIX Intelligence Generation & Detection Rules

**Step 1: Convert Hunt Findings to STIX 2.1**

```python
# stix_generator.py
from stix2 import (Indicator, Relationship, Bundle, 
                    AttackPattern, Identity, Report)
from datetime import datetime

def create_stix_bundle(hunt_findings):
    """Convert validated hunt findings to STIX 2.1 bundle."""
    
    soc_identity = Identity(
        name="SOC AI Hunt Team",
        identity_class="organization"
    )
    
    indicators = []
    relationships = []
    
    for finding in hunt_findings:
        if finding['verdict'] == 'MALICIOUS':
            indicator = Indicator(
                name=f"Hunt Finding: {finding['description'][:50]}",
                pattern=f"[{finding['stix_pattern']}]",
                pattern_type="stix",
                valid_from=datetime.now(),
                labels=["malicious-activity"],
                created_by_ref=soc_identity.id,
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": finding['attack_technique']
                }]
            )
            indicators.append(indicator)
            
            attack_pattern = AttackPattern(
                name=finding['attack_technique'],
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": finding['attack_technique']
                }]
            )
            
            rel = Relationship(
                source_ref=indicator.id,
                target_ref=attack_pattern.id,
                relationship_type="indicates"
            )
            relationships.append(rel)
    
    bundle = Bundle(
        objects=[soc_identity] + indicators + relationships
    )
    
    # Save STIX bundle
    with open("hunt_intelligence.json", "w") as f:
        f.write(bundle.serialize(pretty=True))
    
    return bundle

# Usage
bundle = create_stix_bundle(validated_findings)
print(f"Generated STIX bundle with {len(bundle.objects)} objects")
```

**Step 2: AI-Generated Sigma Rules**

```python
# Ask AI to generate detection rules from findings
sigma_prompt = """Based on these validated hunt findings:
{findings_summary}

Generate Sigma detection rules for each confirmed malicious finding.
Follow exact Sigma specification format with:
- title, id, status, description, author, date
- logsource (category, product)
- detection (selection, condition)
- falsepositives, level, tags (ATT&CK)

Output as valid YAML."""

sigma_rules = agent.analyze(sigma_prompt)

# VALIDATE: Review each rule before deployment
print("=== REVIEW SIGMA RULES BEFORE DEPLOYMENT ===")
print(sigma_rules)
```

---

### **Week 3: Metrics, Documentation & Portfolio**

#### Day 15-17: Performance Metrics & Comparison

**AI-Assisted vs. Manual Hunt Comparison:**

| Metric | Manual Hunt (P5) | AI-Assisted Hunt (P9) | Improvement |
|--------|-----------------|----------------------|-------------|
| Time per hunt cycle | 8 hours | 45 minutes | 91% faster |
| Queries developed | 4-5 per hunt | 15-20 per hunt | 3-4x more |
| Data volume analyzed | 50K events | 200K+ events | 4x more |
| Detection rules generated | 1-2 per hunt | 5-8 per hunt | 4x more |
| False positive rate | 60% initial | 25% initial | 58% reduction |
| STIX objects generated | 0 (manual notes) | 15+ per hunt | N/A (new capability) |

#### Day 18-21: Portfolio Documentation & Notebook Cleanup

**Clean and document 3 Jupyter Notebooks:**
1. `Hunt-01-Credential-Abuse.ipynb` — Full workflow with AI analysis
2. `Hunt-02-C2-Beaconing.ipynb` — Statistical analysis + visualizations
3. `Hunt-03-LOLBin-AI.ipynb` — Process analysis + STIX output

**Each notebook must contain:**
- Markdown cells explaining hypothesis and methodology
- AI agent responses (full chain-of-thought visible)
- Human validation notes (your judgment documented)
- Visualizations (saved as PNG)
- STIX bundle output
- Sigma detection rules

---

## Evidence to Capture

- [ ] 3 complete Jupyter Notebooks with AI-assisted hunts
- [ ] Screenshots of AI agent analysis (chain-of-thought reasoning)
- [ ] Authentication heatmap and beaconing detection visualizations
- [ ] STIX 2.1 intelligence bundle (JSON)
- [ ] 10+ Sigma detection rules generated from hunt findings
- [ ] AI validation report (confirmed vs. hallucinated findings)
- [ ] Performance comparison: manual vs. AI-assisted metrics
- [ ] Hunt summary report with MITRE ATT&CK mapping

---

## Resume Bullets

### Version 1: AI-First SOC Operations (CISO-Path)
> **AI-Assisted Threat Hunting Framework**  
> - Architected human-AI collaborative threat hunting platform using Jupyter Notebooks and LLM agents, establishing organizational capability for AI-supervised security operations aligned with 2026 Tier 4 SOC model  
> - Reduced threat hunt cycle time from 8 hours to 45 minutes (91% improvement) while increasing detection coverage by 30% through AI-driven log correlation across 200K+ security events per hunt  
> - Implemented AI governance controls including hallucination validation protocols and transparent reasoning requirements, ensuring 100% of AI-generated IOCs were verified against source data before operationalization

### Version 2: Technical Data Science Focus (CISO-Path)
> **Machine Learning & AI for Proactive Threat Detection**  
> - Built Python-based security analytics pipeline processing 200K+ events per hunt using pandas, numpy, and statistical anomaly detection to identify C2 beaconing, credential abuse, and LOLBin attacks invisible to signature-based tools  
> - Developed automated STIX 2.1 intelligence generation from hunt findings, producing machine-readable threat intelligence with ATT&CK mappings that integrated directly into organizational TIP (MISP) for cross-team consumption  
> - Engineered prompt engineering framework for security-specific LLM interactions, achieving 75% accuracy on initial AI analysis with human-in-the-loop validation bringing final accuracy to 95%

### Version 3: Strategic Business Impact (CISO-Path)
> **Next-Generation SOC Capability Development**  
> - Designed and validated AI-augmented threat hunting methodology that enabled 4x analyst productivity improvement, directly supporting executive decision to reduce SOC headcount growth by 30% while expanding detection coverage  
> - Established AI supervision protocols and validation frameworks adopted as organizational standard for all AI-assisted security operations, reducing risk of automated false positive escalation by 58%  
> - Generated 15+ STIX threat intelligence objects per hunt cycle, creating reusable organizational knowledge base that improved cross-functional threat awareness and informed quarterly risk reporting to the board

---

## Interview Talking Points

### Question: "How do you use AI in security operations?"

**STAR Answer:**

**Situation:**  
"Our SOC was spending 8 hours per threat hunt, manually writing queries, analyzing results, and documenting findings. We could only run 2-3 hunts per month, leaving significant ATT&CK coverage gaps."

**Task:**  
"I was tasked with exploring how AI agents could accelerate our threat hunting program without sacrificing accuracy or introducing new risks."

**Action:**  
"I built a human-AI collaborative framework using Jupyter Notebooks as the workspace. The AI agent — powered by GPT-4 with a security-specific system prompt — would analyze log data summaries, identify statistical anomalies, and suggest investigation paths.

Critically, I implemented guardrails: the AI never had direct SIEM access, I reviewed all AI-generated code before execution, and every IOC the AI suggested was validated against raw log data. I created a validation protocol that caught AI hallucinations — in one case, the model fabricated an IP address that didn't exist in our logs.

The workflow was: I loaded data into pandas, provided the AI with statistical summaries, reviewed its analysis, validated findings, then used the AI to generate STIX intelligence objects and Sigma detection rules from confirmed findings."

**Result:**  
"We reduced hunt cycle time from 8 hours to 45 minutes — a 91% improvement. The AI helped us analyze 4x more data per hunt and generate 4x more detection rules. But the key metric was accuracy: with the human-in-the-loop validation, our final finding accuracy was 95%, compared to 75% from the AI alone. This proved that human-AI teaming is the model — not full automation."

---

### Question: "What are the risks of using AI in SOC operations?"

**Strong Answer:**

"Three critical risks I've identified and mitigated:

**1. Hallucination Risk:** LLMs can fabricate IOCs, invent log entries, or misattribute techniques. In my project, I caught the AI generating an IP address that wasn't in our dataset. Mitigation: mandatory cross-validation of every AI output against source data.

**2. Over-Reliance:** If analysts blindly trust AI output, they stop developing investigative skills. Mitigation: I designed the workflow so the human always reviews AI reasoning and makes the final classification decision. The AI suggests; the human decides.

**3. Prompt Injection:** If an attacker can influence the data the AI analyzes — for example, crafting log entries with embedded instructions — they could manipulate the AI's analysis. Mitigation: sanitize all input data, use system prompts that resist injection, and treat AI output as untrusted until validated.

The meta-lesson: AI in SOC is a force multiplier, not a replacement. The 2026 model is human supervision of AI execution, not autonomous AI making security decisions alone."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] LLM API integration (OpenAI, Anthropic)
- [ ] Prompt engineering for security analysis
- [ ] Python data analysis (pandas, numpy, matplotlib)
- [ ] Jupyter Notebook development
- [ ] STIX 2.1 threat intelligence creation
- [ ] Sigma rule generation
- [ ] SIEM API integration (Splunk SDK / Elastic API)
- [ ] Statistical anomaly detection
- [ ] AI output validation techniques

**Frameworks:**
- [ ] Human-AI teaming methodology
- [ ] AI governance for security operations
- [ ] MITRE ATT&CK (automated mapping)
- [ ] STIX/TAXII 2.1 data model
- [ ] Threat hunting lifecycle (AI-enhanced)

**Soft Skills:**
- [ ] AI supervision and oversight
- [ ] Critical evaluation of AI output
- [ ] Strategic thinking — AI capability assessment
- [ ] Technical documentation for executive audience
- [ ] Risk assessment of AI-powered tools

---

## Common Mistakes to Avoid

1. **Trusting AI blindly:** ALWAYS validate AI-generated IOCs against raw data
2. **Feeding raw data to LLM:** Summarize data → send summary (token limits + cost)
3. **Ignoring hallucinations:** Track AI accuracy metrics — expect 70-85% raw accuracy
4. **No system prompt:** Security-specific system prompts dramatically improve output quality
5. **Skipping human review of AI code:** Never `exec()` AI-generated code without reading it first
6. **Over-engineering prompts:** Simple, specific prompts outperform complex ones

---

## Next Steps

1. **Move to Project 10:** Post-Quantum Cryptography Readiness
2. **Expand:** Add more data sources (EDR telemetry, cloud logs)
3. **Automate:** Schedule recurring AI-assisted hunts via cron/Airflow
4. **Publish:** Write a blog post on "AI-Assisted Threat Hunting: Lessons Learned"
5. **Certify:** Consider SANS SEC595 (Applied Data Science for Cybersecurity)

---

**Total Time Investment:** 35-45 hours over 2-3 weeks  
**Portfolio Artifacts:** 3 Jupyter Notebooks, STIX bundle, 10+ Sigma rules, performance metrics  
**Job Market Value:** AI-assisted security is THE differentiator in 2026 — <5% of candidates have this skill

---

**This project proves you can operate as a Tier 4 SOC Orchestrator — supervising AI agents, validating machine output, and making strategic security decisions. That's the 2026 CISO path.** 🚀🤖🔒
