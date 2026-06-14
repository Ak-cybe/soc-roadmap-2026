# Project 8: Automated Threat Intelligence Platform (TIP)
**Platform:** MISP + OpenCTI + Cortex + Custom Python Automation | **Duration:** 3-4 weeks | **Difficulty:** Advanced

---

## Project Overview

Build an **enterprise-grade Threat Intelligence Platform** that automatically collects IOCs from 15+ sources, enriches them with AI-powered analysis, correlates threats across your infrastructure, and generates actionable SIEM detection rules—all without manual intervention.

**This is your "killer project"** for demonstrating:
- Strategic security thinking (proactive vs. reactive)
- Multi-tool orchestration at scale
- AI/ML integration for threat analysis
- Automated intelligence → detection pipeline
- Enterprise TI operations

**The Impact:** Convert raw threat feeds into deployed SIEM rules in <5 minutes, automated.

---

## Why This Project Is Powerful

**Traditional TI Programs (Manual):**
- Analyst subscribes to 5-10 threat feeds
- Manually reviews 1,000s of IOCs daily
- Copy-pastes relevant IOCs into SIEM
- Creates detection rules one-by-one
- Takes days/weeks to operationalize intelligence

**Your Automated TIP:**
- ✅ Ingests from 15+ sources automatically (APIs, RSS, STIX/TAXII)
- ✅ AI-powered relevance scoring (filters 10,000 IOCs → 50 actionable)
- ✅ Automated enrichment (VirusTotal, AbuseIPDB, Shodan, passive DNS)
- ✅ Cross-correlation with your environment (EDR, firewall logs)
- ✅ Auto-generates Sigma/Splunk/Elastic rules
- ✅ Pushes rules to SIEM via API in real-time
- ✅ **Result:** Intelligence → Detection in <5 minutes vs. 5 days

---

## Learning Objectives

- Master threat intelligence lifecycle (collection → analysis → dissemination → feedback)
- Implement STIX/TAXII protocols for TI sharing
- Build automated ingestion pipelines from multiple sources
- Use AI/ML for IOC relevance scoring and false positive reduction
- Create intelligence → detection automation (IOCs → SIEM rules)
- Understand strategic vs. tactical intelligence
- Develop automated threat correlation workflows

---

## Tools & Technologies

### Core Intelligence Stack

| Tool | Role | Function |
|------|------|----------|
| **MISP** | TI Platform (TIP) | Central IOC repository, correlation engine, event management |
| **OpenCTI** | Cyber Threat Intelligence Platform | Knowledge graph, campaign tracking, relationship analysis |
| **Cortex** | Observable Analyzers | Automated enrichment engine (40+ analyzers) |
| **TheHive** | Case Management | Convert TI to investigations (integrates from Project 7) |
| **Custom Python** | Automation Glue | API orchestration, ML scoring, rule generation |

### Threat Intelligence Sources (15+ Free Feeds)

**OSINT Feeds:**
- AlienVault OTX (Open Threat Exchange)
- Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- Spamhaus DROP lists
- EmergingThreats IDS rules
- PhishTank
- SANS ISC (Internet Storm Center)

**Commercial Free Tiers:**
- VirusTotal Intelligence
- AbuseIPDB
- Shodan
- IPVoid
- ThreatCrowd

**Community Feeds:**
- MISP communities (public instances)
- Twitter #threatintel hashtag scraping
- GitHub IOC repositories

### Infrastructure Requirements

- **MISP Server:** Ubuntu 22.04 VM (8 GB RAM, 4 vCPU, 100 GB disk)
- **OpenCTI Server:** Ubuntu VM (8 GB RAM, 4 vCPU, 100 GB disk) OR Docker
- **Cortex Analyzers:** Ubuntu VM (4 GB RAM, 2 vCPU, 50 GB disk)
- **Automation Server:** Python 3.10+, Redis, PostgreSQL
- **Total:** 3-4 VMs OR cloud instances (AWS/Azure)

---

## Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│          AUTOMATED THREAT INTELLIGENCE PLATFORM (TIP)             │
└───────────────────────────────────────────────────────────────────┘

┌─────────────── INGESTION LAYER ───────────────┐
│                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │AlienVault│  │ Abuse.ch │  │PhishTank │   │
│  │   OTX    │  │  Feeds   │  │          │   │  (15+ Sources)
│  └──────────┘  └──────────┘  └──────────┘   │
│       │              │              │         │
│       └──────────────┼──────────────┘         │
│                      ▼                         │
│            ┌──────────────────┐               │
│            │  MISP Feeders    │ ← Automated   │
│            │  (Python Jobs)   │   ingestion   │
│            └──────────────────┘   every 1hr   │
└────────────────────┬───────────────────────────┘
                     │
                     ▼
┌─────────────── PROCESSING LAYER ──────────────┐
│                                                │
│         ┌─────────────────────┐               │
│         │       MISP          │               │
│         │ (Central TI Repo)   │               │
│         │  • 100K+ IOCs       │               │
│         │  • Tagging          │               │
│         │  • Correlation      │               │
│         └─────────────────────┘               │
│                  │                             │
│     ┌────────────┼────────────┐               │
│     ▼            ▼             ▼               │
│ ┌────────┐  ┌────────┐  ┌──────────┐         │
│ │Cortex  │  │OpenCTI │  │ Python   │         │
│ │Analyzers│ │Knowledge│ │ML Scorer │         │
│ └────────┘  │ Graph  │  └──────────┘         │
│     │        └────────┘       │               │
│     │ Enrich      │ Context   │ Relevance    │
│     ▼             ▼            ▼               │
│         AI-Powered Filtering                  │
│         • VirusTotal score                    │
│         • ML relevance (is it targeting us?)  │
│         • False positive prediction           │
│         • Severity calculation                │
│                  │                             │
│         10,000 IOCs → 50 Actionable           │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
┌─────────────── AUTOMATION LAYER ──────────────┐
│                                                │
│    ┌────────────────────────────┐            │
│    │  Detection Rule Generator  │            │
│    │      (Python Engine)       │            │
│    └────────────────────────────┘            │
│             │                                  │
│    ┌────────┼────────┐                       │
│    ▼        ▼         ▼                       │
│ ┌──────┐ ┌──────┐ ┌──────┐                  │
│ │Sigma │ │Splunk│ │Elastic│                 │
│ │Rules │ │ SPL  │ │ KQL  │                  │
│ └──────┘ └──────┘ └──────┘                  │
│     │        │         │                      │
│     └────────┼─────────┘                      │
│              ▼                                │
│    ┌──────────────────┐                      │
│    │ SIEM API Pusher  │ ← Auto-deploy rules │
│    └──────────────────┘                      │
└────────────────┬──────────────────────────────┘
                 │
                 ▼
┌─────────────── DETECTION LAYER ───────────────┐
│                                                │
│         ┌──────────────────┐                  │
│         │  Splunk / Elastic│                  │
│         │      (SIEM)      │                  │
│         │  • Auto-deployed │                  │
│         │    IOC rules     │                  │
│         │  • Active alerts │                  │
│         └──────────────────┘                  │
│                  │                             │
│         Alert fires on match                  │
│                  ▼                             │
│         ┌──────────────────┐                  │
│         │    TheHive       │ ← From Project 7 │
│         │  (Auto-ticket)   │                  │
│         └──────────────────┘                  │
└─────────────────────────────────────────────────┘

 Intelligence → Detection Cycle Time: < 5 minutes (automated)
           vs. 5 days (manual SOC process)
```

---

## Step-by-Step Execution Plan

### **Week 1: Infrastructure Setup & MISP Deployment**

#### Day 1-2: MISP Installation

**Objective:** Deploy central threat intelligence platform

**Step 1: Install MISP (Ubuntu VM)**

```bash
# SSH to Ubuntu VM
# Use automated installer
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
sudo bash /tmp/INSTALL.sh -A

# This installs:
# - MISP core application
# - MySQL database
# - Redis cache
# - Apache web server

# Installation takes 30-40 minutes
# Access: https://<vm-ip>
# Default creds: admin@admin.test / admin (change immediately!)
```

**Step 2: Initial MISP Configuration**

1. **Login** to MISP web UI
2. **Change admin password**
3. **Create Organization:**
   - Name: "Your SOC Lab"
   - Description: "Automated TI Platform"
4. **Create API Key:**
   - Admin → List Users → Your User → Auth Keys
   - Add authentication key
   - Copy key (starts with `xyz123...`)

**Step 3: Enable MISP Modules (Enrichment)**

```bash
# Install MISP modules for automated enrichment
sudo apt-get install -y python3-pip
cd /usr/local/src/
sudo git clone https://github.com/MISP/misp-modules.git
cd misp-modules
sudo pip3 install -r REQUIREMENTS
sudo pip3 install .

# Start modules service
sudo systemctl enable --now misp-modules

# Configure MISP to use modules
# In MISP UI: Server Settings & Maintenance → Plugin Settings
# → Enable "Plugin.Enrichment_services_enable"
```

**Validation:**
- MISP UI accessible at https://\<vm-ip\>
- Can create test event manually
- Modules running: `sudo systemctl status misp-modules`

---

#### Day 3-4: Threat Feed Integration (Automated Ingestion)

**Objective:** Configure automatic pulling of threat feeds

**Step 1: Add Feeds in MISP**

In MISP UI: **Sync Actions → List Feeds → Add Feed**

**Configure these free feeds:**

1. **AlienVault OTX**
   - Name: AlienVault OTX
   - Provider: AlienVault
   - Type: MISP Feed
   - URL: `https://otx.alienvault.com/api/v1/pulses/subscribed`
   - Headers: `X-OTX-API-KEY: <your-otx-api-key>`
   - Distribution: Your organization only

2. **Abuse.ch URLhaus**
   - Name: Abuse.ch URLhaus
   - Type: CSV
   - URL: `https://urlhaus.abuse.ch/downloads/csv_recent/`
   - Settings: Select all fields

3. **Abuse.ch MalwareBazaar**
   - Type: MISP Feed
   - URL: `https://mb-api.abuse.ch/misp/`

4. **EmergingThreats**
   - Type: Freetext
   - URL: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`

5. **PhishTank**
   - Type: CSV
   - URL: `http://data.phishtank.com/data/<your-api-key>/online-valid.csv`

**Repeat for 10+ more feeds** (SANS ISC, Spamhaus, etc.)

**Step 2: Automate Feed Pulling (Cron Jobs)**

```bash
# Create automation script
sudo nano /opt/misp-automation/fetch-feeds.sh
```

```bash
#!/bin/bash
# MISP Automated Feed Fetcher

MISP_URL="https://localhost"
MISP_API_KEY="your-misp-api-key-here"

# Fetch all enabled feeds
for feed_id in $(curl -k -H "Authorization: $MISP_API_KEY" \
  "$MISP_URL/feeds" | jq -r '.Feed[] | select(.Feed.enabled == true) | .Feed.id')
do
  echo "Fetching feed ID: $feed_id"
  curl -k -X GET -H "Authorization: $MISP_API_KEY" \
    "$MISP_URL/feeds/fetchFromFeed/$feed_id"
  sleep 10
done

echo "Feed fetch complete"
```

```bash
# Make executable
sudo chmod +x /opt/misp-automation/fetch-feeds.sh

# Add to crontab (runs every hour)
sudo crontab -e
# Add this line:
0 * * * * /opt/misp-automation/fetch-feeds.sh >> /var/log/misp-feeds.log 2>&1
```

**Step 3: Test Feed Ingestion**

```bash
# Manually run once
sudo /opt/misp-automation/fetch-feeds.sh

# Check MISP UI: Event Actions → List Events
# Should see new events with "Feed" tag
```

**Expected Result:** MISP automatically pulls 1,000s of IOCs hourly from 15+ sources.

---

#### Day 5-7: Cortex Analyzer Deployment (Enrichment Engine)

**Objective:** Deploy automated IOC enrichment system

**Step 1: Install Cortex**

```bash
# New Ubuntu VM or Docker
wget -q -O /tmp/cortex-install.sh https://download.thehive-project.org/scripts/install.sh
sudo bash /tmp/cortex-install.sh Cortex

# Access: http://<cortex-ip>:9001
# Create admin account on first login
```

**Step 2: Install Analyzers (40+ Available)**

```bash
cd /opt/Cortex-Analyzers
sudo pip3 install -r analyzers/requirements.txt

# Enable key analyzers in Cortex UI:
# - VirusTotal (file, URL, IP, domain)
# - AbuseIPDB
# - Shodan
# - MaxMind GeoIP
# - PassiveTotal
# - OTXQuery (AlienVault)
# - ThreatCrowd
# - Malwares (hash lookups)
```

**Step 3: Integrate MISP ↔ Cortex**

**In MISP:**
- Server Settings & Maintenance → Plugin Settings
- `Plugin.Cortex_services_enable` = true
- `Plugin.Cortex_services_url` = http://\<cortex-ip\>:9001
- `Plugin.Cortex_authkey` = \<cortex-api-key\>

**Test Integration:**
- Open any event in MISP
- Click an attribute (e.g., IP address)
- Click "Correlate" → "Cortex"
- Select analyzer (e.g., "VirusTotal_GetReport")
- Should return enrichment data

**Automation:** Configure auto-enrichment on new IOCs (MISP workflows)

---

### **Week 2: AI-Powered Filtering & Intelligence Scoring**

#### Day 8-10: Build ML-Based Relevance Scorer

**Objective:** Filter 10,000 daily IOCs → 50 actionable using machine learning

**Why This Matters:**
- Most threat feeds have 90%+ noise (generic IOCs, old data)
- Manual review impossible at scale
- Need automated "Is this relevant to MY environment?" scoring

---

**Step 1: Create Training Dataset**

```python
# collect_training_data.py
import requests
import json
import pandas as pd
from datetime import datetime, timedelta

MISP_URL = "https://your-misp-instance"
MISP_KEY = "your-api-key"

headers = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Get last 30 days of events
response = requests.get(
    f"{MISP_URL}/events/index",
    headers=headers,
    params={"date_from": "2025-12-10"},
    verify=False
)

events = response.json()

# Extract features for ML
training_data = []

for event in events:
    for attr in event.get("Attribute", []):
        # Features
        features = {
            "ioc_type": attr["type"],  # ip-src, domain, sha256, etc.
            "threat_level": event.get("threat_level_id", 4),
            "tlp": attr.get("distribution", 0),
            "tags_count": len(event.get("Tag", [])),
            "has_malware_tag": any("malware" in t["name"].lower() for t in event.get("Tag", [])),
            "has_apt_tag": any("apt" in t["name"].lower() for t in event.get("Tag", [])),
            "source_reliability": event.get("orgc", {}).get("name", "unknown"),
            "age_days": (datetime.now() - datetime.fromisoformat(attr["timestamp"])).days,
            "correlation_count": attr.get("sharing_group_id", 0),
            
            # Label (you manually labeled 100 IOCs as relevant/not)
            "is_relevant": attr.get("comment", "").startswith("RELEVANT")  # Your manual label
        }
        training_data.append(features)

df = pd.DataFrame(training_data)
df.to_csv("ioc_training_data.csv", index=False)
print(f"Collected {len(df)} training samples")
```

---

**Step 2: Train Random Forest Classifier**

```python
# train_relevance_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load training data
df = pd.read_csv("ioc_training_data.csv")

# Encode categorical features
le_type = LabelEncoder()
le_source = LabelEncoder()

df["ioc_type_encoded"] = le_type.fit_transform(df["ioc_type"])
df["source_encoded"] = le_source.fit_transform(df["source_reliability"])

# Features for model
feature_cols = [
    "ioc_type_encoded", "threat_level", "tlp", "tags_count",
    "has_malware_tag", "has_apt_tag", "source_encoded",
    "age_days", "correlation_count"
]

X = df[feature_cols]
y = df["is_relevant"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importance
feature_importance = pd.DataFrame({
    "feature": feature_cols,
    "importance": model.feature_importances_
}).sort_values("importance", ascending=False)

print("\nTop Features:")
print(feature_importance.head(10))

# Save model
joblib.dump(model, "ioc_relevance_model.pkl")
joblib.dump(le_type, "label_encoder_type.pkl")
joblib.dump(le_source, "label_encoder_source.pkl")

print("\nModel saved. Accuracy:", model.score(X_test, y_test))
```

**Expected Output:**
```
Classification Report:
              precision    recall  f1-score   support
           0       0.92      0.88      0.90      1200
           1       0.85      0.90      0.87       800

    accuracy                           0.89      2000

Model saved. Accuracy: 0.89
```

---

**Step 3: Real-Time Scoring Pipeline**

```python
# score_new_iocs.py
import requests
import joblib
import pandas as pd
from datetime import datetime

# Load trained model
model = joblib.load("ioc_relevance_model.pkl")
le_type = joblib.load("label_encoder_type.pkl")
le_source = joblib.load("label_encoder_source.pkl")

MISP_URL = "https://your-misp-instance"
MISP_KEY = "your-api-key"

headers = {"Authorization": MISP_KEY, "Accept": "application/json"}

def score_ioc(ioc_data):
    """Score single IOC for relevance"""
    features = {
        "ioc_type_encoded": le_type.transform([ioc_data["type"]])[0],
        "threat_level": ioc_data.get("threat_level", 4),
        "tlp": ioc_data.get("distribution", 0),
        "tags_count": len(ioc_data.get("tags", [])),
        "has_malware_tag": any("malware" in t.lower() for t in ioc_data.get("tags", [])),
        "has_apt_tag": any("apt" in t.lower() for t in ioc_data.get("tags", [])),
        "source_encoded": le_source.transform([ioc_data.get("org", "unknown")])[0],
        "age_days": (datetime.now() - datetime.fromisoformat(ioc_data["timestamp"])).days,
        "correlation_count": ioc_data.get("correlation_count", 0)
    }
    
    X = pd.DataFrame([features])
    relevance_prob = model.predict_proba(X)[0][1]  # Probability of being relevant
    
    return {
        "ioc_value": ioc_data["value"],
        "relevance_score": round(relevance_prob * 100, 2),
        "is_actionable": relevance_prob > 0.7  # 70% threshold
    }

# Fetch today's new IOCs
response = requests.get(
    f"{MISP_URL}/attributes/restSearch",
    headers=headers,
    json={"timestamp": "1d"},  # Last 24 hours
    verify=False
)

new_iocs = response.json()["response"]["Attribute"]

# Score all
scored_iocs = []
for ioc in new_iocs:
    score_result = score_ioc(ioc)
    scored_iocs.append(score_result)

# Filter actionable (relevance > 70%)
actionable = [ioc for ioc in scored_iocs if ioc["is_actionable"]]

print(f"Total new IOCs: {len(scored_iocs)}")
print(f"Actionable IOCs: {len(actionable)} ({len(actionable)/len(scored_iocs)*100:.1f}%)")

# Save actionable IOCs for rule generation
with open("actionable_iocs.json", "w") as f:
    json.dump(actionable, f, indent=2)
```

**Run daily via cron:**
```bash
0 2 * * * /usr/bin/python3 /opt/misp-automation/score_new_iocs.py >> /var/log/ioc-scoring.log 2>&1
```

---

#### Day 11-14: Automated Detection Rule Generation

**Objective:** Convert actionable IOCs into SIEM detection rules

**Step 1: Rule Templates (Sigma Format)**

```python
# generate_sigma_rules.py
import json
import yaml
from datetime import datetime

def generate_sigma_rule(ioc):
    """Generate Sigma rule for IOC"""
    
    ioc_type = ioc["type"]
    ioc_value = ioc["value"]
    
    # Base rule structure
    rule = {
        "title": f"Threat Intel Match - {ioc_type.upper()} - {ioc_value[:20]}",
        "id": f"ti-{hash(ioc_value) % 100000000}",  # Unique ID
        "status": "experimental",
        "description": f"Detection triggered by threat intelligence feed match",
        "author": "Automated TIP",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "references": [
            f"MISP Event ID: {ioc.get('event_id', 'N/A')}"
        ],
        "tags": [
            "attack.t1071",  # Adjust based on IOC type
            "attack.command_and_control"
        ],
        "logsource": {},
        "detection": {},
        "falsepositives": [
            "Legitimate services sharing infrastructure",
            "CDN or cloud provider overlap"
        ],
        "level": "high"
    }
    
    # IOC-type specific logic
    if ioc_type == "ip-dst" or ioc_type == "ip-src":
        rule["logsource"] = {
            "category": "firewall",
            "product": "any"
        }
        rule["detection"] = {
            "selection": {
                "DestinationIp": ioc_value
            },
            "condition": "selection"
        }
    
    elif ioc_type == "domain":
        rule["logsource"] = {
            "category": "dns",
            "product": "any"
        }
        rule["detection"] = {
            "selection": {
                "query": ioc_value
            },
            "condition": "selection"
        }
    
    elif ioc_type == "url":
        rule["logsource"] = {
            "category": "proxy",
            "product": "any"
        }
        rule["detection"] = {
            "selection": {
                "c-uri|contains": ioc_value
            },
            "condition": "selection"
        }
    
    elif ioc_type == "sha256" or ioc_type == "md5":
        rule["logsource"] = {
            "product": "windows",
            "service": "sysmon"
        }
        rule["detection"] = {
            "selection": {
                "EventID": [1, 11],  # Process creation or file creation
                "Hashes|contains": ioc_value
            },
            "condition": "selection"
        }
    
    return rule

# Load actionable IOCs
with open("actionable_iocs.json") as f:
    actionable_iocs = json.load(f)

# Generate rules
sigma_rules = []
for ioc in actionable_iocs:
    rule = generate_sigma_rule(ioc)
    sigma_rules.append(rule)
    
    # Save individual rule
    filename = f"sigma_rules/ti_rule_{rule['id']}.yml"
    with open(filename, "w") as f:
        yaml.dump(rule, f, default_flow_style=False)

print(f"Generated {len(sigma_rules)} Sigma rules")
```

---

**Step 2: Convert Sigma → Splunk SPL**

```bash
# Install sigmac (Sigma converter)
pip3 install sigma-cli

# Convert all rules to Splunk
for rule in sigma_rules/*.yml; do
    sigma convert -t splunk "$rule" > "splunk_rules/$(basename $rule .yml).spl"
done
```

**Example Output (Splunk SPL):**
```spl
index=firewall DestinationIp="45.142.212.61" 
| eval severity="high"
| eval threat_intel_source="MISP_Feed_AlienVault"
| table _time, SourceIp, DestinationIp, DestinationPort, Action
```

---

**Step 3: Auto-Deploy Rules to Splunk**

```python
# deploy_to_splunk.py
import requests
import glob

SPLUNK_URL = "https://your-splunk:8089"
SPLUNK_TOKEN = "your-splunk-hec-token"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

# Get all generated SPL rules
spl_files = glob.glob("splunk_rules/*.spl")

for spl_file in spl_files:
    with open(spl_file) as f:
        search_query = f.read()
    
    # Create saved search (alert)
    alert_config = {
        "name": f"TI_Alert_{spl_file.split('/')[-1].replace('.spl', '')}",
        "search": search_query,
        "cron_schedule": "*/5 * * * *",  # Every 5 minutes
        "actions": "email",
        "action.email.to": "soc@company.com",
        "alert.severity": "3",
        "alert.track": "1"  # Per-result alert
    }
    
    response = requests.post(
        f"{SPLUNK_URL}/servicesNS/admin/search/saved/searches",
        headers=headers,
        data=alert_config,
        verify=False
    )
    
    if response.status_code == 201:
        print(f"✓ Deployed: {alert_config['name']}")
    else:
        print(f"✗ Failed: {spl_file} - {response.text}")

print(f"\nDeployed {len(spl_files)} detection rules to Splunk")
```

**Run automatically after scoring:**
```bash
0 3 * * * /usr/bin/python3 /opt/misp-automation/generate_sigma_rules.py && \
          /usr/bin/python3 /opt/misp-automation/deploy_to_splunk.py >> /var/log/rule-deployment.log 2>&1
```

---

### **Week 3: OpenCTI Integration & Campaign Tracking**

#### Day 15-17: Deploy OpenCTI Knowledge Graph

**Objective:** Track adversary campaigns, TTPs, relationships

**Step 1: Install OpenCTI**

```bash
# Docker Compose installation (easiest)
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker

# Edit .env file
nano .env
# Set:
# - OPENCTI_ADMIN_EMAIL=admin@yourdomain.com
# - OPENCTI_ADMIN_PASSWORD=ChangeMe
# - OPENCTI_ADMIN_TOKEN=<generate-uuid>

# Start OpenCTI
docker-compose up -d

# Access: http://<vm-ip>:8080
# Login with admin creds from .env
```

**Step 2: Connect OpenCTI ↔ MISP**

1. **In OpenCTI:** Data → Connectors → MISP
   - MISP URL: https://your-misp-instance
   - MISP Key: \<api-key\>
   - Enable "Import from MISP"

2. **Configure sync:**
   - Pull MISP events every 6 hours
   - Create relationships automatically
   - Map MISP tags → OpenCTI labels

**Step 3: Visualize Threat Campaigns**

- OpenCTI automatically creates:
  - **Intrusion Sets** (APT groups)
  - **Malware families** (graphs showing evolution)
  - **Attack Patterns** (MITRE ATT&CK techniques)
  - **Indicators** (linked to campaigns)

**Use Case:** Analyst sees alert → Opens OpenCTI → Views full campaign context

---

#### Day 18-21: End-to-End Automation Orchestration

**Objective:** Tie everything together into single automated pipeline

**Master Orchestration Script:**

```python
# master_tip_orchestrator.py
#!/usr/bin/env python3
"""
Automated Threat Intelligence Platform Orchestrator
Runs full pipeline: Ingest → Enrich → Score → Generate → Deploy
"""

import subprocess
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/tip-orchestrator.log'),
        logging.StreamHandler()
    ]
)

def run_step(script_name, description):
    """Execute pipeline step with logging"""
    logging.info(f"Starting: {description}")
    try:
        result = subprocess.run(
            ["python3", f"/opt/misp-automation/{script_name}"],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode == 0:
            logging.info(f"✓ Completed: {description}")
            logging.debug(result.stdout)
            return True
        else:
            logging.error(f"✗ Failed: {description}\n{result.stderr}")
            return False
    except Exception as e:
        logging.error(f"✗ Exception in {description}: {str(e)}")
        return False

def main():
    logging.info("="*60)
    logging.info("TIP ORCHESTRATION CYCLE STARTED")
    logging.info("="*60)
    
    steps = [
        ("fetch-feeds.sh", "Step 1: Ingest threat feeds from 15+ sources"),
        ("enrich_iocs.py", "Step 2: Enrich IOCs with Cortex analyzers"),
        ("score_new_iocs.py", "Step 3: ML-based relevance scoring"),
        ("generate_sigma_rules.py", "Step 4: Generate Sigma detection rules"),
        ("deploy_to_splunk.py", "Step 5: Deploy rules to SIEM"),
        ("update_opencti.py", "Step 6: Sync to OpenCTI knowledge graph")
    ]
    
    success_count = 0
    for script, description in steps:
        if run_step(script, description):
            success_count += 1
        else:
            logging.warning(f"Pipeline continuing despite failure in: {description}")
    
    # Summary
    logging.info("="*60)
    logging.info(f"ORCHESTRATION COMPLETE: {success_count}/{len(steps)} steps successful")
    logging.info("="*60)
    
    # Metrics
    logging.info("Collecting metrics...")
    # Add metrics collection here (IOCs ingested, rules deployed, etc.)

if __name__ == "__main__":
    main()
```

**Schedule via cron (runs daily at 3 AM):**
```bash
0 3 * * * /usr/bin/python3 /opt/misp-automation/master_tip_orchestrator.py
```

---

### **Week 4: Testing, Metrics & Portfolio Finalization**

#### Day 22-24: End-to-End Testing

**Test Scenario 1: New Malware Campaign**

1. **Simulate:** Add new IOCs to MISP manually (fake campaign)
2. **Observe:**
   - IOCs scored by ML model
   - Sigma rules generated
   - Rules deployed to Splunk
   - OpenCTI shows campaign relationships
3. **Validate:**
   - Trigger alert in Splunk (simulate traffic matching IOC)
   - TheHive case auto-created
   - Full investigation timeline available

**Test Scenario 2: High-Volume Feed Day**

- **Load:** 10,000 IOCs from AlienVault OTX
- **ML Filtering:** Should reduce to ~200-500 actionable
- **Rule Generation:** Only high-confidence IOCs get rules
- **Performance:** Pipeline completes in <30 minutes

**Test Scenario 3: False Positive Handling**

- **Add known-benign IOC** (e.g., google.com IP)
- **ML model should score it low** (not relevant)
- **No rule generated** → validates intelligent filtering

---

#### Day 25-28: Metrics Dashboard & Documentation

**KPIs to Track:**

| Metric | Calculation | Target |
|--------|-------------|--------|
| **Intelligence → Detection Time** | Time from IOC ingestion to SIEM rule deployment | <5 minutes |
| **False Positive Rate** | (FP alerts / Total alerts) × 100 | <10% |
| **Coverage Ratio** | (Unique IOC sources / Total possible) × 100 | >80% |
| **Actionable Intelligence %** | (Actionable IOCs / Total ingested) × 100 | 3-5% |
| **Enrichment Rate** | (Enriched IOCs / Total IOCs) × 100 | >90% |
| **Rule Deployment Success** | (Deployed rules / Generated rules) × 100 | >95% |

**Create Metrics API:**

```python
# metrics_api.py
from flask import Flask, jsonify
import json
from datetime import datetime, timedelta

app = Flask(__name__)

@app.route('/api/metrics/daily')
def daily_metrics():
    # Read from logs/database
    metrics = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "iocs_ingested": 12543,
        "iocs_actionable": 467,
        "actionable_percentage": 3.7,
        "sigma_rules_generated": 467,
        "splunk_rules_deployed": 454,
        "deployment_success_rate": 97.2,
        "avg_intelligence_to_detection_time_min": 4.3,
        "opencti_entities_created": 89,
        "misp_events_created": 34
    }
    return jsonify(metrics)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Grafana Dashboard (Optional):**
- Visualize metrics in real-time
- Track trend over time
- Alert on anomalies (e.g., sudden drop in feed ingestion)

---

## Evidence to Capture

### Must-Have Artifacts:

- [ ] **Architecture diagram** (updated with your specific setup)
- [ ] **MISP screenshot** showing 10,000+ IOCs ingested
- [ ] **Cortex enrichment report** example (VirusTotal analysis)
- [ ] **ML model performance metrics** (classification report, ROC curve)
- [ ] **Generated Sigma rules** (5-10 examples in GitHub repo)
- [ ] **Splunk alert screenshot** (rule deployed and firing)
- [ ] **OpenCTI campaign visualization** (knowledge graph)
- [ ] **Orchestration logs** showing full pipeline execution
- [ ] **Metrics dashboard** (daily stats)
- [ ] **Performance benchmarks** (before/after automation)

### Portfolio Documentation:

```markdown
# Automated Threat Intelligence Platform

## Executive Summary
Architected enterprise-grade TIP processing 10,000+ daily IOCs from 15+ sources, using ML-based filtering (89% accuracy) to reduce analyst workload by 95% and achieving intelligence-to-detection cycle time of <5 minutes through automated Sigma rule generation and SIEM deployment.

## Architecture
[Insert your completed diagram]

## Technology Stack
- **TI Repository:** MISP 2.4
- **Knowledge Graph:** OpenCTI
- **Enrichment:** Cortex (40+ analyzers)
- **ML Filtering:** Python scikit-learn (Random Forest)
- **Rule Generation:** Sigma → Splunk SPL / Elastic KQL
- **Orchestration:** Python + Cron

## Key Innovations
1. **ML-Powered Filtering:** Trained Random Forest classifier reducing 10,000 IOCs → 50 actionable (99.5% noise reduction)
2. **Automated Rule Pipeline:** Sigma templates → SIEM-specific → API deployment (zero manual steps)
3. **Context Enrichment:** Cortex integration providing 40+ data points per IOC automatically
4. **Campaign Tracking:** OpenCTI knowledge graph linking IOCs to APT groups and TTPs

## Metrics
| Metric | Value |
|--------|-------|
| Daily IOCs Ingested | 12,543 |
| Actionable (ML-filtered) | 467 (3.7%) |
| Sigma Rules Generated | 467 |
| SIEM Deployment Success | 97.2% |
| Intelligence → Detection Time | 4.3 minutes |
| Analyst Time Saved | 95% (20 hours/day → 1 hour/day) |

## Test Results
- Correctly identified 89% of relevant IOCs in validation set
- False positive rate: 8.2% (below 10% target)
- Pipeline handles 50,000 IOC spike without degradation

## Challenges & Solutions
**Challenge:** VirusTotal API rate limits (4 req/min on free tier)
**Solution:** Implemented queue system with Redis, prioritized high-confidence IOCs

**Challenge:** Duplicate IOCs across feeds causing noise
**Solution:** MISP de-duplication logic + fuzzy matching algorithm

## Future Enhancements
- Add GPT-4 for IOC context summarization
- YARA rule auto-generation from malware samples
- Automated threat report generation (PDF executive summary)
- Integration with EDR for automated blocking
```

---

## Resume Bullets

### Version 1: Enterprise TI Operations
> **Automated Threat Intelligence Platform Architecture**  
> - Designed and deployed enterprise TIP ingesting 12,500+ daily IOCs from 15+ OSINT/commercial feeds (AlienVault OTX, Abuse.ch, EmergingThreats) with automated STIX/TAXII collection, reducing manual feed monitoring from 20 hours to 0 hours  
> - Implemented ML-based relevance scoring using Random Forest classifier (89% accuracy) to filter 10,000 daily IOCs to 50 actionable indicators, eliminating 99.5% noise and focusing analyst effort on high-confidence threats  
> - Automated intelligence-to-detection pipeline generating Sigma detection rules and deploying to Splunk SIEM via API within 5 minutes of IOC ingestion, reducing traditional 5-day manual process by 99.3%

### Version 2: Technical AI/ML Focus
> **Machine Learning for Threat Intelligence Automation**  
> - Trained supervised ML model (Random Forest, scikit-learn) on 10,000+ labeled IOCs achieving 89% classification accuracy for relevance prediction, with feature engineering across 9 dimensions (IOC type, age, source reliability, correlation count, TLP)  
> - Built automated enrichment pipeline integrating 40+ Cortex analyzers (VirusTotal, Shodan, AbuseIPDB, PassiveTotal) providing multi-source validation and context for IOC scoring with 90%+ enrichment coverage  
> - Developed Python-based Sigma rule generation engine converting filtered IOCs to SIEM-specific detection logic (SPL, KQL, QRadar AQL) with templated rule structures and automated MITRE ATT&CK mapping

### Version 3: Strategic Security Impact
> **Proactive Threat Intelligence Program Development**  
> - Transformed reactive SOC operations to proactive threat-informed defense by deploying automated TIP reducing Mean Time to Detect (MTTD) for known threats from 5 days to 5 minutes through real-time IOC operationalization  
> - Integrated MISP, OpenCTI, and Cortex into unified intelligence ecosystem enabling campaign-level threat tracking, adversary TTPs correlation, and relationship analysis across 50,000+ historical indicators  
> - Achieved 95% reduction in analyst time spent on threat feed review (20 hours/day → 1 hour/day) through ML-driven automation, reallocating resources to proactive threat hunting and detection engineering

---

## Interview Talking Points

### Question: "Describe a complex automation project you built."

**STAR Answer:**

**Situation:**  
"In my SOC automation projects, I identified that threat intelligence was a major pain point. Our analysts were manually reviewing 15 different threat feeds daily—10,000+ IOCs—trying to find maybe 50 that were actually relevant to our environment. This took 20 person-hours per day and we were always 3-5 days behind on operationalizing intelligence."

**Task:**  
"I was tasked with building an automated threat intelligence platform that could ingest feeds, filter for relevance, and automatically deploy detections—all without manual intervention."

**Action:**  
"I architected a multi-tier system:

First, I deployed MISP as the central threat intelligence repository and configured automated ingestion from 15 sources including AlienVault OTX, Abuse.ch feeds, EmergingThreats, and PhishTank. This ran on cron jobs every hour pulling via APIs and STIX/TAXII protocols.

Next, I integrated Cortex as the enrichment layer with 40 analyzers—VirusTotal, Shodan, AbuseIPDB—that automatically ran on every new IOC, providing context like malware family, threat actor association, and geolocation data.

The innovative part was the ML filtering layer. I collected a training dataset of 10,000 IOCs that I manually labeled as 'relevant' or 'noise.' I trained a Random Forest classifier using 9 features: IOC type, threat level, source reliability, age, correlation count, and tag analysis. The model achieved 89% accuracy.

This model ran daily, scoring every new IOC. Only those with >70% relevance probability advanced to the next stage.

Then I built a Python-based Sigma rule generator that created detection rules from actionable IOCs. The system automatically converted these to Splunk SPL and deployed them via the Splunk REST API.

Finally, I integrated OpenCTI to provide campaign-level context, creating knowledge graphs that linked IOCs to APT groups and MITRE ATT&CK techniques.

The entire pipeline was orchestrated with a master Python script running daily at 3 AM."

**Result:**  
"The system now processes 12,500 IOCs daily, filters to 50 actionable ones, and deploys detection rules to our SIEM in under 5 minutes—fully automated. We reduced analyst time from 20 hours/day to 1 hour/day (just oversight), and decreased our intelligence-to-detection cycle from 5 days to 5 minutes—a 99.3% improvement. This freed up our analysts to focus on threat hunting and investigation instead of feed review."

---

### Question: "How did you validate your ML model for threat intelligence?"

**Strong Answer:**

"Great question—validation was critical because false positives in threat intelligence waste resources, and false negatives mean missed threats.

**My validation approach:**

**1. Train/Test Split:**  
I used 80/20 split on my labeled dataset of 10,000 IOCs to prevent overfitting.

**2. Metrics:**  
I focused on three: Precision (are flagged IOCs actually relevant?), Recall (are we catching all relevant IOCs?), and F1-score (balanced measure). My model achieved 85% precision and 90% recall—meaning we'd catch 9 out of 10 relevant IOCs while only having 15% false positives.

**3. Confusion Matrix Analysis:**  
I examined what the model was getting wrong. It struggled with newly registered domains (too few features) and legitimate security tools (like Sysinternals) that some feeds incorrectly flagged. I added domain age as a feature and whitelisted known-good tool signatures.

**4. Real-World Testing:**  
I ran the model on a week of production data in parallel with our manual process before deployment. Analysts reviewed the model's picks blind—it matched their manual selections 87% of the time but was 60x faster.

**5. Continuous Improvement:**  
Post-deployment, I implemented a feedback loop. When analysts mark an IOC as 'false positive' in MISP, it gets added to the training set and the model retrains monthly. Accuracy has improved from 89% to 93% over 6 months.

**The key insight:** Perfect accuracy isn't the goal. Even at 89%, the model processes 10,000 IOCs in 2 minutes vs. 20 hours manually. The 11% error rate is correctable in the 1 hour of analyst review, still giving us a massive net gain."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] Threat intelligence platforms (MISP, OpenCTI)
- [ ] STIX/TAXII protocols
- [ ] Automated feed ingestion (APIs, RSS, webhooks)
- [ ] Enrichment engines (Cortex, multi-analyzer orchestration)
- [ ] Machine Learning (scikit-learn, Random Forest, feature engineering)
- [ ] Sigma rule authoring and conversion
- [ ] SIEM API integration (Splunk REST API, Elastic API)
- [ ] Python automation (requests, pandas, joblib, Flask)
- [ ] Knowledge graph visualization (OpenCTI, campaign tracking)
- [ ] Linux system administration (Ubuntu, cron, systemd)

**Frameworks:**
- [ ] Threat intelligence lifecycle (collection → analysis → dissemination)
- [ ] MITRE ATT&CK (automated technique mapping)
- [ ] STIX 2.x data model
- [ ] Cyber Kill Chain

**Soft Skills:**
- [ ] Strategic security thinking (proactive vs. reactive)
- [ ] Systems architecture design
- [ ] ML model validation and tuning
- [ ] Technical documentation for executive audience

---

## Common Mistakes to Avoid

1. **Feed overload:** Don't add 50 feeds on day 1 → Start with 5, validate, then scale
2. **No de-duplication:** Leads to duplicate alerts → Use MISP correlation
3. **Ignoring false positives:** ML model needs tuning → Collect feedback, retrain
4. **API rate limits:** VirusTotal free = 4 req/min → Implement queue + delays
5. **Poor rule naming:** "rule_1234" is useless → Use descriptive names with IOC context
6. **No testing:** Always test rules in dev SIEM before production deployment

---

## Next Steps After Completion

1. **Expand Intelligence Sources:**
   - Add commercial feeds (if budget available): Recorded Future, Anomali, ThreatConnect
   - Implement Twitter scraping for #threatintel hashtag
   - Integrate ISAC feeds (if in specific industry)

2. **Advanced ML:**
   - Implement deep learning (LSTM) for time-series IOC analysis
   - Add clustering to automatically group related IOCs into campaigns
   - Use GPT-4 API for IOC context summarization

3. **Automated Response:**
   - Integrate with EDR for auto-blocking high-confidence IOCs
   - Connect to firewall APIs for network-level blocking
   - Email gateway integration for domain/URL blocking

4. **Reporting Automation:**
   - Generate weekly executive threat reports (PDF)
   - Automated threat briefings using LLM summarization
   - Trend analysis dashboards (Grafana/Kibana)

5. **Contribute to Community:**
   - Share curated IOCs back to MISP communities
   - Publish Sigma rules to SigmaHQ repository
   - Write blog post on ML-based TI filtering

---

**Total Time Investment:** 50-60 hours over 3-4 weeks  
**Portfolio Impact:** This is a **flagship "wow" project** - enterprise-grade, ML-powered, end-to-end automation  
**Job Market Value:** Only 1-2% of SOC candidates have threat intelligence automation experience

---

## Why This Project Is "Powerful"

✅ **Enterprise-scale:** Handles 10,000+ IOCs/day (realistic production volume)  
✅ **Multi-tool integration:** MISP + OpenCTI + Cortex + SIEM + ML pipeline  
✅ **AI/ML component:** Not just scripting—actual machine learning model  
✅ **Measurable impact:** 99.3% time reduction, quantifiable metrics  
✅ **Strategic thinking:** Shifts from reactive to proactive defense  
✅ **2026-aligned:** Automation-first, intelligence-driven operations  
✅ **Open-source:** All free tools = accessible to everyone  
✅ **Portfolio differentiator:** <2% of candidates have this capability

---

**You wanted "powerful"? This is it. 🚀**

**This project proves you can:**
- Architect complex security ecosystems
- Apply AI/ML to real security problems
- Automate strategic workflows (not just tactical tasks)
- Think like a senior security engineer

**Now go build it and dominate your job interviews.** 💪🔒🤖
