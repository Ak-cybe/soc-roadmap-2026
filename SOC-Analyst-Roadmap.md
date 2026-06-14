# SOC Analyst Project Roadmap
## Beginner to Intermediate Level | Target: SOC Analyst Role

---

## Overview

This roadmap contains **6 portfolio-ready projects** designed to build core SOC analyst skills using LetsDefend, TryHackMe, and CyberDefenders platforms. Each project maps directly to skills demanded in SOC job descriptions.

**Estimated Timeline:** 8-12 weeks (8-15 hours/week)

---

## Project Progression

### **Phase 1: Foundations (Weeks 1-3)**
Build core alert triage and log analysis skills.

- **Project 1:** Live SOC Alert Monitoring (LetsDefend)
- **Project 2:** Phishing Email Analysis Lab (CyberDefenders)

### **Phase 2: Incident Investigation (Weeks 4-7)**
Develop incident response and SIEM/EDR investigation capabilities.

- **Project 3:** SOC Analyst Simulation - Incident Response (TryHackMe)
- **Project 4:** Ransomware Kill Chain Investigation (CyberDefenders)

### **Phase 3: Intermediate Detection & Hunting (Weeks 8-12)**
Advanced threat hunting, detection rule creation, and purple team exercises.

- **Project 5:** Threat Hunting with Splunk/ELK (TryHackMe)
- **Project 6:** Detection Engineering - Writing SIEM Rules (Home Lab + Platform Combo)

---

## Skills Matrix

| Project | Alert Triage | Log Analysis | Incident Response | SIEM Tools | EDR Tools | Threat Hunting | Detection Rules |
|---------|--------------|--------------|-------------------|------------|-----------|----------------|-----------------|
| Project 1 | ✅✅✅ | ✅✅ | ✅ | ✅ | - | - | - |
| Project 2 | ✅✅ | ✅✅✅ | ✅ | - | - | - | - |
| Project 3 | ✅ | ✅✅✅ | ✅✅✅ | ✅✅ | ✅✅ | ✅ | - |
| Project 4 | ✅ | ✅✅✅ | ✅✅✅ | ✅ | ✅✅✅ | ✅✅ | - |
| Project 5 | - | ✅✅ | ✅ | ✅✅✅ | ✅ | ✅✅✅ | ✅ |
| Project 6 | ✅ | ✅✅ | ✅ | ✅✅✅ | - | ✅✅ | ✅✅✅ |

---

## Portfolio Structure

Organize your projects in this directory structure:

```
soc project/
├── SOC-Analyst-Roadmap.md (this file)
├── projects/
│   ├── 01-Live-SOC-Monitoring/
│   │   ├── README.md
│   │   ├── screenshots/ (redacted)
│   │   ├── triage-log.md
│   │   └── lessons-learned.md
│   ├── 02-Phishing-Analysis/
│   │   ├── README.md
│   │   ├── evidence/
│   │   ├── ioc-list.csv
│   │   └── analysis-report.md
│   ├── 03-Incident-Response-Sim/
│   ├── 04-Ransomware-Investigation/
│   ├── 05-Threat-Hunting-SIEM/
│   └── 06-Detection-Engineering/
└── templates/
    ├── Project-1-Template.md
    ├── Project-2-Template.md
    └── ... (all 6 templates)
```

---

## Next Steps

1. **Review each project template** in the `templates/` folder
2. **Start with Project 1** - Live SOC Monitoring on LetsDefend
3. **Document as you go** - capture screenshots, notes, and findings
4. **Build your portfolio** - complete 2-3 projects before applying to jobs
5. **Refine resume bullets** using the provided templates

---

## Job Application Strategy

**Minimum for Applications:**
- Complete Projects 1, 2, and 3 (foundation + 1 incident response)
- Create a GitHub repo showcasing your work
- Add 6-8 resume bullets from these projects

**Competitive Portfolio:**
- Complete all 6 projects
- Contribute detection rules to public repos (Sigma, Suricata)
- Maintain a blog/Medium with 2-3 project write-ups

---

## Platform Access Requirements

- **LetsDefend:** Free tier sufficient for Project 1 (upgrade recommended for more scenarios)
- **TryHackMe:** Subscription recommended for Projects 3 & 5 (free rooms available)
- **CyberDefenders:** Free account for Projects 2 & 4
- **Home Lab:** Optional for Project 6 (can use free SIEM trials: Splunk, Elastic)

---

## Additional Resources

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **Cyber Kill Chain:** Lockheed Martin model
- **NIST Incident Response:** SP 800-61
- **SOC Interview Prep:** Common questions + STAR method answers in each template

---

**Ready to start? Open `templates/Project-1-Template.md` for your first project!**
