# Project 10: Post-Quantum Cryptography (PQC) Readiness Assessment
**Platform:** Home Lab + Cloud Environment + Open-Source Tools | **Duration:** 2 weeks | **Difficulty:** Advanced

---

## Project Overview

Conduct an **enterprise-grade cryptographic inventory and quantum-readiness assessment** across infrastructure, applications, and data stores. Identify quantum-vulnerable algorithms (RSA, ECDSA, DH), implement hybrid classical/PQC protections in a test environment, and deliver a phased migration roadmap to NIST-approved post-quantum standards (ML-KEM, ML-DSA).

**This project proves you can:**
- Think strategically about emerging threats (CISO-level foresight)
- Conduct cryptographic risk assessments at enterprise scale
- Implement NIST PQC standards before they're mandated
- Build migration roadmaps with business impact analysis
- Position your organization ahead of the quantum threat curve

**The Impact:** Inventory 200+ cryptographic implementations and reduce quantum computing risk exposure by 80% through proactive migration planning.

---

## Learning Objectives

- Understand the quantum computing threat to current cryptography
- Master NIST PQC standards: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
- Conduct cryptographic inventory across infrastructure and applications
- Identify and prioritize quantum-vulnerable assets
- Deploy hybrid (classical + PQC) TLS in test environment
- Create executive-ready migration roadmaps with cost/risk analysis
- Understand "harvest now, decrypt later" (HNDL) attack model

---

## Tools & Technologies

| Tool | Role | Function |
|------|------|----------|
| **OpenSSL 3.x** | Crypto testing | PQC algorithm testing, certificate generation |
| **liboqs (Open Quantum Safe)** | PQC library | Reference implementations of NIST PQC algorithms |
| **oqs-provider** | OpenSSL plugin | Adds PQC algorithms to OpenSSL |
| **Cryptosense Analyzer** (or manual) | Crypto inventory | Scan codebases for cryptographic usage |
| **SSLyze / testssl.sh** | TLS scanner | Audit TLS configurations across infrastructure |
| **Wireshark** | Network analysis | Capture and analyze PQC TLS handshakes |
| **Python + cryptography lib** | Scripting | Automated scanning, benchmarking, reporting |
| **NIST PQC Documentation** | Reference | Algorithm specifications, migration guidance |

### Infrastructure Requirements

- Ubuntu 22.04 VM (or WSL2) with 4GB+ RAM
- OpenSSL 3.0+ with OQS provider
- Python 3.10+
- Sample web applications (DVWA, Juice Shop) for scanning
- Network with TLS services to audit
- Optional: AWS/Azure account for cloud crypto scanning

---

## Step-by-Step Execution Plan

### **Week 1: Cryptographic Inventory & Vulnerability Assessment**

#### Day 1-2: Understanding the Quantum Threat

**Objective:** Build foundational knowledge of quantum computing threats to cryptography.

**Study Material (4 hours):**

1. **NIST PQC Standards** — Read executive summaries of:
   - FIPS 203: ML-KEM (Module-Lattice Key Encapsulation) — replaces RSA/DH key exchange
   - FIPS 204: ML-DSA (Module-Lattice Digital Signature) — replaces RSA/ECDSA signatures
   - FIPS 205: SLH-DSA (Stateless Hash-Based Signature) — backup signature scheme

2. **"Harvest Now, Decrypt Later" (HNDL):**
   - Adversaries record encrypted traffic TODAY
   - Store it until quantum computers can break encryption (est. 2030-2035)
   - HIGH RISK for: healthcare records, financial data, state secrets, classified comms
   - This is why migration must START NOW, not when quantum computers arrive

3. **Create Threat Model Document:**

```markdown
## Quantum Threat Model

### Vulnerable Algorithms (MUST migrate):
| Algorithm | Usage | Quantum Attack | Timeline Risk |
|-----------|-------|---------------|---------------|
| RSA-2048/4096 | TLS, code signing, email | Shor's algorithm | HIGH — broken by ~2030 |
| ECDSA (P-256/P-384) | TLS, JWT, blockchain | Shor's algorithm | HIGH — broken by ~2030 |
| Diffie-Hellman | Key exchange | Shor's algorithm | HIGH — broken by ~2030 |
| AES-128 | Symmetric encryption | Grover's algorithm | MEDIUM — halved security |
| SHA-256 | Hashing | Grover's algorithm | LOW — still 128-bit security |

### Safe Algorithms (No migration needed):
- AES-256 (Grover reduces to 128-bit — still secure)
- SHA-384/SHA-512 (still sufficient security margin)
- HMAC-SHA-256 (quantum-resistant)

### NIST PQC Replacements:
| Legacy | PQC Replacement | Standard |
|--------|----------------|----------|
| RSA key exchange | ML-KEM (Kyber) | FIPS 203 |
| ECDSA signatures | ML-DSA (Dilithium) | FIPS 204 |
| RSA signatures | SLH-DSA (SPHINCS+) | FIPS 205 |
```

---

#### Day 3-5: Cryptographic Inventory Scan

**Objective:** Identify every cryptographic usage across infrastructure.

**Step 1: Install Scanning Tools**

```bash
# TLS scanner
pip install sslyze
sudo apt install testssl.sh

# Code scanning for crypto usage
pip install bandit  # Python security linter (catches weak crypto)
pip install semgrep  # Multi-language static analysis

# OpenSSL with PQC support
sudo apt install cmake ninja-build
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install

# OQS OpenSSL provider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && mkdir build && cd build
cmake -GNinja .. && ninja && sudo ninja install
```

**Step 2: Scan TLS Configurations**

```python
# crypto_inventory_scanner.py
import subprocess
import json
import csv
from datetime import datetime

class CryptoInventoryScanner:
    """Scan infrastructure for quantum-vulnerable cryptography."""

    def __init__(self):
        self.inventory = []

    def scan_tls_endpoint(self, hostname, port=443):
        """Scan TLS configuration of a single endpoint."""
        result = subprocess.run(
            ["sslyze", "--json_out=-", f"{hostname}:{port}"],
            capture_output=True, text=True, timeout=60
        )

        scan_data = json.loads(result.stdout)

        for server in scan_data.get("server_scan_results", []):
            tls_info = server.get("scan_result", {})

            # Extract cipher suites
            for tls_version in ["tls_1_2", "tls_1_3"]:
                ciphers = tls_info.get(f"{tls_version}_cipher_suites", {})
                accepted = ciphers.get("accepted_cipher_suites", [])

                for cipher in accepted:
                    cipher_name = cipher.get("cipher_suite", {}).get("name", "")
                    key_exchange = self._extract_key_exchange(cipher_name)
                    
                    self.inventory.append({
                        "host": hostname,
                        "port": port,
                        "tls_version": tls_version.upper(),
                        "cipher_suite": cipher_name,
                        "key_exchange": key_exchange,
                        "quantum_vulnerable": self._is_quantum_vulnerable(key_exchange),
                        "priority": self._calculate_priority(hostname, key_exchange),
                        "scan_date": datetime.now().isoformat()
                    })

    def _is_quantum_vulnerable(self, algorithm):
        """Check if algorithm is vulnerable to quantum attacks."""
        vulnerable = ["RSA", "ECDHE", "ECDSA", "DHE", "DH", "ECDH"]
        return any(v in algorithm.upper() for v in vulnerable)

    def _calculate_priority(self, hostname, key_exchange):
        """Calculate migration priority based on asset criticality."""
        critical_hosts = ["payment", "auth", "api", "database", "vault"]
        is_critical = any(c in hostname.lower() for c in critical_hosts)
        is_vulnerable = self._is_quantum_vulnerable(key_exchange)

        if is_critical and is_vulnerable:
            return "CRITICAL"
        elif is_vulnerable:
            return "HIGH"
        else:
            return "LOW"

    def _extract_key_exchange(self, cipher_name):
        """Extract key exchange algorithm from cipher suite name."""
        if "ECDHE" in cipher_name: return "ECDHE"
        if "DHE" in cipher_name: return "DHE"
        if "RSA" in cipher_name: return "RSA"
        return "UNKNOWN"

    def scan_multiple(self, targets):
        """Scan list of (hostname, port) tuples."""
        for host, port in targets:
            print(f"Scanning {host}:{port}...")
            try:
                self.scan_tls_endpoint(host, port)
            except Exception as e:
                print(f"  Error scanning {host}: {e}")

    def generate_report(self, output_file="crypto_inventory.csv"):
        """Export inventory to CSV."""
        if not self.inventory:
            print("No scan results to export.")
            return

        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.inventory[0].keys())
            writer.writeheader()
            writer.writerows(self.inventory)

        # Summary statistics
        total = len(self.inventory)
        vulnerable = sum(1 for i in self.inventory if i["quantum_vulnerable"])
        critical = sum(1 for i in self.inventory if i["priority"] == "CRITICAL")

        print(f"\n=== CRYPTO INVENTORY SUMMARY ===")
        print(f"Total cipher suites scanned: {total}")
        print(f"Quantum-vulnerable: {vulnerable} ({vulnerable/total*100:.1f}%)")
        print(f"Critical priority: {critical}")
        print(f"Report saved: {output_file}")

# Usage
scanner = CryptoInventoryScanner()
targets = [
    ("your-web-app.local", 443),
    ("mail-server.local", 993),
    ("vpn-gateway.local", 443),
    ("api-gateway.local", 8443),
    # Add all internal TLS endpoints
]
scanner.scan_multiple(targets)
scanner.generate_report()
```

**Step 3: Scan Code Repositories for Crypto Usage**

```bash
# Scan Python code for weak/quantum-vulnerable crypto
semgrep --config "p/python-crypto" --json ./your-app-code/ > code_crypto_scan.json

# Check for hardcoded keys, weak algorithms
bandit -r ./your-app-code/ -f json -o bandit_results.json

# Manual grep for crypto patterns
grep -rn "RSA\|ECDSA\|Diffie-Hellman\|from Crypto\|from cryptography" ./your-app-code/
```

**Step 4: Create Inventory Spreadsheet**

| Asset | Algorithm | Key Size | Usage | Quantum Risk | Data Sensitivity | Migration Priority |
|-------|-----------|----------|-------|-------------|-----------------|-------------------|
| Web Server TLS | ECDHE-RSA | 2048 | HTTPS | HIGH | Customer PII | CRITICAL |
| API Gateway | ECDSA P-256 | 256 | mTLS | HIGH | Financial data | CRITICAL |
| Email Server | RSA | 2048 | S/MIME | HIGH | Internal comms | HIGH |
| VPN | DH | 2048 | IKEv2 | HIGH | All traffic | CRITICAL |
| Database TLS | AES-256-GCM | 256 | Data at rest | LOW | Customer data | LOW |
| JWT Signing | RS256 | 2048 | Auth tokens | HIGH | Session data | HIGH |
| Code Signing | ECDSA P-384 | 384 | CI/CD | HIGH | Supply chain | HIGH |

---

### **Week 2: Hybrid PQC Implementation & Migration Roadmap**

#### Day 6-8: Deploy Hybrid Classical/PQC TLS

**Objective:** Implement dual-protection TLS using classical + post-quantum algorithms.

**Step 1: Generate PQC Certificates**

```bash
# Generate ML-DSA (Dilithium) CA certificate
openssl req -x509 -new -newkey mldsa65 -keyout pqc_ca.key \
  -out pqc_ca.crt -nodes -days 365 \
  -subj "/CN=PQC Test CA/O=SOC Lab"

# Generate hybrid server certificate (classical + PQC)
openssl req -new -newkey rsa:2048 -keyout server_classical.key \
  -out server_classical.csr -nodes \
  -subj "/CN=testserver.local"

# Sign with PQC CA
openssl x509 -req -in server_classical.csr \
  -CA pqc_ca.crt -CAkey pqc_ca.key \
  -out server_hybrid.crt -days 365

# Generate pure PQC server certificate
openssl req -new -newkey mldsa65 -keyout server_pqc.key \
  -out server_pqc.csr -nodes \
  -subj "/CN=testserver.local"

openssl x509 -req -in server_pqc.csr \
  -CA pqc_ca.crt -CAkey pqc_ca.key \
  -out server_pqc.crt -days 365
```

**Step 2: Configure Nginx with Hybrid TLS**

```nginx
# /etc/nginx/conf.d/pqc-test.conf
server {
    listen 443 ssl;
    server_name testserver.local;

    # Classical certificate (backward compatibility)
    ssl_certificate /etc/nginx/certs/server_hybrid.crt;
    ssl_certificate_key /etc/nginx/certs/server_classical.key;

    # Enable hybrid key exchange (classical + PQC)
    # X25519+ML-KEM-768 hybrid
    ssl_ecdh_curve X25519MLKEM768:X25519:P-256;

    # TLS 1.3 only for PQC support
    ssl_protocols TLSv1.3;

    location / {
        return 200 "PQC Hybrid TLS Active\n";
    }
}
```

**Step 3: Verify PQC Handshake**

```bash
# Test connection with PQC
openssl s_client -connect testserver.local:443 -groups X25519MLKEM768

# Capture PQC handshake in Wireshark
# Filter: tls.handshake.type == 1
# Look for: supported_groups extension containing ML-KEM

# Benchmark: classical vs. hybrid vs. pure PQC
openssl speed rsa2048 ecdsap256 mldsa65
```

**Step 4: Performance Benchmarking**

```python
# pqc_benchmark.py
import subprocess
import time
import json

def benchmark_algorithm(algorithm, operations=1000):
    """Benchmark cryptographic operation speed."""
    start = time.time()
    result = subprocess.run(
        ["openssl", "speed", "-seconds", "10", algorithm],
        capture_output=True, text=True
    )
    elapsed = time.time() - start
    return {
        "algorithm": algorithm,
        "duration_seconds": round(elapsed, 2),
        "output": result.stdout
    }

algorithms = {
    "Classical": ["rsa2048", "ecdsap256", "ecdhx25519"],
    "PQC": ["mldsa65", "mlkem768"],
    "Hybrid": ["x25519mlkem768"]
}

results = {}
for category, algos in algorithms.items():
    results[category] = {}
    for algo in algos:
        print(f"Benchmarking {algo}...")
        results[category][algo] = benchmark_algorithm(algo)

# Performance comparison table
print("\n=== PQC PERFORMANCE COMPARISON ===")
print(f"{'Algorithm':<20} {'Category':<12} {'Ops/sec':<10}")
print("-" * 42)
for cat, algos in results.items():
    for algo, data in algos.items():
        print(f"{algo:<20} {cat:<12} See output")
```

---

#### Day 9-11: Migration Roadmap Development

**Objective:** Create executive-ready PQC migration plan.

**Migration Roadmap Document:**

```markdown
# Post-Quantum Cryptography Migration Roadmap

## Executive Summary
Quantum computers capable of breaking RSA and ECC are projected by 2030-2035.
Our assessment identified 200+ cryptographic implementations across the enterprise,
with 73% using quantum-vulnerable algorithms. This roadmap provides a phased
migration plan to NIST-approved post-quantum standards over 36 months.

## Current State Assessment
- **Total crypto implementations inventoried:** 200+
- **Quantum-vulnerable:** 146 (73%)
- **Critical priority (customer data / auth):** 42 (21%)
- **High priority (internal systems):** 67 (33.5%)
- **Low priority (quantum-safe already):** 54 (27%)

## Risk Assessment

### Highest Risk: "Harvest Now, Decrypt Later"
- Encrypted data captured TODAY can be decrypted when quantum computers arrive
- Risk window: Data encrypted with RSA/ECC has a shelf life problem
- Most critical: Long-lived secrets (healthcare records, financial data, IP)

### Risk Matrix
| Asset Category | Data Sensitivity | Crypto Lifespan | HNDL Risk | Migration Priority |
|---------------|-----------------|-----------------|-----------|-------------------|
| Customer PII | Critical | 7+ years | EXTREME | Phase 1 |
| Financial transactions | Critical | 5+ years | HIGH | Phase 1 |
| Authentication (JWT/OAuth) | High | Short-lived | MEDIUM | Phase 2 |
| Internal communications | Medium | Short-lived | LOW | Phase 3 |
| Code signing | High | Multi-year | HIGH | Phase 2 |

## Phased Migration Plan

### Phase 1: Immediate (0-6 months) — Critical Assets
**Budget Estimate:** $50K-100K
- [ ] Deploy hybrid TLS (X25519+ML-KEM-768) on customer-facing web servers
- [ ] Migrate VPN key exchange to hybrid IKEv2 with PQC
- [ ] Update certificate lifecycle management for PQC support
- [ ] Begin developer training on PQC libraries

### Phase 2: Short-Term (6-18 months) — High Priority
**Budget Estimate:** $100K-250K
- [ ] Migrate API gateway mTLS to ML-DSA certificates
- [ ] Update JWT signing from RS256 to ML-DSA
- [ ] Deploy PQC in CI/CD code signing pipeline
- [ ] Migrate email encryption (S/MIME) to hybrid PQC
- [ ] Update key management systems for PQC key sizes

### Phase 3: Medium-Term (18-36 months) — Complete Migration
**Budget Estimate:** $150K-300K
- [ ] Full TLS 1.3 PQC deployment across all services
- [ ] Legacy system migration (mainframes, embedded devices)
- [ ] Third-party vendor PQC compliance requirements
- [ ] Retire all classical-only cryptographic configurations
- [ ] Conduct post-migration security audit

## Performance Impact Analysis
| Operation | Classical (RSA-2048) | PQC (ML-KEM-768) | Hybrid | Impact |
|-----------|---------------------|-------------------|--------|--------|
| Key Generation | 0.3ms | 0.1ms | 0.4ms | Negligible |
| Key Exchange | 0.5ms | 0.2ms | 0.7ms | +40% latency |
| Signature | 0.8ms | 0.3ms | 1.1ms | +37% latency |
| Key Size | 256 bytes | 1,184 bytes | 1,440 bytes | +462% bandwidth |
| TLS Handshake | 1.2ms | 0.8ms | 2.0ms | +67% latency |

**Conclusion:** Hybrid mode adds ~40-70% latency to handshakes but absolute
impact is <1ms — acceptable for most applications. Key sizes increase
significantly, impacting bandwidth for high-volume APIs.

## Vendor Compatibility Matrix
| Vendor/Product | PQC Support | Status | Notes |
|---------------|-------------|--------|-------|
| OpenSSL 3.5+ | ✅ ML-KEM, ML-DSA | GA | Via oqs-provider |
| Chrome 124+ | ✅ X25519+ML-KEM | GA | Default in 2025+ |
| Firefox 130+ | ✅ X25519+ML-KEM | GA | Enabled by default |
| AWS KMS | ✅ Hybrid | Preview | Limited regions |
| Azure Key Vault | ⏳ Coming | 2026 | Roadmap announced |
| Nginx 1.27+ | ✅ Via OpenSSL | GA | Requires oqs-provider |
| Java 21+ | ✅ ML-KEM | GA | JEP 452 |
```

---

#### Day 12-14: Final Documentation & Portfolio

**Create Executive Briefing (1-page PDF):**

```markdown
# EXECUTIVE BRIEFING: Post-Quantum Cryptography Readiness

**Classification:** INTERNAL — LEADERSHIP ONLY
**Date:** [Current Date]
**Author:** [Your Name], Security Engineering

## THE THREAT
Quantum computers will break RSA and ECC encryption by 2030-2035.
Nation-states are already harvesting encrypted data for future decryption.

## OUR EXPOSURE
- 200+ cryptographic implementations inventoried
- 73% use quantum-vulnerable algorithms
- 42 CRITICAL systems handle customer PII and financial data

## RECOMMENDATION
Begin phased migration to NIST post-quantum standards immediately.

## COST: $300K-650K over 36 months
## RISK OF INACTION: Potential data breach of ALL historically encrypted data

## NEXT STEP: Approve Phase 1 budget ($50-100K) for critical asset migration.
```

---

## Evidence to Capture

- [ ] Cryptographic inventory spreadsheet (200+ implementations)
- [ ] TLS scan results for all internal endpoints
- [ ] Code repository crypto usage report
- [ ] Hybrid PQC TLS configuration (Nginx + certificates)
- [ ] Wireshark capture of PQC TLS handshake
- [ ] Performance benchmark comparison (classical vs. PQC vs. hybrid)
- [ ] Migration roadmap document (phased plan with costs)
- [ ] Executive briefing (1-page PDF)
- [ ] Risk assessment matrix with HNDL analysis
- [ ] Vendor compatibility matrix

---

## Resume Bullets

### Version 1: Strategic Risk Management (CISO-Path)
> **Post-Quantum Cryptography Readiness Assessment**  
> - Led enterprise-wide cryptographic inventory identifying 200+ implementations across infrastructure, applications, and data stores, classifying 73% as quantum-vulnerable and establishing migration priorities based on data sensitivity and HNDL risk  
> - Developed 36-month phased PQC migration roadmap with $300-650K budget projections, enabling board-level decision-making on quantum risk and positioning organization 5+ years ahead of mandatory compliance deadlines  
> - Delivered executive briefing translating complex quantum computing threats into business risk language, securing Phase 1 budget approval for critical asset migration protecting customer PII and financial data

### Version 2: Technical Implementation (CISO-Path)
> **NIST Post-Quantum Cryptography Implementation**  
> - Deployed hybrid classical/PQC TLS configurations using ML-KEM-768 (Kyber) and ML-DSA-65 (Dilithium) on test infrastructure, benchmarking performance impact at <1ms additional latency per handshake with 462% key size increase  
> - Built automated cryptographic inventory scanner in Python analyzing TLS configurations, code repositories, and certificate stores across 50+ endpoints, reducing manual audit time from 2 weeks to 4 hours  
> - Created vendor compatibility matrix and migration dependency graph covering OpenSSL, cloud KMS providers, browsers, and Java runtimes, enabling engineering teams to plan PQC adoption with zero production disruption

### Version 3: Business Impact & Compliance (CISO-Path)
> **Quantum Risk Reduction & Compliance Program**  
> - Reduced organizational quantum computing risk exposure by 80% through proactive cryptographic assessment and hybrid PQC deployment on critical systems, addressing "harvest now, decrypt later" threats to long-lived sensitive data  
> - Established cryptographic governance framework including quarterly inventory audits, PQC readiness scoring, and vendor compliance requirements adopted as organizational standard across 3 business units  
> - Aligned migration roadmap with NIST SP 800-131A and emerging CNSA 2.0 requirements, ensuring regulatory compliance and avoiding estimated $2M+ in future emergency migration costs

---

## Interview Talking Points

### Question: "What is post-quantum cryptography and why should organizations care now?"

**STAR Answer:**

**Situation:**  
"Quantum computers capable of running Shor's algorithm will break RSA and ECC — the encryption protecting virtually all internet communications, financial transactions, and stored data. While large-scale quantum computers are estimated at 2030-2035, the threat is already active through 'harvest now, decrypt later' attacks."

**Task:**  
"I conducted a post-quantum cryptography readiness assessment to inventory our cryptographic exposure, test NIST PQC standards, and create a migration plan."

**Action:**  
"First, I built an automated scanner that audited TLS configurations across 50+ endpoints and scanned code repositories for cryptographic usage. This identified 200+ implementations, 73% quantum-vulnerable.

I then deployed a test environment with hybrid TLS — combining classical X25519 with ML-KEM-768 for key exchange — to measure real-world performance impact. The results showed <1ms additional latency, well within acceptable limits.

I created a phased 36-month migration roadmap prioritizing assets by data sensitivity and HNDL risk. Customer PII and financial systems were Phase 1, authentication and code signing Phase 2, internal communications Phase 3.

Finally, I delivered a one-page executive briefing translating quantum risk into business impact language."

**Result:**  
"The assessment reduced our quantum risk exposure by 80% and the migration roadmap was approved by leadership. We positioned the organization 5 years ahead of expected compliance mandates, avoiding an estimated $2M in emergency migration costs. The framework became the standard for quarterly cryptographic health assessments."

---

### Question: "How do you explain complex technical risks like quantum computing to non-technical executives?"

**Strong Answer:**  
"I use the analogy approach: 'Imagine every lock in your building uses the same key type. Someone has announced they're building a universal key-cutting machine that will be ready in 5-8 years. Do you wait until the machine exists, or start changing locks now?'

For quantum cryptography specifically, I focus on three points executives understand:
1. **Timeline:** 2030-2035 isn't far — migration takes 3+ years
2. **HNDL risk:** Data stolen today can be decrypted later — the threat is already active
3. **Cost of inaction vs. proaction:** $300K phased migration vs. $2M+ emergency response

I avoid technical jargon. Instead of 'Shor's algorithm breaks RSA-2048 factoring,' I say 'quantum computers will unlock all current encryption, including data that was encrypted years ago.' That gets attention."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA)
- [ ] OpenSSL PQC configuration and testing
- [ ] Hybrid TLS deployment (classical + PQC)
- [ ] Cryptographic inventory automation
- [ ] TLS scanning and auditing (SSLyze, testssl.sh)
- [ ] Performance benchmarking of cryptographic algorithms
- [ ] Certificate lifecycle management
- [ ] Code-level cryptographic analysis (semgrep, bandit)

**Frameworks:**
- [ ] NIST SP 800-131A (Cryptographic Standards)
- [ ] CNSA 2.0 (NSA quantum-resistant algorithm suite)
- [ ] HNDL threat model
- [ ] Cryptographic agility principles
- [ ] Risk-based migration planning

**Soft Skills:**
- [ ] Executive communication (translating technical risk)
- [ ] Budget estimation and business case development
- [ ] Strategic technology roadmapping
- [ ] Vendor assessment and compatibility analysis
- [ ] Cross-functional stakeholder management

---

## Common Mistakes to Avoid

1. **Waiting for quantum computers to arrive:** Migration takes 3+ years — start NOW
2. **Ignoring HNDL attacks:** Data encrypted today is already at risk
3. **Ripping out classical crypto:** Use HYBRID (classical + PQC) for transition
4. **Forgetting performance impact:** PQC keys are 4-5x larger — test bandwidth
5. **Skipping vendor compatibility:** Not all libraries support PQC yet — check first
6. **Not getting executive buy-in:** Frame as business risk, not technical problem

---

## Next Steps

1. **Move to Project 11:** Active Directory Attack & Defense Lab
2. **Certify:** Consider GIAC GCSA (Cloud Security Architecture) for crypto governance
3. **Monitor:** Track NIST PQC standard updates and vendor adoption
4. **Publish:** Write a blog on "PQC Migration: A Practical Guide for Security Teams"
5. **Expand:** Add cloud crypto scanning (AWS KMS, Azure Key Vault audit)

---

**Total Time Investment:** 25-35 hours over 2 weeks  
**Portfolio Artifacts:** Crypto inventory, hybrid TLS deployment, migration roadmap, executive briefing  
**Job Market Value:** PQC readiness is the #1 emerging CISO concern — having this on your resume signals strategic foresight

---

**This project proves you think like a CISO — anticipating threats years ahead, translating risk into business language, and building strategic roadmaps that protect the organization. That's executive-level security leadership.** 🚀🔒🔐
