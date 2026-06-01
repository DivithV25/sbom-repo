# PRISM

**Pull-Request Integrated Security Mechanism**

> An automated security platform that generates Software Bills of Materials (SBOMs), detects vulnerabilities across 4+ package ecosystems, enforces policy-as-code gates, and provides AI-powered remediation recommendations on every pull request.

---

## Overview

Modern software supply chains face increasing threats from vulnerable dependencies and malicious packages. **PRISM** integrates comprehensive security checks directly into the pull request workflow, enabling developers to identify and remediate vulnerabilities **before they reach production**.

PRISM automates the entire security pipeline:
- 🔍 **SBOM Generation** — CycloneDX SBOMs for npm, PyPI, Maven, and Go
- 🚨 **Vulnerability Detection** — OSV integration with CVSS risk scoring
- 🚫 **Policy Enforcement** — Severity-based gates and blocked package rules
- 🤖 **AI Remediation** — OpenAI-powered fix suggestions with safe version recommendations

---

## Key Features

| Feature | Details |
|---------|---------|
| **Multi-Ecosystem Scanning** | npm, PyPI, Maven, Go modules in one scan |
| **Real-time Threat Intelligence** | OSV (Open Source Vulnerabilities) API integration |
| **Risk Scoring** | 0-10 scale with CVSS severity mapping |
| **Policy-as-Code** | YAML-defined severity thresholds and blocked packages |
| **Automated Remediation** | AI suggestions for safe versions and upgrade paths |
| **PR Integration** | Inline comments on vulnerable dependencies with blocking reviews |
| **Decision Tracking** | JSON reports with PASS/WARN/FAIL decisions |

---

## Objective 1: Automated SBOM Generation

### What It Does

When a developer opens or updates a pull request:

1. **Checkout code** and discover all dependencies (npm, PyPI, Maven, Go)
2. **Generate CycloneDX SBOM** via Anchore Syft (excludes PRISM itself via `.syftignore`)
3. **Query OSV API** for each dependency and its transitive packages
4. **Calculate risk scores** based on CVSS and vulnerability count
5. **Apply policy gates** (severity thresholds, blocked packages)
6. **Post PR comment** with decision (PASS/WARN/FAIL) and remediation suggestions
7. **Block merge** if decision is FAIL (requires override or vulnerability fix)

### Workflow Diagram

```
Code Push
    ↓
GitHub Actions Triggered
    ↓
Dependencies Discovered (npm/pip/maven/go)
    ↓
SBOM Generated (CycloneDX)
    ↓
OSV Vulnerability Query
    ↓
Risk Scoring (CVSS mapping)
    ↓
Policy Check (severity thresholds + blocked packages)
    ↓
AI Remediation (OpenAI suggestions)
    ↓
PR Comment + Decision (PASS/WARN/FAIL)
```

---

## Objectives Status

| # | Objective | Status |
|---|-----------|--------|
| 01 | SBOM generation for every PR | ✅ Complete |
| 02 | Vulnerability detection via threat intelligence | ✅ Complete |
| 03 | Policy gates + AI-powered remediation | ✅ Complete |

### SBOM Format

The generated SBOM follows the **CycloneDX v1.4+** specification, an OWASP standard that includes:

- Component names, versions, and package URLs (purl)
- Dependency tree with transitive dependencies
- License information
- Cryptographic hashes (SHA-256, SHA-512)

Example component entry:
```json
{
  "type": "library",
  "bom-ref": "pkg:npm/left-pad@1.3.0",
  "name": "left-pad",
  "version": "1.3.0",
  "purl": "pkg:npm/left-pad@1.3.0",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

---

## Repository Structure

```
sbom-repo/                     # PRISM GitHub Action
├── .github/
│   └── workflows/
│       └── sbom.yml           # Auto-triggered workflow for every PR
├── .syftignore                # Excludes prism/ from SBOM scanning
├── .gitignore
├── .gitattributes
├── README.md                  # This file
├── application/               # Sample project for testing
│   ├── package.json           # npm dependencies
│   ├── requirements.txt        # Python dependencies
│   ├── pom.xml                # Maven dependencies
│   └── go.mod                 # Go dependencies
└── prism/                     # PRISM tool (production code)
    ├── requirements.txt       # Python dependencies (installed by workflow)
    ├── agent/                 # Core scanning engine
    │   ├── main.py
    │   ├── sbom_parser.py
    │   ├── osv_client.py
    │   ├── risk_engine.py
    │   ├── policy_engine.py
    │   ├── remediation_advisor.py
    │   └── reporter.py
    ├── config/
    │   └── prism_config.yaml
    ├── policies/              # Default policy definitions
    │   └── default_policy.yaml
    ├── rules/                 # Blocked packages list
    │   └── blocked_packages.yaml
    ├── tests/                 # Test suite
    ├── docs/                  # Detailed documentation
    └── output/                # Generated reports
```

---

## Quick Start

### For Your Repository

1. **Clone or fork this repository**
   ```bash
   git clone https://github.com/yourusername/sbom-repo.git
   cd sbom-repo
   ```

2. **Add your code** (any structure—npm, Python, Maven, Go, or mixed)
   - PRISM automatically detects all package managers

3. **Create a PR**
   - Workflow triggers automatically
   - SBOM generated → Vulnerabilities detected → Policy checked → Decision posted

4. **Review the PR comment**
   - ✅ PASS — No vulnerabilities (or acceptable risk)
   - ⚠️ WARN — Medium severity found (informational)
   - ❌ FAIL — Critical/High severity or blocked packages (blocks merge)

### For Using PRISM in Another Repo

Add to your `.github/workflows/security.yml`:

```yaml
name: PRISM Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: username/sbom-repo@v1
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Then configure with GitHub Secrets:
- `OPENAI_API_KEY` — For AI remediation suggestions

---

## Ecosystem Support

| Ecosystem | Package Manager | Detection | Dependencies |
|-----------|-----------------|-----------|--------------|
| **Node.js** | npm | `package.json`, `package-lock.json` | ✅ Direct + Transitive |
| **Python** | pip | `requirements.txt`, `Pipfile` | ✅ Direct + Transitive |
| **Java** | Maven | `pom.xml` | ✅ Direct + Transitive |
| **Go** | go mod | `go.mod`, `go.sum` | ✅ Direct + Transitive |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **CI/CD** | GitHub Actions |
| **SBOM Generator** | Anchore Syft v1.42.3+ |
| **SBOM Format** | CycloneDX JSON (OWASP standard) |
| **Threat Intel** | OSV (Open Source Vulnerabilities) API |
| **Risk Scoring** | CVSS v3.0/3.1 mapping |
| **Policy Engine** | YAML-based rules (custom) |
| **AI Remediation** | OpenAI GPT-4 API |
| **Language** | Python 3.12 |
| **Runtime** | Ubuntu Latest (GitHub Actions) |

---

## How It Works

### 1. SBOM Generation
- **Tool:** Anchore Syft
- **Coverage:** npm, pip, maven, go ecosystems
- **Output:** CycloneDX JSON with all components

### 2. Vulnerability Detection
- **Source:** OSV (Open Source Vulnerabilities)
- **Process:** Query each component against OSV database
- **Data:** CVE IDs, severity, attack vectors, exploitability

### 3. Risk Scoring
- **Formula:** Aggregate CVSS scores from all vulnerabilities
- **Scale:** 0-10 (0.0=UNKNOWN, 0.1-3.9=LOW, 4.0-6.9=MEDIUM, 7.0-8.9=HIGH, 9.0-10.0=CRITICAL)
- **Logic:** Higher risk if multiple critical vulnerabilities in same component

### 4. Policy Gates
- **Severity Thresholds:** Customizable (default: FAIL on CRITICAL/HIGH)
- **Blocked Packages:** YAML list of package names that auto-FAIL regardless of CVSS
- **Decision:** PASS / WARN / FAIL

### 5. AI Remediation
- **Model:** OpenAI GPT-4 (gpt-4o-mini for cost optimization)
- **Suggestions:** Safe version recommendations, upgrade paths, testing strategies
- **Output:** Inline PR comments with specific fixes

### 6. Decision & Reporting
- **PR Comment:** Human-readable summary with vulnerability details
- **JSON Report:** Structured `decision.json` for automation
- **Blocking Review:** Auto-blocks merge if FAIL decision (overridable)
- **Artifacts:** SBOM and reports uploaded to GitHub

---

## Configuration

### Policy Configuration

Edit `prism/policies/default_policy.yaml`:

```yaml
fail_on:
  - CRITICAL
  - HIGH
warn_on:
  - MEDIUM
info_on:
  - LOW
```

### Blocked Packages

Edit `prism/rules/blocked_packages.yaml`:

```yaml
blocked_packages:
  - requests            # Block all versions
  - openssl
  - log4j-core
  - yaml
```

When a blocked package is detected, PRISM forces a FAIL decision regardless of CVSS score.

---

## Example Output

### PR Comment on Vulnerability Detection

```
🔐 PRISM SECURITY SCAN REPORT

📊 SBOM Summary:
  • Total Components: 25
  • Direct Dependencies: 8
  • Transitive Dependencies: 17
  • Ecosystems Scanned: npm, pip, maven, go

🚨 Vulnerability Summary:
  • CRITICAL: 1
  • HIGH: 2
  • MEDIUM: 3
  • LOW: 0
  • UNKNOWN: 1

📋 Details:
  - requests@2.28.0 (Python) - BLOCKED PACKAGE
    └─ Decision: FAIL

  - lodash@4.17.15 (JavaScript) - HIGH SEVERITY
    └─ CVE-2021-23337: Prototype Pollution
    └─ Suggested Fix: Upgrade to lodash@4.17.21

🤖 AI Remediation Suggestions:
  - requests: Cannot upgrade (blocked package policy)
  - lodash: Safe to upgrade from 4.17.15 → 4.17.21
    └─ No breaking changes expected
    └─ No additional dependencies introduced

✅ Decision: FAIL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Reason: Blocked package detected (requests)
Action: Fix blocked packages before merge
```

---

## Troubleshooting

### Workflow Fails on `pip install -r prism/requirements.txt`

**Solution:** Ensure your GitHub Actions runner has internet access and Python 3.12 is installed (handled by workflow).

### SBOM is Empty or Missing Components

**Check:**
1. Do your dependency files exist? (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`)
2. Are they in your PR branch?
3. Are they excluded by `.syftignore`? (Should only exclude `prism/`)

### AI Remediation Suggestions Not Appearing

**Add GitHub Secret:**
1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Add `OPENAI_API_KEY` with your OpenAI API key

---

## References

- [CycloneDX Specification](https://cyclonedx.org/)
- [OSV Database](https://osv.dev/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [Anchore Syft](https://github.com/anchore/syft)
- [OWASP SBOM Best Practices](https://owasp.org/www-community/Software_Bill_of_Materials_(SBOM))

---

## License

MIT License - This project is provided as-is for educational and commercial use.

---

## Contributing

Contributions welcome! Please submit issues and pull requests.

---

## Academic Context

**Original Development:** Department of Computer Science & Engineering (Cyber Security)
Ramaiah Institute of Technology

| Developers | USN |
|------------|-----|
| Aadarsh G K | 1MS22CY001 |
| Divith V | 1MS22CY023 |
| Sidrah Saif | 1MS22CY067 |

**Faculty Guide:** Dr. Siddesh G.M., Professor and Head, Dept. of CSE (Cyber Security)

**Current Status:** Production-ready, awaiting IEEE publication clearance for Marketplace listing.

---

<p align="center">
  <sub>Built with 🔒 for secure software supply chains</sub>
</p>
