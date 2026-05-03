# PRISM

**Pull-Request Integrated Security Mechanism**

> A CI/CD-native security framework that automates Software Bill of Materials (SBOM) generation, vulnerability analysis, and policy enforcement for every pull request.

---

## Overview

Modern software supply chains face increasing threats from vulnerable dependencies and malicious packages. Traditional security scans often occur post-merge, leaving critical vulnerabilities undetected until production. **PRISM** addresses this gap by integrating security checks directly into the pull request workflow.

This repository demonstrates **Objective 1** of the PRISM framework: automated SBOM generation triggered on every pull request.

### Key Features ✨

- ✅ **Multi-Ecosystem Support** - npm, Python, Go, Maven
- ✅ **Automatic Dependency Detection** - Detects and scans all supported ecosystems
- ✅ **Unified SBOM Generation** - Single CycloneDX SBOM with components from all languages
- ✅ **Vulnerability Scanning** - OSV database integration for all ecosystems
- ✅ **Smart Remediation** - Ecosystem-specific upgrade commands and suggestions
- ✅ **Policy Enforcement** - Block vulnerable PRs from merging
- ✅ **Inline PR Comments** - Specific fix suggestions for each vulnerability

---

## Multi-Ecosystem Support

The workflow now supports **4 major programming ecosystems** out of the box:

| Ecosystem | Files | Detection |
|-----------|-------|-----------|
| **npm** (Node.js) | `package.json`, `package-lock.json` | Automatic |
| **Python** | `requirements.txt`, `setup.py`, `pyproject.toml` | Automatic |
| **Go** | `go.mod`, `go.sum` | Automatic |
| **Maven** | `pom.xml` | Automatic |

The workflow automatically detects which ecosystems are present and:
1. Installs dependencies for each
2. Generates a unified SBOM with all components
3. Scans for vulnerabilities across all ecosystems
4. Posts targeted fix suggestions per ecosystem

### Demo Applications

Check the `application/` folder for sample applications:
- `nodejs-app/` - Node.js with npm dependencies
- `python-app/` - Python with pip dependencies
- `go-app/` - Go modules
- `maven-app/` - Java/Maven project

---

## Project Objectives

| # | Objective | Status |
|---|-----------|--------|
| 01 | Automate SBOM generation for every PR using GitHub Actions | ✅ Implemented |
| 02 | Develop autonomous vulnerability detection mapping SBOM to threat intelligence | 🔄 Phase 2 |
| 03 | Integrate policy-as-code gates with remediation suggestions | 🔄 Phase 3 |

---

## Objective 1: Automated SBOM Generation

When a developer opens, updates, or reopens a pull request, this workflow:

1. **Detects all ecosystems** (npm, Python, Go, Maven)
2. **Installs dependencies** for each supported ecosystem
3. **Generates a unified SBOM** using Syft (auto-detects all ecosystems)
4. **Scans for vulnerabilities** using OSV database
5. **Posts a summary comment** on the PR with findings
6. **Suggests inline fixes** for each vulnerable package with ecosystem-specific commands
7. **Blocks merge** if critical vulnerabilities are found

### Quick Start: Add Multi-Ecosystem Support

1. **Copy demo applications** (or add your own dependency files):
   ```bash
   cp -r application/nodejs-app .
   cp -r application/python-app .
   cp -r application/go-app .
   cp -r application/maven-app .
   ```

2. **Create a PR with dependencies**:
   ```bash
   git add .
   git commit -m "feat: Add multi-ecosystem dependencies"
   git push -u origin feature/multi-ecosystem
   ```

3. **Workflow runs automatically**:
   - Detects all 4 ecosystems
   - Generates SBOM with all components
   - Scans for vulnerabilities
   - Posts results in PR comments

4. **Review results**:
   - Check main comment for summary
   - Read inline suggestions for each vulnerable package
   - Follow ecosystem-specific upgrade instructions

### Example PR Comment

```markdown
## 🔐 PRISM Security Scan Results

✅ **Vulnerability Fix Available** (npm)
Upgrade `axios` from `1.4.0` to `1.6.0`

Fix command (npm):
npm install axios@1.6.0

---

✅ **Vulnerability Fix Available** (Python)  
Upgrade `requests` from `2.28.0` to `2.31.0`

Fix command (PyPI):
pip install requests==2.31.0
```

### Workflow Diagram (Multi-Ecosystem)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Developer   │────▶│  Pull Request│────▶│GitHub Action │────▶│    SBOM      │
│   Commits    │     │    Opened    │     │    Runs      │     │  Generated   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                      │
                                                                      ▼
                                                              ┌──────────────┐
                                                              │  PR Comment  │
                                                              │  + Artifact  │
                                                              └──────────────┘
```

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
sbom-repo/
├── .github/
│   └── workflows/
│       └── sbom.yml          # GitHub Actions workflow for SBOM generation
├── package.json              # Sample Node.js project with dependencies
└── README.md                 # Project documentation
```

---

## Usage

### Prerequisites

- GitHub repository with Actions enabled
- Project with a supported package manager (npm, pip, maven, etc.)

### Triggering the Workflow

1. Create a new branch and make changes
2. Open a Pull Request against `main`
3. The workflow triggers automatically
4. Check the PR comments for SBOM summary
5. Download the artifact from the Actions tab

### Viewing Artifacts

Navigate to **Actions** → Select the workflow run → **Artifacts** section → Download `sbom-pr-<number>`

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| CI/CD Platform | GitHub Actions |
| SBOM Generator | Anchore Syft |
| SBOM Format | CycloneDX JSON |
| Runtime | Ubuntu Latest |

---

## Future Phases

### Phase 2: Vulnerability Correlation (Objective 2)

- Parse generated SBOM and query OSV, NVD, and GitHub Advisory APIs
- Perform reachability analysis to filter non-exploitable vulnerabilities
- Calculate risk scores based on CVSS + exploitability

### Phase 3: Policy Gate Integration (Objective 3)

- Implement OPA/Rego or YAML-based policy rules
- Block PRs with critical reachable vulnerabilities
- Post remediation suggestions as PR comments
- Generate signed compliance artifacts

---

## Documentation

| Guide | Purpose |
|-------|---------|
| [**MULTI_ECOSYSTEM_GUIDE.md**](./MULTI_ECOSYSTEM_GUIDE.md) | Complete guide to multi-ecosystem support, features, and behavior |
| [**IMPLEMENTATION_GUIDE.md**](./IMPLEMENTATION_GUIDE.md) | Step-by-step setup guide for each ecosystem |
| [**TESTING_GUIDE.md**](./TESTING_GUIDE.md) | How to verify and test the setup locally |

### Quick Links

- 🚀 **New to PRISM?** Start with [MULTI_ECOSYSTEM_GUIDE.md](./MULTI_ECOSYSTEM_GUIDE.md)
- 🔧 **Setting up?** Follow [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md)  
- 🧪 **Testing?** Use [TESTING_GUIDE.md](./TESTING_GUIDE.md)
- ✅ **Verifying setup?** Run `python verify_ecosystems.py`

---

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/page/software-bill-materials)
- [Anchore Syft](https://github.com/anchore/syft)
- [OWASP Dependency-Track](https://dependencytrack.org/)

---

## Team

**Department of Computer Science & Engineering (Cyber Security)**  
Ramaiah Institute of Technology

| Name | USN |
|------|-----|
| Aadarsh G K | 1MS22CY001 |
| Divith V | 1MS22CY023 |
| Sidrah Saif | 1MS22CY067 |

**Guide:** Dr. Siddesh G.M., Professor and Head, Dept. of CSE (Cyber Security)

---

## License

This project is part of an academic major project for demonstration purposes.

---

<p align="center">
  <sub>Built with 🔒 for secure software supply chains</sub>
</p>
