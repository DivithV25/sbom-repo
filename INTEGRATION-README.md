# Integration Branch - PRISM Security Scan

This branch (`integration-sid`) combines the SBOM generation (from `main`) with the vulnerability scanning agent (from `Aadarsh`).

## What This Branch Does

When a Pull Request is opened, synchronized, or reopened:

1. **Generates SBOM** - Creates a CycloneDX JSON SBOM using Anchore Syft
2. **Scans for Vulnerabilities** - Queries OSV API for known vulnerabilities
3. **Calculates Risk Score** - Computes CVSS scores and severity levels
4. **Applies Policy Gates** - PASS/FAIL decision based on severity thresholds
5. **Posts PR Comment** - Automated security report as a PR comment
6. **Uploads Artifacts** - SBOM and vulnerability reports for download

## Workflow Execution

### Automated (on GitHub)
```
Pull Request Created/Updated
    ↓
GitHub Actions Triggered
    ↓
1. Checkout code
2. Install npm dependencies
3. Generate SBOM (sbom.json)
4. Set up Python
5. Install Python deps (requests, pyyaml)
6. Run vulnerability scanner
7. Display results in workflow logs
8. Upload artifacts (SBOM + reports)
9. Post comment on PR
```

### Manual Testing (Local)

**Test with sample SBOMs:**
```bash
# Test with clean package (should PASS)
python -m agent.main samples/sample_sbom.json

# Test with vulnerable package (should FAIL)
python -m agent.main samples/fail_sbom.json
```

**Test with custom output directory:**
```bash
python -m agent.main samples/fail_sbom.json --output my-test-output
```

**Test with blocked package rules:**
```bash
python -m agent.main samples/sample_sbom.json rules/blocked_packages.yaml
```

## Viewing Results

### In VS Code Terminal (Local Testing)
When you run the scanner locally, you'll see the markdown report directly in your terminal:
```
## 🔐 Safe PR Agent Report

**Decision:** ❌ FAIL  
**Overall Severity:** HIGH  
**Max CVSS:** 7.5  
**Total Vulnerabilities:** 3  

---

### 🚨 Vulnerable Components

- lodash@4.17.20
  - GHSA-29mw-wpgm-hmr9 (CVSS: 7.5)
  - GHSA-35jh-r3h4-6jhm (CVSS: 7.5)
  - GHSA-xxjr-mmjv-4gpg (CVSS: 7.5)

---

### 🛡️ Policy Result
Severity threshold exceeded
```

### In GitHub Actions (PR Workflow)
1. **Workflow Logs**: Go to Actions tab → Select the workflow run → View "Display Vulnerability Report" step
2. **PR Comment**: Automated comment will be posted on the PR with full report
3. **Artifacts**: Download SBOM and vulnerability reports from the workflow run

## Architecture

```
┌─────────────────┐
│  Pull Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│     GitHub Actions Workflow             │
│                                         │
│  ┌──────────────────────────────────┐  │
│  │  1. Generate SBOM (Syft)         │  │
│  └──────────┬───────────────────────┘  │
│             │                           │
│             ▼                           │
│  ┌──────────────────────────────────┐  │
│  │  2. Vulnerability Scanner        │  │
│  │     - Parse SBOM                 │  │
│  │     - Query OSV API              │  │
│  │     - Calculate Risk             │  │
│  │     - Apply Policy               │  │
│  └──────────┬───────────────────────┘  │
│             │                           │
│             ▼                           │
│  ┌──────────────────────────────────┐  │
│  │  3. Generate Reports             │  │
│  │     - pr_comment.md              │  │
│  │     - report.json                │  │
│  └──────────┬───────────────────────┘  │
│             │                           │
└─────────────┼───────────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │  PR Comment Posted  │
    │  Artifacts Uploaded │
    └─────────────────────┘
```

## Components

### From `main` Branch:
- `.github/workflows/sbom.yml` - GitHub Actions workflow
- `package.json` - Sample Node.js project
- `README.md` - Project documentation

### From `Aadarsh` Branch:
- `agent/` - Vulnerability scanning agent
  - `main.py` - CLI orchestrator
  - `sbom_parser.py` - SBOM parser
  - `osv_client.py` - OSV API client
  - `risk_engine.py` - Risk calculator
  - `policy_engine.py` - Policy evaluator
  - `reporter.py` - Report generator
  - `utils.py` - Helper functions
- `rules/` - Policy rules
- `samples/` - Test SBOMs
- `requirements.txt` - Python dependencies

### New Integration:
- Enhanced workflow with Python setup and scanner execution
- Automated PR commenting
- Artifact uploads for both SBOM and vulnerability reports

## Policy Rules

Current policy gates:
1. **Blocked Packages** - Immediate FAIL if package is in blocklist (see `rules/blocked_packages.yaml`)
2. **Severity Threshold** - FAIL if CRITICAL or HIGH severity vulnerabilities found

## Testing the Integration

### To test locally:
```bash
# Install Python dependencies
pip install -r requirements.txt

# Run scanner on test SBOM
python -m agent.main samples/fail_sbom.json
```

### To test on GitHub:
1. Push this branch to GitHub: `git push origin integration-sid`
2. Create a Pull Request from `integration-sid` to `main`
3. Watch the workflow run in the Actions tab
4. Check for the automated comment on the PR
5. Download artifacts from the workflow run

## Expected Output

### PASS Scenario (No vulnerabilities):
- **Decision**: ✅ PASS
- **Action**: PR can be merged
- **Comment**: Shows clean bill of health

### FAIL Scenario (Vulnerabilities detected):
- **Decision**: ❌ FAIL
- **Action**: PR should not be merged until fixed
- **Comment**: Lists all vulnerabilities with CVSS scores
- **Remediation**: Developer should upgrade vulnerable packages

## Next Steps

1. ✅ SBOM Generation - Complete
2. ✅ Vulnerability Detection - Complete
3. 🔄 Enhancement Opportunities:
   - Add reachability analysis (filter unused dependencies)
   - Multi-feed correlation (NVD, GitHub Advisory, CISA KEV)
   - Remediation suggestions (recommended version upgrades)
   - License compliance checks
   - Dependency age/freshness analysis

## Notes

- The workflow runs on Ubuntu latest with Python 3.12
- OSV API queries may take 10-30 seconds depending on component count
- Rate limits: OSV API has no strict rate limit for reasonable usage
- Failed scans will still upload artifacts for debugging
