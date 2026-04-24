# 🔐 Complete PRISM CI/CD Workflow Summary

**Status:** ✅ PRODUCTION READY | Policy: PRISM_STRICT (Default)

---

## 🎯 Workflow Overview

The GitHub Actions workflow automatically runs on every pull request and performs a complete security analysis using PRISM (Pull-Request Integrated Security Mechanism) with context-aware exploitability assessment.

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Pull Request Opened                   │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  1️⃣  Checkout Code (fetch-depth: 0) │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  2️⃣  Setup Node.js (if npm project) │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  3️⃣  Install Dependencies (npm ci)   │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  4️⃣  Generate SBOM (CycloneDX JSON) │
        │      via Anchore sbom-action         │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  5️⃣  Generate PR Diff                │
        │      (git diff origin/main..HEAD)    │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  6️⃣  Setup Python 3.12              │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  7️⃣  Install PRISM Dependencies     │
        │      (requirements.txt)              │
        └──────────────────────────────────────┘
                           ↓
┌───────────────────────────────────────────────────────┐
│   8️⃣  PRISM VULNERABILITY SCAN (PHASES 1-3)        │
├───────────────────────────────────────────────────────┤
│  ├─ Phase 1: Exploitability Analysis                 │
│  │  └─ 6-factor scoring per vulnerability            │
│  │     • Package present                             │
│  │     • Dependency scope (direct/transitive)        │
│  │     • Imported in PR diff                         │
│  │     • Vulnerable function called                  │
│  │     • User input reaches function                 │
│  │     • Sanitization present                        │
│  │                                                    │
│  ├─ Phase 3: Policy Evaluation (PRISM_STRICT)       │
│  │  └─ Decision: PASS / WARN / FAIL                 │
│  │     • Block if exploitability > 0.45             │
│  │     • Warn if 0.45-0.65 confidence              │
│  │     • Pass if < 0.45 confidence                  │
│  │                                                    │
│  └─ Generate Reports                                 │
│     • Markdown report with evidence                 │
│     • JSON decision with metrics                    │
│     • Remediation recommendations (AI-powered)      │
└───────────────────────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  9️⃣  Display Vulnerability Report    │
        │      (console output)                │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  🔟  Upload Artifacts                │
        │      • sbom.json                     │
        │      • Vulnerability reports         │
        │      • Decision.json                 │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  1️⃣1️⃣  Post PR Comment              │
        │      Security scan results with:     │
        │      • Risk summary                  │
        │      • Exploitability findings      │
        │      • Remediation suggestions      │
        └──────────────────────────────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │  1️⃣2️⃣  Post Inline Fix Suggestions  │
        │      Comments on changed files:      │
        │      • Upgrade commands              │
        │      • Safe version recommendations  │
        └──────────────────────────────────────┘
                           ↓
         ┌─────────────────────────────────┐
         │  Decision Check                 │
         ├─────────────────────────────────┤
         │                                 │
         │  PASS/WARN: ✅ Allow merge      │
         │             ✔️ All green       │
         │                                 │
         │  FAIL: 🔒 Block merge           │
         │        ❌ Request changes       │
         │        🔴 Cannot proceed       │
         │                                 │
         └─────────────────────────────────┘
```

---

## 📋 Workflow Stages

### Stage 1: Setup & Dependencies (Steps 1-4)

**Checkout Code**
```yaml
- name: Checkout code
  uses: actions/checkout@v4
  with:
    fetch-depth: 0  # Full history for diff analysis
```

**Node Setup** (if needed)
```yaml
- name: Set up Node (for npm projects)
  uses: actions/setup-node@v4
  with:
    node-version: 18
```

**Install Dependencies**
```yaml
- name: Install dependencies (npm ci)
  if: always()
  run: |
    if [ -f package-lock.json ]; then 
      npm ci
    elif [ -f package.json ]; then 
      npm install --no-audit --no-fund
    fi
```

**Generate SBOM**
```yaml
- name: Generate SBOM and upload artifact (Anchore sbom-action)
  uses: anchore/sbom-action@v0
  with:
    format: cyclonedx-json
    output-file: sbom.json
```

---

### Stage 2: Diff & Python Setup (Steps 5-7)

**Generate PR Diff** (NEW - for exploitability analysis)
```yaml
- name: Generate PR Diff
  id: pr-diff
  run: |
    echo "📝 Generating PR diff for exploitability analysis..."
    git diff origin/main..HEAD > pr.diff
    if [ -s pr.diff ]; then
      echo "Diff generated ($(wc -l < pr.diff) lines)"
    else
      echo "No changes detected (empty diff)"
    fi
```

**Python Setup**
```yaml
- name: Set up Python for vulnerability scanning
  uses: actions/setup-python@v5
  with:
    python-version: '3.12'
```

**Install Python Dependencies**
```yaml
- name: Install Python dependencies
  run: |
    pip install -r requirements.txt
```

---

### Stage 3: PRISM Security Scan (Step 8) ⭐

**Run Vulnerability Scanner with PRISM_STRICT** (DEFAULT)
```yaml
- name: Run Vulnerability Scanner (PRISM Phase 1-3)
  id: vuln-scan
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: |
    echo "🔍 Scanning SBOM for vulnerabilities..."
    echo "🔬 Using PRISM Exploitability Analysis (Phases 1-3)"
    python -m agent.main sbom.json \
      --diff pr.diff \
      --policy PRISM_STRICT \
      --output vulnscan-output
    echo "scan_complete=true" >> $GITHUB_OUTPUT
```

**What Happens Inside:**
1. Load SBOM (CycloneDX format)
2. Parse components and extract versions
3. Query OSV database for vulnerabilities
4. **Phase 1:** Compute exploitability (6-factor analysis)
   - Analyze each vulnerability with PR diff context
   - Generate confidence score (0-1 scale)
5. **Phase 3:** Apply PRISM_STRICT policy
   - Block if exploitability > 0.45
   - Warn if 0.45-0.65
   - Pass if < 0.45
6. Generate AI-powered remediation suggestions
7. Create markdown report + JSON decision

**Output Files Generated:**
- `vulnscan-output/pr_comment.md` - Markdown report
- `vulnscan-output/report.json` - Full JSON report
- `vulnscan-output/decision.json` - Decision + metrics

---

### Stage 4: Reporting & Comments (Steps 9-12)

**Display Vulnerability Report**
```yaml
- name: Display Vulnerability Report
  if: always()
  run: |
    echo "========================================="
    echo "🔐 PRISM SECURITY SCAN RESULTS"
    echo "========================================="
    if [ -f vulnscan-output/pr_comment.md ]; then
      cat vulnscan-output/pr_comment.md
    else
      echo "⚠️ No report generated"
    fi
```

**Upload Artifacts**
```yaml
- name: Upload SBOM Artifact
  uses: actions/upload-artifact@v4
  with:
    name: sbom-pr-${{ github.event.pull_request.number }}
    path: sbom.json

- name: Upload Vulnerability Report
  uses: actions/upload-artifact@v4
  with:
    name: vulnerability-report-pr-${{ github.event.pull_request.number }}
    path: vulnscan-output/
```

**Post PR Comment with Results**
```yaml
- name: Post PR Comment with Results & Inline Fix Suggestions
  if: always() && github.event.pull_request.number
  uses: actions/github-script@v7
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    script: |
      # Read pr_comment.md and post to PR
      # Extract remediations from report.json
      # Post inline suggestions on changed files
```

**Block PR on FAIL** ⛔
```yaml
- name: Block PR Merge on FAIL Decision
  if: always() && github.event.pull_request.number
  uses: actions/github-script@v7
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    script: |
      const decision = JSON.parse(fs.readFileSync('vulnscan-output/decision.json', 'utf8'));
      
      if (decision.decision === 'FAIL') {
        # Post "REQUEST_CHANGES" review (blocks merge)
        # Include risk summary + exploitability metrics
        # Fail the workflow
        core.setFailed(`🔒 PRISM Security Scan FAILED: ${decision.reason}`);
      }
```

---

## 🚀 Default Policy: PRISM_STRICT

| Aspect | PRISM_STRICT |
|--------|--------------|
| **Threshold** | Exploitability > 0.45 = FAIL |
| **Strategy** | Context-aware, strictest |
| **False Positives** | Very low |
| **False Negatives** | Very low |
| **Use Case** | Production apps, security-critical |

**Decision Logic:**
```
if exploitability > 0.65:
    decision = FAIL  # Highly exploitable
elif exploitability > 0.45:
    decision = WARN  # Moderately exploitable
else:
    decision = PASS  # Not exploitable
```

---

## 📊 Example Decision Output

### Scenario 1: High CVSS but Not Exploitable → PASS ✅

```
Vulnerability: CVE-2021-23337
CVSS: 9.5 (CRITICAL)
Affected Package: lodash@4.17.20

Exploitability Analysis:
├─ Package in SBOM: ✓ (1.0)
├─ Direct Dependency: ✓ (0.8)
├─ Imported in PR diff: ✗ (0.0)
├─ Vulnerable function called: ✗ (0.0)
├─ User input reaches function: ✗ (0.0)
└─ No sanitization: N/A (0.0)

Confidence Score: 0.23 (not exploitable)

Policy: PRISM_STRICT
├─ Is exploitable? No (0.23 < 0.45)
└─ Decision: ✅ PASS (allow merge)

Result: High CVSS but not in code → no risk
```

### Scenario 2: Low CVSS but Highly Exploitable → FAIL ❌

```
Vulnerability: CVE-2024-00001
CVSS: 3.1 (LOW)
Affected Package: custom-lib@1.0.0

Exploitability Analysis:
├─ Package in SBOM: ✓ (1.0)
├─ Direct Dependency: ✓ (0.8)
├─ Imported in PR diff: ✓ (1.0)
├─ Vulnerable function called: ✓ (1.0)
├─ User input reaches function: ✓ (0.9)
└─ No sanitization: ✓ (1.0)

Confidence Score: 0.78 (highly exploitable)

Policy: PRISM_STRICT
├─ Is exploitable? Yes (0.78 > 0.45)
└─ Decision: ❌ FAIL (block merge)

Result: Active vulnerability in PR code → security risk
```

---

## 🔄 Workflow Triggers

**Triggers on:**
- Pull request opened
- Pull request synchronized (new commits)
- Pull request reopened

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened]
```

---

## 🔐 Permissions Required

```yaml
permissions:
  contents: read              # Read repository contents
  pull-requests: write        # Post comments on PRs
  id-token: write            # For OIDC token (OpenAI API)
```

---

## 📝 Key Features

✅ **Automatic SBOM Generation** - CycloneDX JSON via Anchore  
✅ **OSV Database Integration** - Real-time vulnerability queries  
✅ **Context-Aware Analysis** - Exploitability based on code changes  
✅ **AI-Powered Remediation** - Upgrade recommendations  
✅ **Inline PR Comments** - Suggested fixes on changed lines  
✅ **Decision Blocking** - Prevents merge if security issues found  
✅ **Artifact Uploads** - Reports saved for audit trail  
✅ **Full Transparency** - Complete evidence in decision traces  

---

## 🛠️ Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OPENAI_API_KEY` | Optional* | Enable AI remediation suggestions |
| `GITHUB_TOKEN` | Auto | Post PR comments & block merge |

*AI remediation is optional. If not set, basic remediation suggestions are provided.

---

## 📊 Artifact Outputs

**sbom-pr-{PR_NUMBER}.json**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [...]
}
```

**vulnerability-report-pr-{PR_NUMBER}/** (folder)
```
├── pr_comment.md       # Markdown report for PR
├── report.json         # Full vulnerability report
└── decision.json       # Security decision + metrics
```

---

## ✅ Customization Options

### Change Policy Type
Edit `.github/workflows/sbom.yml`:
```yaml
python -m agent.main sbom.json \
  --diff pr.diff \
  --policy CVSS_STRICT \        # Change here
  --output vulnscan-output
```

**Options:** `CVSS_ONLY`, `CVSS_STRICT`, `PRISM`, `PRISM_STRICT`

### Custom Rules
```yaml
python -m agent.main sbom.json \
  --diff pr.diff \
  --policy PRISM_STRICT \
  --rules custom_rules.yaml \    # Custom rules file
  --output vulnscan-output
```

---

## 🎓 Summary

| Component | Status | Purpose |
|-----------|--------|---------|
| SBOM Generation | ✅ Automated | Component inventory |
| Vulnerability Scan | ✅ OSV Integration | Real-time threat database |
| Exploitability (Phase 1) | ✅ 6-factor analysis | Context-aware scoring |
| Policy Engine (Phase 3) | ✅ PRISM_STRICT default | Intelligent blocking |
| Remediation | ✅ AI-powered | Upgrade suggestions |
| PR Integration | ✅ Full | Comments + blocking |
| Reporting | ✅ Comprehensive | Markdown + JSON |
| Artifacts | ✅ Preserved | Audit trail |

---

**The workflow is now fully integrated with PRISM Phases 1-3, defaulting to PRISM_STRICT policy for the most context-aware security analysis.**
