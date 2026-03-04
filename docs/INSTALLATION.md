# PRISM Installation & Setup Guide

Complete guide to installing and configuring PRISM for your project.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Feature-Specific Setup](#feature-specific-setup)
4. [Configuration](#configuration)
5. [Troubleshooting](#troubleshooting)
6. [Verification](#verification)

---

## System Requirements

### Minimum Requirements

- **Python:** 3.9 or higher
- **OS:** Windows, macOS, Linux
- **RAM:** 2 GB minimum, 4 GB recommended
- **Disk Space:** 500 MB (for dependencies)

### Optional Requirements

For advanced features:

- **Docker:** 20.10+ (for OPA server)
- **OpenAI API Key:** For AI-powered remediation
- **Git:** For version control of policies

---

## Quick Installation

### 1. Clone Repository

```bash
# Clone PRISM
git clone https://github.com/YOUR_ORG/sbom-repo.git
cd sbom-repo
```

### 2. Install Python Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Or with virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Dependencies Installed:**
- `requests` - API calls to vulnerability databases
- `pyyaml` - Configuration file parsing
- `openai` - GPT-4 integration (optional)

### 3. Verify Installation

```bash
# Test basic scan
python agent/main.py samples/sample_sbom.json

# Expected output:
# ✅ Loaded 10 components from SBOM
# ✅ Found 3 vulnerabilities
# ✅ Report generated: output/report.json
```

---

## Feature-Specific Setup

### 1. Level 2 Reachability (Import/Call Graph Analysis)

**No additional setup required!** Works out of the box.

**Usage:**
```bash
python agent/main.py samples/sample_sbom.json \
  --project-root /path/to/your/source/code
```

**Supported Languages:**
- ✅ JavaScript (ES6, CommonJS)
- ✅ TypeScript
- ✅ Python

**Verification:**
```bash
# Test import graph analyzer
python agent/import_graph_analyzer.py lodash /path/to/project javascript

# Expected output:
# Is Imported: True/False
# Usage Count: X
# Confidence: 0.0 - 1.0
```

---

### 2. AI-Powered Remediation

**Setup Steps:**

#### Step 1: Get OpenAI API Key

1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up / Log in
3. Navigate to **API Keys**
4. Click **Create new secret key**
5. Copy the key (starts with `sk-...`)

#### Step 2: Set Environment Variable

**Linux/macOS:**
```bash
export OPENAI_API_KEY="sk-your-actual-key-here"

# Make it permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export OPENAI_API_KEY="sk-your-actual-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-actual-key-here"

# Make it permanent (user environment variable)
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-your-actual-key-here", "User")
```

**Windows (Command Prompt):**
```cmd
set OPENAI_API_KEY=sk-your-actual-key-here

# Make it permanent
setx OPENAI_API_KEY "sk-your-actual-key-here"
```

#### Step 3: Enable in Configuration

Edit `config/prism_config.yaml`:
```yaml
ai:
  enabled: true

  openai:
    model: "gpt-4"  # or "gpt-3.5-turbo" for lower cost
    temperature: 0.3
    max_tokens: 2000
```

#### Step 4: Test AI Features

```bash
python agent/main.py samples/sample_sbom.json \
  --ai \
  --project-root /path/to/your/code

# Expected output:
# 🤖 AI-POWERED ANALYSIS
# Impact Analysis: ...
# Remediation Plan: ...
```

**Cost Estimation:**
- GPT-4: ~$0.03 per vulnerability analyzed
- GPT-3.5-Turbo: ~$0.002 per vulnerability (15x cheaper)
- Average project (50 components): ~$0.50 with GPT-3.5

**Fallback Behavior:**
If API key not set or OpenAI unavailable, PRISM falls back to basic remediation advisor (no AI).

---

### 3. OPA/Rego Policy Engine

**Setup Options:**

#### Option A: Docker (Recommended)

**Step 1: Install Docker**

- **Windows:** [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- **macOS:** [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
- **Linux:** `sudo apt-get install docker.io docker-compose`

**Step 2: Start OPA Server**

```bash
# Start OPA server (from sbom-repo directory)
docker-compose up -d opa

# Verify OPA is running
curl http://localhost:8181/health

# Expected output:
# {"status": "ok"}
```

**Step 3: Test Policy Evaluation**

```bash
# Test with sample input
curl -X POST http://localhost:8181/v1/data/prism/allow \
  -H "Content-Type: application/json" \
  -d @test/opa_test_input.json

# Expected output:
# {"result": {"decision": "FAIL", "reason": "...", ...}}
```

#### Option B: Native OPA Binary (No Docker)

**Step 1: Download OPA**

**Linux:**
```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
```

**macOS:**
```bash
brew install opa
# Or manually:
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
```

**Windows:**
```powershell
# Download from https://www.openpolicyagent.org/downloads/
# Or use Chocolatey:
choco install opa
```

**Step 2: Start OPA Server**

```bash
# Start OPA server with policies
opa run --server --watch policies/

# Expected output:
# {"level":"info","msg":"Initializing server.","time":"..."}
```

**Step 3: Enable in PRISM**

Edit `config/prism_config.yaml`:
```yaml
policy_engine:
  opa:
    enabled: true
    server_url: "http://localhost:8181"
    fallback_to_python: true  # Use Python if OPA unavailable
```

**Step 4: Test Integration**

```bash
python agent/main.py samples/fail_sbom.json --opa

# Expected output:
# ⚖️ OPA Policy Decision: FAIL
# Reason: CRITICAL reachable vulnerability detected
```

**Fallback Behavior:**
If OPA server unavailable, PRISM falls back to Python-based policy engine using `rules/blocked_packages.yaml`.

---

### 4. Multi-Agent System

**No additional setup required!** Works with existing configuration.

**Enable in Configuration:**

Edit `config/prism_config.yaml`:
```yaml
multi_agent:
  enabled: true

  agents:
    vulnerability_analyzer:
      enabled: true
    code_context_analyzer:
      enabled: true
    remediation_planner:
      enabled: true
    report_generator:
      enabled: true
```

**Usage:**
```bash
python agent/main.py samples/sample_sbom.json --multi-agent --ai
```

**Verification:**
```bash
# Check execution log in report
cat output/report.json | grep execution_log

# Expected output:
# "execution_log": [
#   {"step": 1, "agent": "vulnerability_analyzer", ...},
#   {"step": 2, "agent": "code_context_analyzer", ...},
#   ...
# ]
```

---

## Configuration

### Configuration File Structure

Complete configuration reference: [`config/prism_config.yaml`](../config/prism_config.yaml)

**Key Sections:**

```yaml
# Risk Scoring Formula
risk_scoring:
  formula:
    weights:
      vulnerability_count: 0.4  # 40%
      cvss_score: 0.5          # 50%
      reachability: 0.1        # 10%

# Vulnerability Data Sources
vulnerability_sources:
  default_sources:
    - osv      # Fast, comprehensive
    - github   # Fast, GitHub-specific
    - kev      # Fast, exploited only
    # - nvd    # SLOW, comment out for speed

  rate_limits:
    nvd_delay_seconds: 6  # NVD requires 10 req/min max

# Reachability Analysis
reachability:
  level_1:
    enabled: true
    dev_dependencies_risk_multiplier: 0.1

  level_2:
    enabled: true  # Enable import/call graph
    import_graph:
      enabled: true
      max_depth: 10
    call_graph:
      enabled: true

# AI Features
ai:
  enabled: true  # Requires OPENAI_API_KEY env var

  openai:
    model: "gpt-4"  # or "gpt-3.5-turbo"
    temperature: 0.3
    max_tokens: 2000

# OPA Policies
policy_engine:
  opa:
    enabled: true  # Requires OPA server running
    server_url: "http://localhost:8181"
    fallback_to_python: true

# Multi-Agent System
multi_agent:
  enabled: true
```

### Environment Variables

PRISM respects these environment variables:

```bash
# Required for AI features
export OPENAI_API_KEY="sk-..."

# Optional: Override config file path
export PRISM_CONFIG="/path/to/custom/config.yaml"

# Optional: Override OPA server URL
export OPA_SERVER_URL="http://custom-opa:8181"
```

---

## Troubleshooting

### Common Issues

#### 1. "Module not found" errors

**Error:**
```
ModuleNotFoundError: No module named 'requests'
```

**Solution:**
```bash
pip install -r requirements.txt

# If using virtual environment
source venv/bin/activate  # Activate first
pip install -r requirements.txt
```

---

#### 2. OpenAI API errors

**Error:**
```
OpenAI API error: Invalid API key
```

**Solutions:**

**Check environment variable:**
```bash
# Linux/macOS
echo $OPENAI_API_KEY

# Windows PowerShell
$env:OPENAI_API_KEY

# Should output: sk-...
```

**Verify API key works:**
```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

**Set correctly:**
```bash
# Make sure no extra quotes or spaces
export OPENAI_API_KEY="sk-proj-abc123..."  # Correct
export OPENAI_API_KEY="'sk-proj-abc123...'"  # WRONG - extra quotes
```

---

#### 3. OPA server connection errors

**Error:**
```
OPA server unreachable at http://localhost:8181
```

**Solutions:**

**Check if OPA is running:**
```bash
# Docker
docker ps | grep opa

# Native
ps aux | grep opa
```

**Check OPA health:**
```bash
curl http://localhost:8181/health

# Should return: {"status": "ok"}
```

**Restart OPA:**
```bash
# Docker
docker-compose restart opa

# Native
killall opa
opa run --server --watch policies/
```

**Use fallback:**
```yaml
# config/prism_config.yaml
policy_engine:
  opa:
    enabled: true
    fallback_to_python: true  # Uses Python if OPA unavailable
```

---

#### 4. Level 2 reachability not working

**Error:**
```
Level 2 analysis skipped - no project root provided
```

**Solution:**
```bash
# Must specify --project-root
python agent/main.py samples/sample_sbom.json \
  --project-root /path/to/source/code  # Add this!
```

**Verify project structure:**
```bash
# Project root should contain source files
ls /path/to/source/code

# Should see: src/, lib/, index.js, main.py, etc.
```

---

#### 5. Performance issues (slow scans)

**Symptoms:**
- Scans take > 60 seconds
- Many API timeout errors

**Solutions:**

**Disable NVD (slowest source):**
```yaml
# config/prism_config.yaml
vulnerability_sources:
  default_sources:
    - osv
    - github
    - kev
    # - nvd  # COMMENTED OUT
```

**Disable Level 2 for quick scans:**
```yaml
reachability:
  level_2:
    enabled: false  # Faster, less accurate
```

**Use GPT-3.5 instead of GPT-4:**
```yaml
ai:
  openai:
    model: "gpt-3.5-turbo"  # 10x faster, 15x cheaper
```

---

## Verification

### Test All Features

**1. Basic Scan (No Advanced Features):**
```bash
python agent/main.py samples/sample_sbom.json

# ✅ Should complete in < 10 seconds
# ✅ Should generate output/report.json
```

**2. Level 2 Reachability:**
```bash
python agent/main.py samples/sample_sbom.json \
  --project-root /path/to/code

# ✅ Should show "Import Analysis" in output
# ✅ Should show confidence scores (0.0-1.0)
```

**3. AI Remediation:**
```bash
export OPENAI_API_KEY="sk-..."
python agent/main.py samples/sample_sbom.json --ai

# ✅ Should show "🤖 AI-POWERED ANALYSIS"
# ✅ Should show personalized remediation plan
```

**4. OPA Policies:**
```bash
docker-compose up -d opa
python agent/main.py samples/fail_sbom.json --opa

# ✅ Should show "⚖️ OPA Policy Decision: FAIL"
# ✅ Should show matched policy rules
```

**5. Multi-Agent System:**
```bash
python agent/main.py samples/sample_sbom.json \
  --multi-agent \
  --ai

# ✅ Should show agent execution log
# ✅ Should show 4 agents: VulnAnalyzer, CodeContext, Remediation, Report
```

**6. Full Enterprise Mode (All Features):**
```bash
docker-compose up -d opa
export OPENAI_API_KEY="sk-..."
python agent/main.py samples/sample_sbom.json \
  --ai \
  --opa \
  --multi-agent \
  --project-root /path/to/code

# ✅ All features working together
# ✅ Should complete in < 60 seconds
```

---

## Next Steps

After successful installation:

1. **Read Documentation:**
   - [FEATURES.md](FEATURES.md) - Complete feature guide
   - [OPA_SETUP.md](OPA_SETUP.md) - Advanced policy writing
   - [COMPARISON.md](COMPARISON.md) - vs Dependabot/Snyk

2. **Try on Real Project:**
   ```bash
   # Generate SBOM for your project
   # (Install CycloneDX generators first)

   # Node.js
   npm install -g @cyclonedx/cyclonedx-npm
   cyclonedx-npm --output-file sbom.json

   # Python
   pip install cyclonedx-bom
   cyclonedx-py -o sbom.json

   # Scan with PRISM
   python agent/main.py sbom.json --ai --project-root .
   ```

3. **Customize Policies:**
   - Edit `policies/prism.rego`
   - Add custom rules for your organization
   - Test with `opa test policies/`

4. **Integrate with CI/CD:**
   - See GitHub Actions examples in `.github/workflows/`
   - Add to your PR workflow
   - Configure fail thresholds

---

## Support

**Issues:** [GitHub Issues](https://github.com/YOUR_REPO/issues)
**Discussions:** [GitHub Discussions](https://github.com/YOUR_REPO/discussions)
**Email:** prism-security@rit.edu.in

---

*Last Updated: January 2024*
