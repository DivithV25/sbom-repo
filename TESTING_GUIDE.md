# Testing Guide: Multi-Ecosystem SBOM Scanning

## Quick Verification

### 1. Verify Setup is Complete

```bash
# Run the ecosystem validator script
python verify_ecosystems.py
```

Expected output:
```
🔍 Multi-Ecosystem SBOM Validation
============================================================

📦 Checking npm (Node.js)...
   ✓ package.json found
   ✓ Valid JSON format
   ✓ package-lock.json found (recommended)

🐍 Checking Python...
   ✓ requirements.txt found
   ✓ Valid format (8 packages)
   ✓ All packages have pinned versions

🐹 Checking Go...
   ✓ go.mod found
   ✓ Valid go.mod format
   ✓ go.sum found (recommended)

☕ Checking Maven...
   ✓ pom.xml found
   ✓ Valid pom.xml format (3 dependencies)

⚙️  Checking GitHub Workflow...
   ✓ sbom.yml workflow found
   ✓ NPM setup found
   ✓ PYTHON setup found
   ✓ GO setup found
   ✓ MAVEN setup found

📊 VALIDATION SUMMARY
✅ NPM      - Valid
✅ PYTHON   - Valid
✅ GO       - Valid
✅ MAVEN    - Valid

Detected Ecosystems: 4/4
Valid Ecosystems: 4/4

✅ All 4 ecosystems detected!
```

## Local Testing

### Step 1: Install Required Tools

```bash
# Node.js
node --version      # Should be v18+
npm --version       # Should be 8+

# Python
python --version    # Should be 3.12+
pip --version

# Go
go version          # Should be 1.21+

# Maven
mvn --version       # Should be 3.8+

# SBOM Tools
pip install syft cyclonedx-bom
syft --version
```

### Step 2: Generate SBOM Locally

```bash
# Change to repo directory
cd d:/MajorProject/sbom-repo

# Generate SBOM with all ecosystems
syft . -o cyclonedx-json > sbom.json

# View generated SBOM
cat sbom.json | python -m json.tool | head -50

# Count components by ecosystem
echo "Components by ecosystem:"
grep -o '"purl":"[^"]*"' sbom.json | grep -o ':[^/]*' | sort | uniq -c
```

Expected output:
```
Components by ecosystem:
  5 :npm
  8 :pypi
  4 :golang
  3 :maven
```

### Step 3: Run Vulnerability Scanner Locally

```bash
# Install PRISM dependencies
pip install -r requirements.txt

# Run scanner
python -m agent.main sbom.json --output local-test-output

# Check results
ls -la local-test-output/
cat local-test-output/pr_comment.md
cat local-test-output/report.json | python -m json.tool
```

### Step 4: Test Vulnerability Detection

#### Add a Known Vulnerable Package

**Python Example (CVE-2021-23336)**:
```bash
# Add vulnerable urllib3
echo "urllib3==1.24.0" >> application/python-app/requirements.txt

# Regenerate SBOM
syft . -o cyclonedx-json > sbom-vuln.json

# Scan
python -m agent.main sbom-vuln.json --output vuln-test-output

# Check for detected vulnerability
cat vuln-test-output/report.json | grep -i "urllib3"
```

#### npm Example (Various):
```bash
# Add older axios (has known vulnerabilities)
jq '.dependencies.axios = "1.1.0"' application/nodejs-app/package.json > temp.json && mv temp.json application/nodejs-app/package.json

# Regenerate SBOM
syft . -o cyclonedx-json > sbom-vuln.json

# Scan
python -m agent.main sbom-vuln.json --output npm-vuln-test
```

### Step 5: Test PR Comment Generation

**Simulate PR changes**:
```bash
# Create a test branch
git checkout -b test/multi-ecosystem-update

# Modify all dependency files
echo '  "new-package": "1.0.0"' >> application/nodejs-app/package.json
echo 'new-package==1.0.0' >> application/python-app/requirements.txt
echo 'require new-package v1.0.0' >> application/go-app/go.mod
sed -i 's/<version>1.0.0<\/version>/<version>2.0.0<\/version>/' application/maven-app/pom.xml

# Commit and create PR (simulate)
git add -A
git commit -m "test: Update all ecosystem dependencies"
```

### Step 6: Verify Inline Suggestion Logic

```bash
# Check if report has remediations
python -c "
import json
with open('local-test-output/report.json') as f:
    report = json.load(f)
    remediations = report.get('remediations', [])
    print(f'Total remediations: {len(remediations)}')
    for rem in remediations:
        print(f'  - {rem[\"component\"][\"name\"]} ({rem[\"component\"].get(\"ecosystem\", \"unknown\")})')
"
```

## Automated Testing

### Create a Test PR with Multiple Ecosystems

1. **Create feature branch**:
   ```bash
   git checkout -b feature/test-multi-ecosystem
   ```

2. **Add all dependency files**:
   ```bash
   # Ensure all demo apps have dependencies
   cd application/
   
   # Check each directory
   cat nodejs-app/package.json
   cat python-app/requirements.txt
   cat go-app/go.mod
   cat maven-app/pom.xml
   ```

3. **Commit changes**:
   ```bash
   git add application/
   git commit -m "feat: Add multi-ecosystem test applications"
   ```

4. **Push and create PR**:
   ```bash
   git push -u origin feature/test-multi-ecosystem
   # Then create PR on GitHub
   ```

5. **Monitor workflow**:
   - Watch GitHub Actions run
   - Check for ecosystem detection
   - Verify SBOM generation
   - Review PR comments
   - Check inline suggestions

## Expected Test Results

### Successful Test:
```
✅ Workflow triggers on PR
✅ Detects all 4 ecosystems
✅ Installs dependencies for each
✅ Generates unified SBOM
✅ Scans components
✅ Posts main comment
✅ Posts inline suggestions
✅ Makes PASS/FAIL decision
```

### Debug Output to Check:

**Ecosystem Detection**:
```bash
# In GitHub Actions workflow logs:
🔍 Detecting project ecosystems...
✓ npm (Node.js)
✓ python
✓ go
✓ maven
📦 Detected ecosystems: npm python go maven
```

**SBOM Generation**:
```bash
# Check SBOM artifact
cat sbom.json | jq '.metadata.component'
grep "purl" sbom.json | wc -l  # Count total components
```

**Scanning Results**:
```bash
# Check PR comment artifact
cat vulnscan-output/pr_comment.md

# Check decision
cat vulnscan-output/decision.json
```

## Troubleshooting During Testing

### Issue: Workflow Not Triggering

**Solution**:
```bash
# Verify workflow file syntax
yamllint .github/workflows/sbom.yml

# Check permissions
# Ensure secrets are set (OPENAI_API_KEY)
```

### Issue: Some Ecosystems Not Detected

**Solution**:
```bash
# Verify files exist
find . -name "package.json" -o -name "requirements.txt" -o -name "go.mod" -o -name "pom.xml"

# Check file contents
file application/nodejs-app/package.json
file application/python-app/requirements.txt
```

### Issue: SBOM Missing Components

**Solution**:
```bash
# Install Syft directly and test
pip install syft
syft . -o text  # See what Syft detects

# Check if dependencies are installed
npm ls
pip list
go list -m all
mvn dependency:tree
```

### Issue: No Inline Suggestions

**Solution**:
```bash
# Check if report has remediations
cat vulnscan-output/report.json | jq '.remediations'

# Verify changed files include dependencies
git diff HEAD~1 -- "*.json" "*.txt" "*.mod" "*.xml"

# Check positioning in patch
git diff HEAD~1 -- application/python-app/requirements.txt
```

## Performance Testing

### Measure Workflow Duration

```bash
# Run locally and time each step
time syft . -o cyclonedx-json > sbom.json
time python -m agent.main sbom.json --output bench-output
```

Typical times:
- SBOM Generation: 10-30 seconds
- Vulnerability Scan: 20-60 seconds (depends on component count)
- Total: 30-90 seconds

### Optimize Slow Steps

**If SBOM generation is slow**:
```bash
# Limit scope
syft application/nodejs-app -o cyclonedx-json > sbom-node-only.json

# Or generate per ecosystem
syft application/nodejs-app --scope AllLayers -o cyclonedx-json
```

**If scanning is slow**:
```bash
# Reduce component count for testing
jq '.components |= .[0:10]' sbom.json > sbom-small.json
python -m agent.main sbom-small.json
```

## Validation Checklist

- [ ] All 4 dependency files present
- [ ] Workflow file updated for multi-ecosystem
- [ ] Tools installed (node, python, go, maven)
- [ ] SBOM generates without errors
- [ ] SBOM contains components from all 4 ecosystems
- [ ] Scanner runs successfully
- [ ] PR comment posts correctly
- [ ] Inline suggestions appear for vulnerable packages
- [ ] PASS decision allows PR to merge
- [ ] FAIL decision blocks PR with review
- [ ] Stale reviews dismissed on PASS
- [ ] Performance acceptable (<2 minutes)

## CI/CD Integration Test

### Test with GitHub Workflow

1. Push test PR:
   ```bash
   git push -u origin feature/test-multi-ecosystem
   ```

2. Create PR on GitHub

3. Monitor Actions tab:
   - ✅ Security-scan job runs
   - ✅ All steps complete
   - ✅ PR comment appears
   - ✅ Inline suggestions appear (if vulnerabilities)

4. Verify results:
   - Check main comment for summary
   - Check inline comments for fixes
   - Verify decision (PASS/FAIL/WARN)

### Test with Different Dependency States

**Test 1: All Safe**
- Add known-safe versions
- Expect: PASS decision, can merge

**Test 2: Minor Vulnerabilities**
- Add packages with low-severity issues
- Expect: WARN decision, can merge with caution

**Test 3: Critical Vulnerabilities**
- Add packages with critical issues
- Expect: FAIL decision, blocks merge

## Regression Testing

After updates, run these tests:

```bash
# 1. All ecosystems still detected
python verify_ecosystems.py

# 2. SBOM still generates
syft . -o cyclonedx-json > sbom.json && echo "✓ SBOM OK"

# 3. Scanner still runs
python -m agent.main sbom.json --output test && echo "✓ Scanner OK"

# 4. Sample vulnerable package still detected
# (Depends on your test data)
```

---

**Ready to test? Start with Step 1 above!**
