# Blocking Dependencies in Pipeline - PRISM Multi-Language Guide

This guide explains how to use PRISM's multi-language support to block unwanted dependencies in your CI/CD pipeline.

## Overview

PRISM allows you to:
1. **Detect** dependencies across Node.js, Python, Go, and Java/Maven projects
2. **Block** specific packages by adding them to security policies
3. **Enforce** these policies in your CI/CD pipeline
4. **Prevent** vulnerable or unauthorized code from being deployed

## How to Block Dependencies

### Step 1: Define Blocked Packages

Edit or create `policies/default_policy.yaml`:

```yaml
# List of packages that are blocked from use in any ecosystem
blocked_packages:
  # Node.js (npm)
  - lodash@4.17.15
  - axios@0.21.0
  - express@4.17.0
  
  # Python (PyPI)
  - Flask@2.0.0
  - requests@2.25.0
  - django@2.2.0
  
  # Go (golang)
  - github.com/example/malicious-package
  
  # Java/Maven
  - org.springframework:spring-core:5.0.0
  - commons-lang:commons-lang:2.6

# Additional rules
vulnerability_rules:
  - condition: "severity == Critical"
    action: FAIL
    reason: "Critical vulnerabilities not allowed in production"
  
  - condition: "severity == High and reachable == true"
    action: WARN
    reason: "High severity reachable vulnerabilities detected"
```

### Step 2: Apply Policy During Scan

#### Option A: Using Main PRISM CLI with Multi-Language Support
```bash
# Scan entire application with policy
python -m agent.main --scan ./application \
  --rules policies/default_policy.yaml \
  --output reports
```

#### Option B: Using Dedicated Application Scanner
```bash
python scan_application.py ./application/nodejs-app \
  --rules policies/default_policy.yaml \
  --output reports
```

#### Option C: Scan Individual Languages
```bash
# Node.js only
python -m agent.main --scan ./application/nodejs-app \
  --rules policies/default_policy.yaml \
  --output reports/nodejs

# Python only
python -m agent.main --scan ./application/python-app \
  --rules policies/default_policy.yaml \
  --output reports/python

# Java/Maven only
python -m agent.main --scan ./application/maven-app \
  --rules policies/default_policy.yaml \
  --output reports/maven
```

### Step 3: Interpret Results

After scanning, check `reports/decision.json`:

```json
{
  "decision": "FAIL",
  "reason": "Policy violations found: 3 blocked package(s)",
  "total_vulnerabilities": 0,
  "critical_vulnerabilities": 0
}
```

### Decision Types

| Decision | Meaning | Action |
|----------|---------|--------|
| `PASS` | All checks passed, no issues | ✅ Deploy allowed |
| `WARN` | Non-critical issues detected | ⚠️ Review recommended |
| `FAIL` | Critical issues or policy violations | ❌ Deployment blocked |

## Real-World Examples

### Example 1: Block Log4j in Java Projects

**Scenario:** You want to prevent the vulnerable Log4j library from being used.

1. Update `policies/default_policy.yaml`:
```yaml
blocked_packages:
  - org.apache.logging.log4j:log4j-core  # Block all versions
```

2. Scan Maven application:
```bash
python -m agent.main --scan ./application/maven-app \
  --rules policies/default_policy.yaml \
  --output reports
```

3. Result:
```
❌ BLOCKED: org.apache.logging.log4j:log4j-core@2.14.1 (maven)
```

### Example 2: Block Outdated Lodash

**Scenario:** Node.js team requires Lodash 4.17.21+

1. Policy:
```yaml
blocked_packages:
  - lodash@4.17.15  # Block old version
  - lodash@4.17.19
```

2. Scan:
```bash
python -m agent.main --scan ./application/nodejs-app \
  --rules policies/default_policy.yaml
```

3. Result if old version found:
```
❌ BLOCKED: lodash@4.17.15 (npm)
```

### Example 3: Multi-Language Project Policy

**Scenario:** Enterprise-wide security policy across multiple teams

1. Create unified policy `policies/enterprise_policy.yaml`:
```yaml
blocked_packages:
  # Security-critical packages
  - axios@0.21.0          # npm
  - requests@2.25.0       # pypi
  - express@4.17.0        # npm
  - Flask@2.0.0           # pypi
  - org.apache:commons-collections:3.1  # maven
  
# Enforce strict rules
vulnerability_rules:
  - condition: "severity == Critical"
    action: FAIL
  - condition: "severity == High"
    action: FAIL
```

2. Scan all applications:
```bash
# Node.js service
python -m agent.main --scan ./services/api-service \
  --rules policies/enterprise_policy.yaml \
  --output reports/api-service

# Python service
python -m agent.main --scan ./services/data-service \
  --rules policies/enterprise_policy.yaml \
  --output reports/data-service

# Go service
python -m agent.main --scan ./services/worker-service \
  --rules policies/enterprise_policy.yaml \
  --output reports/worker-service
```

## CI/CD Pipeline Integration

### GitHub Actions Workflow

```yaml
name: PRISM Dependency Check

on:
  pull_request:
    paths:
      - 'application/**'
      - 'package.json'
      - 'requirements.txt'
      - 'go.mod'
      - 'pom.xml'
  push:
    branches: [main, develop]

jobs:
  security-check:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install PRISM Dependencies
        run: pip install -r requirements.txt
      
      - name: Run PRISM Multi-Language Scan
        run: |
          python -m agent.main --scan ./application \
            --rules policies/default_policy.yaml \
            --output security-report
      
      - name: Check Security Decision
        run: |
          DECISION=$(jq -r '.decision' security-report/decision.json)
          echo "Security Decision: $DECISION"
          
          if [ "$DECISION" = "FAIL" ]; then
            echo "❌ Deployment blocked due to security policy violations"
            jq '.reason' security-report/decision.json
            exit 1
          fi
      
      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: security-report/
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-report/pr_comment.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
```

### GitLab CI Pipeline

```yaml
stages:
  - security
  - build
  - deploy

prism-scan:
  stage: security
  image: python:3.11
  
  script:
    - pip install -r requirements.txt
    - python -m agent.main --scan ./application
        --rules policies/default_policy.yaml
        --output security-report
    
    # Check decision
    - DECISION=$(jq -r '.decision' security-report/decision.json)
    - |
      if [ "$DECISION" = "FAIL" ]; then
        echo "Deployment blocked by PRISM"
        exit 1
      fi
  
  artifacts:
    paths:
      - security-report/
    reports:
      sast: security-report/report.json
  
  allow_failure: false
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Install Dependencies') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }
        
        stage('PRISM Security Scan') {
            steps {
                sh '''
                    python -m agent.main --scan ./application \\
                        --rules policies/default_policy.yaml \\
                        --output security-report
                '''
            }
        }
        
        stage('Check Security Decision') {
            steps {
                script {
                    def decision = sh(
                        script: 'jq -r ".decision" security-report/decision.json',
                        returnStdout: true
                    ).trim()
                    
                    echo "Security Decision: ${decision}"
                    
                    if (decision == 'FAIL') {
                        error('Deployment blocked due to security policy violations')
                    }
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                reportDir: 'security-report',
                reportFiles: 'pr_comment.md',
                reportName: 'PRISM Security Report'
            ])
        }
    }
}
```

## Advanced Blocking Scenarios

### 1. Block Dependencies by Severity

```yaml
vulnerability_rules:
  - condition: "severity == Critical"
    action: FAIL
    reason: "Critical vulnerabilities not allowed"
```

### 2. Block Reachable Vulnerabilities Only

```yaml
vulnerability_rules:
  - condition: "reachable == true"
    action: FAIL
    reason: "Reachable vulnerabilities must be fixed"
```

### 3. Version-Specific Blocking

```yaml
blocked_packages:
  - lodash@4.17.15  # Specific version
  - lodash@4.17.19  # Another version
  # 4.17.21+ will be allowed
```

### 4. License-Based Blocking

```yaml
# Example for future implementation
blocked_licenses:
  - GPL-2.0
  - GPL-3.0
  - AGPL-3.0
```

## Troubleshooting

### Issue: Blocking isn't working

**Check:**
1. Verify package name matches exactly (case-sensitive)
2. Ensure policy file syntax is correct YAML
3. Confirm policy file path is passed to scan command
4. Check that manifest file contains the package

### Issue: False positives (blocking too much)

**Solution:**
1. Use version-specific blocking instead of wildcard
2. Check exact package names in generated SBOM
3. Review policy rules - adjust conditions if needed

### Issue: Package not detected

**Check:**
1. Verify package is in manifest file
2. Confirm manifest file format is correct
3. Check for typos in package names
4. Ensure ecosystem is supported (npm, pypi, golang, maven)

## Monitoring and Reporting

### Generate Policy Compliance Report

```bash
# Scan and save results
python -m agent.main --scan ./application \
  --rules policies/default_policy.yaml \
  --output compliance-report

# Extract statistics
echo "=== Compliance Report ==="
jq '.decision, .reason, .dependencies_by_ecosystem' compliance-report/decision.json
```

### Track Violations Over Time

```bash
# Run periodic scans and store results
for DATE in $(seq 1 7); do
  python -m agent.main --scan ./application \
    --output "reports/day-$DATE"
done

# Compare results
diff reports/day-1/decision.json reports/day-7/decision.json
```

## Best Practices

1. **Start Permissive:** Begin with WARN decisions, then escalate to FAIL
2. **Version Specific:** Block specific vulnerable versions, not entire packages
3. **Regular Updates:** Review and update policies quarterly
4. **Communication:** Notify teams before blocking new packages
5. **Whitelist Exceptions:** Document why specific packages are allowed
6. **Test Locally:** Always test policies locally before CI/CD deployment

## Summary

PRISM's multi-language support enables you to:
- ✅ Block dependencies across all language ecosystems
- ✅ Enforce unified security policies
- ✅ Automate compliance checks in CI/CD
- ✅ Prevent unauthorized code deployment
- ✅ Scale security to multi-language teams

For more information, see [MULTI_LANGUAGE_SUPPORT.md](../docs/MULTI_LANGUAGE_SUPPORT.md)
