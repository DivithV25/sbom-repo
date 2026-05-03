# PRISM Multi-Language Quick Reference

## 🚀 Quick Start

### Scan Node.js App
```bash
python -m agent.main --scan ./application/nodejs-app
```

### Scan Python App
```bash
python -m agent.main --scan ./application/python-app
```

### Scan Go App
```bash
python -m agent.main --scan ./application/go-app
```

### Scan Maven/Java App
```bash
python -m agent.main --scan ./application/maven-app
```

### Scan ALL Languages
```bash
python -m agent.main --scan ./application
```

---

## 🛡️ Block Dependencies

### Step 1: Create Policy File
```yaml
# policies/my_policy.yaml
blocked_packages:
  - lodash@4.17.15       # npm
  - requests@2.25.0      # pypi
  - log4j-core           # maven
```

### Step 2: Run Scan with Policy
```bash
python -m agent.main --scan ./application \
  --rules policies/my_policy.yaml
```

### Step 3: Check Result
```bash
# Check decision
cat output/decision.json
```

---

## 📊 Supported Formats

| Language | Manifest | Command |
|----------|----------|---------|
| Node.js | package.json | `python -m agent.main --scan ./nodejs-app` |
| Python | requirements.txt | `python -m agent.main --scan ./python-app` |
| Go | go.mod | `python -m agent.main --scan ./go-app` |
| Java | pom.xml | `python -m agent.main --scan ./maven-app` |
| All | Mixed | `python -m agent.main --scan ./` |

---

## 📁 Output Files

```
output/
├── sboms/                                    # Generated SBOMs
│   ├── sbom_npm_package_json.json
│   ├── sbom_pypi_requirements_txt.json
│   ├── sbom_golang_go_mod.json
│   ├── sbom_maven_pom_xml.json
│   └── sbom_combined_all_languages.json
├── report.json                               # Full findings
├── pr_comment.md                             # GitHub comment
└── decision.json                             # PASS/WARN/FAIL
```

---

## ✅ Decisions

| Decision | Meaning | Action |
|----------|---------|--------|
| PASS | All clear | Deploy ✅ |
| WARN | Issues found | Review ⚠️ |
| FAIL | Critical issues | Block ❌ |

---

## 🔍 Check Results

### Decision
```bash
cat output/decision.json | jq '.decision, .reason'
```

### Vulnerabilities
```bash
cat output/report.json | jq '.findings[] | {name, vulnerabilities}'
```

### Dependencies by Ecosystem
```bash
cat output/report.json | jq '.risk_summary'
```

---

## 🔗 CI/CD Integration

### GitHub Actions
```yaml
- name: PRISM Scan
  run: |
    python -m agent.main --scan ./application \
      --rules policies/default_policy.yaml
    
    DECISION=$(jq -r '.decision' output/decision.json)
    [ "$DECISION" != "FAIL" ] || exit 1
```

### GitLab CI
```yaml
prism_scan:
  script:
    - python -m agent.main --scan ./application
    - test $(jq -r '.decision' output/decision.json) != "FAIL"
```

---

## 📝 Policy Examples

### Block Versions
```yaml
blocked_packages:
  - lodash@4.17.15  # Specific version
  - lodash@4.17.19  # Multiple versions
  # 4.17.21+ allowed
```

### Block by Severity
```yaml
vulnerability_rules:
  - condition: "severity == Critical"
    action: FAIL
```

### Block Reachable Vulns Only
```yaml
vulnerability_rules:
  - condition: "reachable == true"
    action: FAIL
```

---

## 🐛 Troubleshooting

### No manifests found?
```bash
# Check if files exist
find . -name "package.json" -o -name "requirements.txt" -o -name "go.mod" -o -name "pom.xml"
```

### Dependency not detected?
```bash
# Check file format
cat package.json | jq .
cat requirements.txt
cat go.mod
cat pom.xml
```

### Vulnerability scan fails?
```bash
# Check internet connection
ping api.osv.dev

# Try single dependency
python -c "from agent.osv_client import query_osv; print(query_osv('lodash', '4.17.15', 'npm'))"
```

---

## 📚 Documentation

- **Full Guide**: [MULTI_LANGUAGE_SUPPORT.md](docs/MULTI_LANGUAGE_SUPPORT.md)
- **Blocking Guide**: [BLOCKING_DEPENDENCIES_PIPELINE.md](docs/BLOCKING_DEPENDENCIES_PIPELINE.md)
- **Demo Apps**: [application/README.md](application/README.md)
- **Implementation**: [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)

---

## 🎯 Common Tasks

### Scan entire monorepo
```bash
python -m agent.main --scan ./services
```

### Export SBOM
```bash
cat output/sboms/sbom_combined_all_languages.json > my_sbom.json
```

### Check specific package
```bash
cat output/report.json | jq '.findings[] | select(.component.name == "lodash")'
```

### List all blocked packages
```bash
cat policies/default_policy.yaml | grep -A 20 "blocked_packages"
```

### Test policy locally
```bash
python -m agent.main --scan ./application \
  --rules policies/test_policy.yaml \
  --output test-results
```

---

## 🚀 API Usage

### Python Code
```python
from agent.multi_language_scanner import ManifestDetector, DependencyParser, SBOMGenerator

# Detect manifests
manifests = ManifestDetector.detect_manifests('./app')

# Parse dependencies
ecosystem, components = DependencyParser.parse_manifest('./package.json')

# Generate SBOM
sbom = SBOMGenerator.generate_sbom(components)
SBOMGenerator.save_sbom(sbom, './sbom.json')
```

---

## 💡 Pro Tips

1. **Version Specific**: Use exact versions in blocked_packages for precision
2. **Start Permissive**: Use WARN first, escalate to FAIL after testing
3. **Cache Cleanup**: Delete `.prism_cache` to force fresh vulnerability scan
4. **Parallel Scanning**: Run multiple scans with different policies simultaneously
5. **Save Results**: Archive reports for compliance and audit trails

---

## 🔗 Links

- [Main README](README.md)
- [Requirements](requirements.txt)
- [Sample Applications](application/)
- [Policies](policies/)
- [Tests](tests/)

---

**For help**: Review `docs/MULTI_LANGUAGE_SUPPORT.md` or `docs/BLOCKING_DEPENDENCIES_PIPELINE.md`
