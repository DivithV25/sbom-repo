# Multi-Language Support - PRISM Security Scanner

## Overview

PRISM now supports **multi-language dependency scanning** with automatic manifest detection and SBOM generation. You can now scan applications written in:

- 📦 **Node.js** (package.json)
- 🐍 **Python** (requirements.txt, Pipfile)
- 🐹 **Go** (go.mod)
- ☕ **Java/Maven** (pom.xml)

## What's New

### 1. Automatic Manifest Detection
PRISM automatically detects dependency manifests in your project structure and extracts dependencies from them.

### 2. Multi-Ecosystem SBOM Generation
Generates CycloneDX SBOMs from different package managers with proper ecosystem tagging (npm, pypi, golang, maven).

### 3. Unified Security Policy
Apply the same security policies (blocked packages, vulnerability rules) across all languages.

### 4. Comprehensive Scanning
Scan multi-language projects and get a unified security report.

## Quick Start

### Scan a Node.js Application
```bash
python -m agent.main --scan ./application/nodejs-app --output ./reports
```

### Scan a Python Application
```bash
python -m agent.main --scan ./application/python-app --output ./reports
```

### Scan Entire Application Directory (Multi-Language)
```bash
python -m agent.main --scan ./application --output ./reports
```

### Scan with Custom Security Policy
```bash
python -m agent.main --scan ./application \
  --rules policies/custom_policy.yaml \
  --output ./reports
```

### Using the Dedicated Scanner CLI
```bash
python scan_application.py ./application/nodejs-app
python scan_application.py ./application --output ./reports --rules ./policies/default_policy.yaml
```

## Directory Structure

```
application/
├── nodejs-app/
│   ├── package.json         # Node.js dependencies
│   └── index.js            # Application code
├── python-app/
│   ├── requirements.txt     # Python dependencies
│   └── app.py              # Application code
├── go-app/
│   ├── go.mod              # Go dependencies
│   └── main.go             # Application code
└── maven-app/
    ├── pom.xml             # Maven dependencies
    └── src/
        └── main/java/
            └── Application.java  # Java code
```

## Supported Manifest Files

| Language | Manifest File | Ecosystem | Status |
|----------|--------------|-----------|--------|
| Node.js  | package.json | npm | ✅ Supported |
| Python  | requirements.txt | pypi | ✅ Supported |
| Python  | Pipfile | pypi | ✅ Supported |
| Go      | go.mod | golang | ✅ Supported |
| Java/Maven | pom.xml | maven | ✅ Supported |

## How It Works

### Workflow Steps

```
┌─────────────────────────────────────────┐
│ 1. Detect Manifests                     │
│    Recursively scan directory for       │
│    package.json, requirements.txt, etc. │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 2. Parse Dependencies                   │
│    Extract components from each         │
│    manifest with correct ecosystem      │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 3. Generate SBOMs                       │
│    Create CycloneDX SBOMs for each      │
│    manifest + combined SBOM             │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 4. Scan Vulnerabilities                 │
│    Query OSV database for all           │
│    dependencies across ecosystems       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 5. Apply Policies                       │
│    Check blocked packages               │
│    Evaluate security rules              │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 6. Generate Report                      │
│    Output security decision + details   │
└─────────────────────────────────────────┘
```

## Output Structure

After scanning, you'll get:

```
output/
├── sboms/
│   ├── sbom_npm_package_json.json
│   ├── sbom_pypi_requirements_txt.json
│   ├── sbom_golang_go_mod.json
│   ├── sbom_maven_pom_xml.json
│   └── sbom_combined_all_languages.json
├── scan_results.json                    # Summary
├── report.json                          # Detailed findings
├── pr_comment.md                        # GitHub PR comment
└── decision.json                        # CI/CD decision status
```

## Example: scan_results.json

```json
{
  "decision": "WARN",
  "reason": "Vulnerabilities detected: 2 affected package(s)",
  "manifests_found": 4,
  "total_dependencies": 28,
  "dependencies_by_ecosystem": {
    "npm": 6,
    "pypi": 8,
    "golang": 5,
    "maven": 9
  },
  "policy_violations": 0,
  "vulnerabilities_found": 2,
  "critical_vulnerabilities": 0,
  "sbom_files": [
    "output/sboms/sbom_npm_package_json.json",
    "output/sboms/sbom_pypi_requirements_txt.json",
    "output/sboms/sbom_golang_go_mod.json",
    "output/sboms/sbom_maven_pom_xml.json"
  ]
}
```

## Security Policies

### Blocking Packages Across Languages

Create a policy file (e.g., `policies/security_policy.yaml`):

```yaml
blocked_packages:
  - lodash@4.17.15  # npm package
  - requests@2.25.1 # pypi package
  - log4j-core      # maven package
  - mquery          # npm package

vulnerability_rules:
  - condition: "severity == Critical"
    action: FAIL
    reason: "Critical vulnerabilities not allowed"
  
  - condition: "severity == High and reachable == true"
    action: WARN
    reason: "High-severity reachable vulnerabilities found"
```

### Apply Policy During Scan

```bash
python -m agent.main --scan ./application \
  --rules ./policies/security_policy.yaml \
  --output ./reports
```

## Demo Applications

The `application/` folder contains reference implementations:

### Node.js Demo (npm)
- Scans `package.json` for Node.js dependencies
- Includes Express, Lodash, Axios
- Sample app in `index.js`

### Python Demo (PyPI)
- Scans `requirements.txt` for Python packages
- Includes Flask, Requests, Werkzeug
- Sample app in `app.py`

### Go Demo (golang)
- Scans `go.mod` for Go modules
- Includes Gin, Logrus, Godotenv
- Sample app in `main.go`

### Maven Demo (Java)
- Scans `pom.xml` for Maven dependencies
- Includes Spring Boot, Gson, Commons Lang
- Sample app in `Application.java`

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: PRISM Security Check

on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: 3.11
      
      - name: Install PRISM
        run: pip install -r requirements.txt
      
      - name: Scan Application
        run: |
          python -m agent.main --scan . \
            --rules policies/default_policy.yaml \
            --output security-report
      
      - name: Check Decision
        run: |
          DECISION=$(jq -r '.decision' security-report/decision.json)
          if [ "$DECISION" = "FAIL" ]; then
            echo "Security check FAILED"
            exit 1
          fi
```

## Advanced Usage

### Scan Specific Directory
```bash
python -m agent.main --scan ./src --output ./reports
```

### Multiple Language Applications
```bash
# Scans entire directory tree, finds all manifests
python -m agent.main --scan ./microservices --output ./reports
```

### Disable AI-Powered Remediation
```bash
python -m agent.main --scan ./application --no-ai --output ./reports
```

### Legacy SBOM Mode (Direct File Input)
```bash
# For existing SBOM files (not manifest-based)
python -m agent.main ./existing-sbom.json --output ./reports
```

## API Reference

### ManifestDetector
```python
from agent.multi_language_scanner import ManifestDetector

# Detect all manifests
manifests = ManifestDetector.detect_manifests('./application')
# Returns: {'npm': [...], 'pypi': [...], 'golang': [...], 'maven': [...]}
```

### DependencyParser
```python
from agent.multi_language_scanner import DependencyParser

# Parse specific manifest
ecosystem, components = DependencyParser.parse_manifest('./package.json')
# Returns: ('npm', [{'name': '...', 'version': '...', 'ecosystem': 'npm', ...}])
```

### SBOMGenerator
```python
from agent.multi_language_scanner import SBOMGenerator

# Generate SBOM from components
sbom = SBOMGenerator.generate_sbom(components, metadata={...})

# Save SBOM
SBOMGenerator.save_sbom(sbom, './sbom.json')
```

## Troubleshooting

### No Manifests Detected
- Ensure manifest files are named correctly: `package.json`, `requirements.txt`, `go.mod`, `pom.xml`
- Check that files are readable
- Verify the directory path is correct

### Dependencies Not Extracted
- Verify manifest file format is valid JSON/YAML/XML
- For `pom.xml`, ensure Maven namespace is included
- For `requirements.txt`, check format is `package==version` or `package>=version`

### Vulnerability Scan Fails
- Check internet connection (queries OSV database)
- Verify package names are correctly parsed
- Check OSV database includes your ecosystem

### Policy Not Applied
- Verify YAML syntax in policy file
- Check blocked package names match exactly
- Ensure policy file path is correct

## Performance Notes

- **First scan:** May take longer (cache initialization)
- **Subsequent scans:** Faster due to vulnerability cache
- **Large projects:** Multi-language scanning scales well
- **OSV queries:** Depends on internet speed and number of dependencies

## Version Information

- **CycloneDX Version:** 1.4
- **Supported Python:** 3.8+
- **OSV Client:** Latest v1

## Contributing

To add support for more package managers:

1. Create a new parser in `multi_language_scanner.py`
2. Add manifest pattern to `MANIFEST_PATTERNS`
3. Implement `parse_*` method
4. Add tests in `tests/`

## License

Same as PRISM project

## Support

For issues or questions:
- Check documentation
- Review example applications in `application/`
- Run demo scans with verbose output
