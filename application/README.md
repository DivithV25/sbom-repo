# Application Demo - Multi-Language Dependency Scanning

This folder contains sample applications in different languages/ecosystems to demonstrate PRISM's multi-language dependency scanning capabilities.

## Quick Start

### 1. Scan Node.js Application
```bash
cd ../
python -m agent.main --scan ./application/nodejs-app --output ./reports/nodejs
```

Expected output:
- Scans `package.json`
- Finds: express, lodash, axios dependencies
- Generates SBOM and security report

### 2. Scan Python Application
```bash
python -m agent.main --scan ./application/python-app --output ./reports/python
```

Expected output:
- Scans `requirements.txt`
- Finds: Flask, requests, Werkzeug dependencies
- Generates SBOM and security report

### 3. Scan Go Application
```bash
python -m agent.main --scan ./application/go-app --output ./reports/go
```

Expected output:
- Scans `go.mod`
- Finds: gin-gonic/gin, sirupsen/logrus dependencies
- Generates SBOM and security report

### 4. Scan Maven/Java Application
```bash
python -m agent.main --scan ./application/maven-app --output ./reports/maven
```

Expected output:
- Scans `pom.xml`
- Finds: Spring Boot, Gson, Commons Lang dependencies
- Generates SBOM and security report

### 5. Scan ALL Applications (Multi-Language)
```bash
python -m agent.main --scan ./application --output ./reports/all-languages
```

Expected output:
- Detects and scans all 4 languages
- Generates individual SBOMs for each language
- Generates combined SBOM
- Unified security report across all dependencies

## Project Structure

```
application/
├── nodejs-app/
│   ├── package.json          # Node.js manifest
│   └── index.js             # Sample code
│
├── python-app/
│   ├── requirements.txt      # Python manifest
│   └── app.py              # Sample code
│
├── go-app/
│   ├── go.mod              # Go manifest
│   └── main.go             # Sample code
│
└── maven-app/
    ├── pom.xml             # Maven manifest
    └── src/main/java/com/prism/
        └── Application.java # Sample code
```

## With Security Policies

### Block Specific Packages Across All Languages
Create `policies/blocking_policy.yaml`:
```yaml
blocked_packages:
  - lodash@4.17.15      # Node.js
  - Flask@2.0.1         # Python
  - log4j-core          # Maven/Java
```

Then scan:
```bash
python -m agent.main --scan ./application \
  --rules policies/blocking_policy.yaml \
  --output ./reports/with-policy
```

## Using the Dedicated Scanner CLI

Alternative method using the specialized CLI:
```bash
python scan_application.py ./application/nodejs-app
python scan_application.py ./application/python-app
python scan_application.py ./application
```

## Understanding the Output

### SBOM Files Generated
- `sbom_npm_package_json.json` - Node.js dependencies
- `sbom_pypi_requirements_txt.json` - Python dependencies
- `sbom_golang_go_mod.json` - Go modules
- `sbom_maven_pom_xml.json` - Maven/Java dependencies
- `sbom_combined_all_languages.json` - All dependencies (merged)

### Reports Generated
- `report.json` - Detailed vulnerability findings
- `pr_comment.md` - GitHub PR comment format
- `decision.json` - Security decision (PASS/WARN/FAIL)
- `scan_results.json` - Summary statistics

## Manifest File Details

### Node.js (package.json)
```json
{
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.15",
    "axios": "0.21.1"
  }
}
```

### Python (requirements.txt)
```
Flask==2.0.1
requests==2.26.0
Werkzeug==2.0.1
```

### Go (go.mod)
```
module github.com/example/prism-scanner-demo
go 1.21
require github.com/gin-gonic/gin v1.9.0
```

### Maven (pom.xml)
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>2.7.0</version>
    </dependency>
</dependencies>
```

## Common Tasks

### List All Detected Dependencies
```bash
python -m agent.main --scan ./application --output ./temp
cat ./temp/sboms/sbom_combined_all_languages.json | jq '.components'
```

### Check for Specific Vulnerability
```bash
# After scanning, check report
cat ./reports/all-languages/report.json | jq '.vulnerabilities[] | select(.package=="lodash")'
```

### Validate SBOM Format
```bash
# SBOMs are valid CycloneDX 1.4 format
python -c "import json; print(json.dumps(json.load(open('./reports/all-languages/sboms/sbom_combined_all_languages.json')), indent=2))"
```

## Troubleshooting

### No manifests detected
- Verify manifest files exist with correct names
- Check permissions are readable
- Ensure you're in the correct directory

### Dependency parsing errors
- For pom.xml: Validate XML is well-formed
- For requirements.txt: Ensure format is `package==version`
- For go.mod: Check go version is valid

### OSV scan fails
- Check internet connectivity
- Verify dependency names are correct
- Some newer packages may not be in OSV

## Next Steps

1. **Modify dependencies**: Change versions in manifest files
2. **Add vulnerabilities**: Use known vulnerable versions
3. **Create policies**: Define your security rules
4. **Integrate with CI/CD**: Add to GitHub Actions/GitLab CI

## Examples of Vulnerable Packages

To test the vulnerability detection, you can modify manifest files with known vulnerable versions:

### Node.js
```json
"lodash": "4.17.4"  // Known vulnerability
"axios": "0.21.1"   // Known vulnerability
```

### Python
```
Flask==2.0.0        # Known vulnerability
requests==2.25.1    # Known vulnerability
```

### Go
```
require github.com/gin-gonic/gin v1.6.3  // Older vulnerable version
```

### Maven
```xml
<version>2.14.1</version>  <!-- log4j Log4Shell -->
```

## Support

- See `../docs/MULTI_LANGUAGE_SUPPORT.md` for detailed documentation
- Check `../README.md` for general PRISM documentation
- Review example outputs in `../test-output/`
