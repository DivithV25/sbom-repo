# PRISM Security Scan Results

*Objectives 1 & 2: SBOM Generation, OSV Scanning, AI Remediation, Policy Gates*

**Decision:** ✗ **FAIL**  
**Overall Severity:** CRITICAL  
**Risk Score:** 10.0 / 10  
**Max CVSS:** 10.0  
**Total Vulnerabilities:** 7  

---

## Vulnerable Components


### org.apache.logging.log4j:log4j-core@2.14.1

- GHSA-3pxv-7cmr-fjr4 (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]
- GHSA-6hg6-v5c8-fphq (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]
- GHSA-7rjr-3q55-vv33 (CVSS: 9.0, Severity: CRITICAL) [Source: OSV]
- GHSA-8489-44mv-ggj8 (CVSS: 6.6, Severity: MEDIUM) [Source: OSV]
- GHSA-jfh8-c2jp-5v3q (CVSS: 10.0, Severity: CRITICAL) [Source: OSV]
- GHSA-p6xc-xr62-6r2g (CVSS: 8.6, Severity: HIGH) [Source: OSV]
- GHSA-vc5p-v9hr-52mj (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]

---

## Remediation Recommendations


### org.apache.logging.log4j:log4j-core@2.14.1


**Summary:** Upgrade org.apache.logging.log4j:log4j-core to fix 7 vulnerabilities


**Impact Analysis:**

AI analysis not available - using basic assessment


**Remediation Plan:**


**Suggested fix:**
```bash
Upgrade org.apache.logging.log4j:log4j-core to version 2.25.4
```

- **Upgrade to:** 2.25.4

- **Command:** `Upgrade org.apache.logging.log4j:log4j-core to version 2.25.4`

- **Priority:** CRITICAL


**Why This Matters:**

This component has 7 known vulnerabilities


**Estimated Effort:**

Unknown


---

## Policy Decision

Severity threshold exceeded: CRITICAL vulnerabilities found (7 total)
