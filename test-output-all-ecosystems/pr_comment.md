# PRISM Security Scan Results

*Objectives 1 & 2: SBOM Generation, OSV Scanning, AI Remediation, Policy Gates*

**Decision:** ✗ **FAIL**  
**Overall Severity:** CRITICAL  
**Risk Score:** 10.0 / 10  
**Max CVSS:** 10.0  
**Total Vulnerabilities:** 17  

---

## Vulnerable Components


### lodash@4.17.20

- GHSA-29mw-wpgm-hmr9 (CVSS: 5.3, Severity: MEDIUM) [Source: OSV]
- GHSA-35jh-r3h4-6jhm (CVSS: 7.2, Severity: HIGH) [Source: OSV]
- GHSA-f23m-r3pf-42rh (CVSS: 6.5, Severity: MEDIUM) [Source: OSV]
- GHSA-r5fr-rjxr-66jc (CVSS: 8.1, Severity: HIGH) [Source: OSV]
- GHSA-xxjr-mmjv-4gpg (CVSS: 6.5, Severity: MEDIUM) [Source: OSV]

### requests@2.31.0

- GHSA-9hjg-9r4m-mvj7 (CVSS: 5.3, Severity: MEDIUM) [Source: OSV]
- GHSA-9wx4-h78v-vm56 (CVSS: 5.6, Severity: MEDIUM) [Source: OSV]
- GHSA-gc5v-m9x4-r6x2 (CVSS: 4.4, Severity: MEDIUM) [Source: OSV]

### org.apache.logging.log4j:log4j-core@2.14.1

- GHSA-3pxv-7cmr-fjr4 (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]
- GHSA-6hg6-v5c8-fphq (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]
- GHSA-7rjr-3q55-vv33 (CVSS: 9.0, Severity: CRITICAL) [Source: OSV]
- GHSA-8489-44mv-ggj8 (CVSS: 6.6, Severity: MEDIUM) [Source: OSV]
- GHSA-jfh8-c2jp-5v3q (CVSS: 10.0, Severity: CRITICAL) [Source: OSV]
- GHSA-p6xc-xr62-6r2g (CVSS: 8.6, Severity: HIGH) [Source: OSV]
- GHSA-vc5p-v9hr-52mj (CVSS: 5.0, Severity: MEDIUM) [Source: OSV]

### github.com/golang-jwt/jwt/v5@v5.0.0

- GHSA-mh63-6h87-95cp (CVSS: 7.5, Severity: HIGH) [Source: OSV]
- GO-2025-3553 (CVSS: UNKNOWN - manual review needed) [Source: OSV]

**Note:** 1 vulnerabilities have no CVSS score and require manual assessment.  

---

## Remediation Recommendations


### lodash@4.17.20


**Summary:** Upgrade lodash to fix 5 vulnerabilities


**Impact Analysis:**

AI analysis not available - using basic assessment


**Remediation Plan:**


**Suggested fix:**
```bash
Upgrade lodash to version 4.18.0
```

- **Upgrade to:** 4.18.0

- **Command:** `Upgrade lodash to version 4.18.0`

- **Priority:** HIGH


**Why This Matters:**

This component has 5 known vulnerabilities


**Estimated Effort:**

Unknown


### requests@2.31.0


**Summary:** Upgrade requests to fix 3 vulnerabilities


**Impact Analysis:**

AI analysis not available - using basic assessment


**Remediation Plan:**


**Suggested fix:**
```bash
Upgrade requests to version 2.33.0
```

- **Upgrade to:** 2.33.0

- **Command:** `Upgrade requests to version 2.33.0`

- **Priority:** MEDIUM


**Why This Matters:**

This component has 3 known vulnerabilities


**Estimated Effort:**

Unknown


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


### github.com/golang-jwt/jwt/v5@v5.0.0


**Summary:** Upgrade github.com/golang-jwt/jwt/v5 to fix 2 vulnerabilities


**Impact Analysis:**

AI analysis not available - using basic assessment


**Remediation Plan:**


**Suggested fix:**
```bash
Upgrade github.com/golang-jwt/jwt/v5 to version 5.2.2
```

- **Upgrade to:** 5.2.2

- **Command:** `Upgrade github.com/golang-jwt/jwt/v5 to version 5.2.2`

- **Priority:** HIGH


**Why This Matters:**

This component has 2 known vulnerabilities


**Estimated Effort:**

Unknown


---

## Policy Decision

Severity threshold exceeded: CRITICAL vulnerabilities found (17 total)
