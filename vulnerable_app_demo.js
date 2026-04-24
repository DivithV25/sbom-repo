/**
 * VULNERABLE EXPRESS APP - For PRISM Phase 1 Demonstration
 * 
 * This app intentionally contains vulnerabilities to demonstrate
 * how PRISM Phase 1 scoring works with real code.
 * 
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const lodash = require('lodash');
const serialize = require('serialize-javascript');

const app = express();

// ============================================================================
// EXAMPLE 1: VULNERABLE - Prototype Pollution (CVE-2021-23337)
// 
// Factors:
// 1. Package Present: ✓ (lodash installed)
// 2. Direct Dependency: ✓ (0.8)
// 3. Imported in PR: ✓ (require at top)
// 4. Vulnerable Function: ✓ (defaultsDeep called)
// 5. User Input Reaches: ✓ (req.body directly)
// 6. No Sanitization: ✓ (no validation)
// 
// Result: EXPLOITABLE → Score: 0.92 → FAIL
// ============================================================================

app.post('/vulnerable/merge', (req, res) => {
  // VULNERABLE CODE - defaultsDeep with user input
  // Attack: Send {"__proto__": {"admin": true}}
  const config = lodash.defaultsDeep(req.body, {
    debug: false,
    maxConnections: 100
  });
  
  res.json(config);
});

// ============================================================================
// EXAMPLE 2: PARTIALLY SAFE - Function exists but not directly from user
//
// Factors:
// 1. Package Present: ✓ (lodash installed)
// 2. Direct Dependency: ✓ (0.8)
// 3. Imported in PR: ✓ (used in function)
// 4. Vulnerable Function: ✓ (defaultsDeep called)
// 5. User Input Reaches: ⚠ (indirect, preprocessed)
// 6. No Sanitization: ✗ (JSON validation)
//
// Result: MODERATELY EXPLOITABLE → Score: 0.58 → WARN
// ============================================================================

app.post('/moderate/config', (req, res) => {
  // Input is validated first
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  // Still vulnerable but validation reduces risk
  const config = lodash.defaultsDeep(req.body, {
    timeout: 5000
  });
  
  res.json(config);
});

// ============================================================================
// EXAMPLE 3: SAFE - Sanitization Present
//
// Factors:
// 1. Package Present: ✓ (lodash installed)
// 2. Direct Dependency: ✓ (0.8)
// 3. Imported in PR: ✓ (used in function)
// 4. Vulnerable Function: ✓ (defaultsDeep called)
// 5. User Input Reaches: ⚠ (filtered first)
// 6. No Sanitization: ✗ (SANITIZED - whitelist)
//
// Result: NOT EXPLOITABLE → Score: 0.42 → PASS
// ============================================================================

const SAFE_CONFIG_KEYS = ['name', 'email', 'theme'];

app.post('/safe/config', (req, res) => {
  // Whitelist - only allow specific keys
  const safeData = {};
  for (const key of SAFE_CONFIG_KEYS) {
    if (req.body && key in req.body) {
      safeData[key] = req.body[key];
    }
  }
  
  // Now safe to use lodash because input is controlled
  const config = lodash.defaultsDeep(safeData, {
    theme: 'light'
  });
  
  res.json(config);
});

// ============================================================================
// EXAMPLE 4: NOT USED - Vulnerable package installed but not in this PR
//
// Factors:
// 1. Package Present: ✓ (lodash installed)
// 2. Direct Dependency: ✓ (0.8)
// 3. Imported in PR: ✗ (NOT used in this endpoint)
// 4. Vulnerable Function: ✗ (not called)
// 5. User Input Reaches: ✗ (N/A)
// 6. No Sanitization: ✗ (N/A)
//
// Result: NOT EXPLOITABLE → Score: 0.27 → PASS
// ============================================================================

app.post('/simple/data', (req, res) => {
  // Doesn't use lodash at all
  const data = {
    received: req.body,
    timestamp: new Date().toISOString()
  };
  
  res.json(data);
});

// ============================================================================
// EXAMPLE 5: SERIALIZE VULNERABILITY (CVE-2020-7660)
//
// Factors:
// 1. Package Present: ✓ (serialize-javascript@5.0.1)
// 2. Direct Dependency: ✓ (0.8)
// 3. Imported in PR: ✓
// 4. Vulnerable Function: ✓ (serialize called)
// 5. User Input Reaches: ✓ (req.body)
// 6. No Sanitization: ✓
//
// Result: EXPLOITABLE → Score: 0.88 → FAIL
// ============================================================================

app.post('/vulnerable/serialize', (req, res) => {
  // VULNERABLE - serialize-javascript has RCE vulnerability
  // Attack: Send object with function that gets executed
  const serialized = serialize(req.body);
  
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`window.data = ${serialized}`);
});

// ============================================================================
// FACTOR ANALYSIS IN CODE
// ============================================================================

/*
HOW PRISM PHASE 1 ANALYZES EACH ENDPOINT:

FACTOR 1 - Package Present: 
  ✓ Check if lodash@4.17.20 is in package.json
  ✓ Check if serialize-javascript@5.0.1 is in package.json

FACTOR 2 - Direct Dependency:
  ✓ Is it in "dependencies" (not devDependencies)?
  ✓ Score: 0.8 for direct, 0.4 for transitive

FACTOR 3 - Imported in Diff:
  ✓ Look for "require('lodash')" in PR diff
  ✓ Look for "import lodash from" patterns
  ✓ Score: 1.0 if found, 0.0 if not

FACTOR 4 - Vulnerable Function Called:
  ✓ Search for "defaultsDeep(" in changed code
  ✓ Search for "serialize(" in changed code
  ✓ Score: 1.0 if found, 0.0 if not

FACTOR 5 - User Input Reaches Function:
  ✓ Detect req.body, req.query, req.params patterns
  ✓ Look for function calls with user data
  ✓ Score: 0.9 if direct, 0.6 if possible path, 0.0 if isolated

FACTOR 6 - No Sanitization:
  ✓ Look for validation patterns (if, schema checks)
  ✓ Look for sanitization (xss, dompurify, escape)
  ✓ Look for whitelisting (key checks)
  ✓ Score: 1.0 if none found, 0.0 if found

FINAL SCORE = 
  0.15 × Factor1 +
  0.15 × Factor2 +
  0.20 × Factor3 +
  0.20 × Factor4 +
  0.20 × Factor5 +
  0.10 × Factor6
*/

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;

// Only start server if this file is run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n⚠️  VULNERABLE APP RUNNING ON PORT ${PORT}`);
    console.log(`This app contains intentional vulnerabilities for testing.`);
    console.log(`DO NOT USE IN PRODUCTION!\n`);
  });
}

module.exports = app;

// ============================================================================
// PRISM PHASE 1 SCORING SUMMARY FOR THIS FILE
// ============================================================================

/*
Expected PRISM Analysis Results:

✅ /vulnerable/merge
   • Exploitable: YES ✓
   • Confidence: 0.92 (HIGH)
   • Decision: FAIL ❌ (Block merge)
   • Reason: Directly exploitable prototype pollution

✅ /moderate/config
   • Exploitable: MAYBE ⚠️
   • Confidence: 0.58 (MODERATE)
   • Decision: WARN (Allow but review)
   • Reason: Vulnerable but with some input validation

✅ /safe/config
   • Exploitable: NO ✓
   • Confidence: 0.42 (LOW)
   • Decision: PASS ✅ (Allow merge)
   • Reason: Mitigated by whitelist sanitization

✅ /simple/data
   • Exploitable: NO ✓
   • Confidence: 0.27 (VERY LOW)
   • Decision: PASS ✅ (Allow merge)
   • Reason: Vulnerable package not used in this endpoint

✅ /vulnerable/serialize
   • Exploitable: YES ✓
   • Confidence: 0.88 (HIGH)
   • Decision: FAIL ❌ (Block merge)
   • Reason: RCE vulnerability in serialize-javascript

This demonstrates how PRISM Phase 1 provides context-aware analysis!
*/
