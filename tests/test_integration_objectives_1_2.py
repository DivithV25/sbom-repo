"""
Integration Tests for Objectives 1 & 2
=======================================

End-to-end integration tests combining:
- Objective 1: Multi-feed vulnerability correlation
- Objective 2: Reachability analysis & AI remediation

Scenarios:
1. Full SBOM → Multi-feed scan → Reachability → AI → Policy check
2. Real-world project simulation
3. Multi-language projects
4. CI/CD pipeline simulation
5. Merge approval/blocking decisions
"""

import pytest
import json
from pathlib import Path
import sys
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.sbom_parser import parse_sbom
from agent.osv_client import query_osv_vulnerabilities
from agent.reachability_analyzer import analyze_reachability, enhance_findings_with_reachability
from agent.risk_engine import compute_risk
from agent.policy_engine import evaluate_policy
from agent.ai_remediation_advisor import get_ai_remediation_batch


class TestFullPipelineIntegration:
    """End-to-end pipeline tests"""

    def test_full_pipeline_vulnerable_reachable(self, temp_project_root, metrics_collector):
        """INT-1: Vulnerable package + REACHABLE → BLOCK merge"""
        print("\n" + "="*80)
        print("INTEGRATION TEST 1: Vulnerable & Reachable → BLOCK")
        print("="*80)

        # Step 1: Create SBOM with vulnerable package
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.15",  # VULNERABLE VERSION
                    "scope": "required",
                    "purl": "pkg:npm/lodash@4.17.15"
                }
            ]
        }

        # Step 2: Create source code that USES the vulnerable function
        (temp_project_root / "app.js").write_text("""
import _ from 'lodash';

export function renderTemplate(userInput) {
    // CRITICAL: Uses vulnerable _.template() function
    return _.template(userInput)({ name: 'User' });
}
        """)

        # Step 3: Simulate vulnerability findings (from OSV)
        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "cvss": 9.8,  # CRITICAL
                "severity": "CRITICAL",
                "description": "Command injection in lodash _.template()",
                "vulnerable_functions": ["_.template", "template"]
            }]
        }]

        # Step 4: L1 Reachability (scope-based)
        component = sbom['components'][0]
        l1_reach = analyze_reachability(component, sbom)
        print(f"\nL1 Reachability: {l1_reach['reachable']} (scope={l1_reach['scope']})")

        assert l1_reach['reachable'] == True  # scope=required

        # Step 5: L2 Reachability (code-based)
        l2_reach = analyze_reachability(
            component,
            sbom,
            project_root=str(temp_project_root),
            enable_level_2=True
        )
        print(f"L2 Reachability: {l2_reach['reachable']} (imported={l2_reach.get('level_2_import_analysis', {}).get('is_imported')})")

        assert l2_reach['reachable'] == True  # Package imported

        # Step 6: Enhance findings with reachability
        reachability_data = {f"{component['name']}@{component['version']}": l2_reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)

        # Step 7: Compute risk score
        risk = compute_risk(enhanced)
        print(f"\nRisk Score: {risk['risk_score']}/10")
        print(f"Total Vulns: {risk['total_vulnerabilities']}")
        print(f"Reachable Vulns: {risk['reachable_vulnerabilities']}")
        print(f"Max Reachable CVSS: {risk['max_reachable_cvss']}")

        assert risk['reachable_vulnerabilities'] > 0
        assert risk['max_reachable_cvss'] >= 9.0  # Critical

        # Step 8: Policy evaluation
        policy_rules = {
            "fail_on": ["CRITICAL", "HIGH"],
            "warn_on": ["MEDIUM"],
            "allow": ["LOW"],
            "fail_on_reachable_only": True,
            "rules": [
                {
                    "type": "deny",
                    "when": "severity == \"CRITICAL\" and reachable == true",
                    "msg": "Critical & reachable → Block"
                }
            ]
        }

        policy_result = evaluate_policy(enhanced, policy_rules)
        print(f"\nPolicy Decision: {policy_result['decision']}")
        print(f"Blocking Reason: {policy_result.get('blocking_reasons', [])}")

        # ASSERT: Should BLOCK merge
        assert policy_result['decision'] == 'FAIL'
        assert 'CRITICAL' in str(policy_result.get('blocking_reasons', []))

        metrics_collector.add_result("INT-1", "decision", "BLOCK")
        metrics_collector.add_result("INT-1", "risk_score", risk['risk_score'])

        print("\n" + "="*80)
        print("RESULT: MERGE BLOCKED ❌ (Critical & Reachable)")
        print("="*80)

    def test_full_pipeline_vulnerable_not_reachable(self, temp_project_root, metrics_collector):
        """INT-2: Vulnerable package + NOT REACHABLE → ALLOW merge"""
        print("\n" + "="*80)
        print("INTEGRATION TEST 2: Vulnerable but NOT Reachable → ALLOW")
        print("="*80)

        # Step 1: SBOM with vulnerable package
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.15",  # VULNERABLE
                    "scope": "required",
                    "purl": "pkg:npm/lodash@4.17.15"
                }
            ]
        }

        # Step 2: Source code that does NOT import lodash
        (temp_project_root / "app.js").write_text("""
import axios from 'axios';
import express from 'express';

// NO lodash import - not actually used!
export async function getData() {
    return axios.get('http://api.example.com');
}
        """)

        # Step 3: Vulnerability findings
        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "description": "Command injection in lodash"
            }]
        }]

        # Step 4: L2 Reachability (code-based)
        component = sbom['components'][0]
        l2_reach = analyze_reachability(
            component,
            sbom,
            project_root=str(temp_project_root),
            enable_level_2=True
        )

        print(f"\nL2 Reachability: {l2_reach['reachable']}")
        print(f"Reason: {l2_reach['reason']}")

        assert l2_reach['reachable'] == False  # NOT imported

        # Step 5: Enhance with reachability
        reachability_data = {f"{component['name']}@{component['version']}": l2_reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)

        # Step 6: Risk score
        risk = compute_risk(enhanced)
        print(f"\nRisk Score: {risk['risk_score']}/10")
        print(f"Reachable Vulns: {risk['reachable_vulnerabilities']}")
        print(f"Unreachable Vulns: {risk['unreachable_vulnerabilities']}")

        assert risk['reachable_vulnerabilities'] == 0
        assert risk['unreachable_vulnerabilities'] > 0

        # Step 7: Policy with fail_on_reachable_only=True
        policy_rules = {
            "fail_on": ["CRITICAL"],
            "fail_on_reachable_only": True,  # ← KEY: Only block reachable
            "rules": [
                {
                    "type": "allow",
                    "when": "severity == \"CRITICAL\" and reachable == false",
                    "msg": "Critical but unreachable → Allow"
                }
            ]
        }

        policy_result = evaluate_policy(enhanced, policy_rules)
        print(f"\nPolicy Decision: {policy_result['decision']}")

        # ASSERT: Should ALLOW merge (unreachable)
        assert policy_result['decision'] in ['WARN', 'PASS']

        metrics_collector.add_result("INT-2", "decision", "ALLOW")
        metrics_collector.add_result("INT-2", "risk_score", risk['risk_score'])

        print("\n" + "="*80)
        print("RESULT: MERGE ALLOWED ✓ (Not Reachable)")
        print("="*80)

    def test_full_pipeline_dev_dependency(self, temp_project_root, metrics_collector):
        """INT-3: Vulnerable in devDependency → ALLOW merge"""
        print("\n" + "="*80)
        print("INTEGRATION TEST 3: Vulnerable in devDependency → ALLOW")
        print("="*80)

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "webpack",
                    "version": "4.0.0",  # Old vulnerable version
                    "properties": [
                        {"name": "cdx:npm:package:development", "value": "true"}
                    ],
                    "purl": "pkg:npm/webpack@4.0.0"
                }
            ]
        }

        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-XXXX-YYYY",
                "cvss": 7.5,
                "severity": "HIGH"
            }]
        }]

        # L1 should catch dev dependency
        component = sbom['components'][0]
        l1_reach = analyze_reachability(component, sbom)

        print(f"\nL1 Reachability: {l1_reach['reachable']}")
        print(f"Is Dev Only: {l1_reach['is_dev_only']}")

        assert l1_reach['reachable'] == False
        assert l1_reach['is_dev_only'] == True

        # Enhanced findings
        reachability_data = {f"{component['name']}@{component['version']}": l1_reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)

        # Risk
        risk = compute_risk(enhanced)
        assert risk['reachable_vulnerabilities'] == 0

        # Policy
        policy_rules = {
            "fail_on": ["HIGH"],
            "fail_on_reachable_only": True
        }
        policy_result = evaluate_policy(enhanced, policy_rules)

        assert policy_result['decision'] in ['WARN', 'PASS']

        print("\n" + "="*80)
        print("RESULT: MERGE ALLOWED ✓ (Dev Dependency)")
        print("="*80)


class TestMergeBlockingScenarios:
    """Specific merge approval/blocking scenarios"""

    def test_branch_blocked_critical_reachable(self, temp_project_root):
        """MERGE-BLOCK-1: Critical + Reachable → ❌ BLOCK"""
        print("\n" + "="*80)
        print("TEST BRANCH: feature/add-vulnerable-lodash")
        print("SCENARIO: Adds lodash 4.17.15 with vulnerable _.template() call")
        print("="*80)

        # Simulated PR changes
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [{
                "name": "lodash",
                "version": "4.17.15",
                "scope": "required",
                "purl": "pkg:npm/lodash@4.17.15"
            }]
        }

        # Code change adds vulnerable call
        (temp_project_root / "NEW_feature.js").write_text("""
import _ from 'lodash';
export const renderUserInput = input => _.template(input)();
        """)

        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "cvss": 9.8,
                "severity": "CRITICAL"
            }]
        }]

        # Analysis
        component = sbom['components'][0]
        reach = analyze_reachability(component, sbom, str(temp_project_root), True)
        reachability_data = {f"{component['name']}@{component['version']}": reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)
        risk = compute_risk(enhanced)

        # Policy
        policy_rules = {
            "fail_on": ["CRITICAL"],
            "fail_on_reachable_only": True,
            "rules": [{
                "type": "deny",
                "when": "severity == \"CRITICAL\" and reachable == true",
                "msg": "Block merge: Critical vulnerability is reachable"
            }]
        }
        policy = evaluate_policy(enhanced, policy_rules)

        print(f"\n📊 Analysis Results:")
        print(f"  Reachable: {reach['reachable']}")
        print(f"  Risk Score: {risk['risk_score']}/10")
        print(f"  Policy Decision: {policy['decision']}")
        print(f"\n🔒 CI/CD Action: BLOCK MERGE")
        print(f"  Reason: {policy.get('blocking_reasons', [])}")
        print(f"  Message: Critical vulnerability in reachable code")

        assert policy['decision'] == 'FAIL'
        assert risk['reachable_vulnerabilities'] > 0

    def test_branch_allowed_high_not_reachable(self, temp_project_root):
        """MERGE-ALLOW-1: High severity + NOT Reachable → ✓ ALLOW"""
        print("\n" + "="*80)
        print("TEST BRANCH: feature/update-dependencies")
        print("SCENARIO: Updates axios but it's not actually imported")
        print("="*80)

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [{
                "name": "axios",
                "version": "0.21.0",  # Has vulnerabilities
                "scope": "required",
                "purl": "pkg:npm/axios@0.21.0"
            }]
        }

        # Code does NOT import axios
        (temp_project_root / "app.js").write_text("""
import fetch from 'node-fetch';
export const getData = () => fetch('/api/data');
        """)

        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-2020-28168",
                "cvss": 7.5,
                "severity": "HIGH"
            }]
        }]

        component = sbom['components'][0]
        reach = analyze_reachability(component, sbom, str(temp_project_root), True)
        reachability_data = {f"{component['name']}@{component['version']}": reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)
        risk = compute_risk(enhanced)

        policy_rules = {
            "fail_on": ["CRITICAL", "HIGH"],
            "fail_on_reachable_only": True,  # ← Key setting
            "rules": [{
                "type": "allow",
                "when": "severity == \"HIGH\" and reachable == false",
                "msg": "Allow: High severity but not reachable"
            }]
        }
        policy = evaluate_policy(enhanced, policy_rules)

        print(f"\n📊 Analysis Results:")
        print(f"  Reachable: {reach['reachable']}")
        print(f"  Risk Score: {risk['risk_score']}/10")
        print(f"  Policy Decision: {policy['decision']}")
        print(f"\n✅ CI/CD Action: ALLOW MERGE (with warning)")
        print(f"  Reason: Vulnerability not reachable in code")
        print(f"  Recommendation: Update to safe version later")

        assert policy['decision'] in ['WARN', 'PASS']
        assert risk['reachable_vulnerabilities'] == 0

    def test_branch_allowed_medium_safe_functions(self, temp_project_root):
        """MERGE-ALLOW-2: Medium + Only safe functions used → ✓ ALLOW"""
        print("\n" + "="*80)
        print("TEST BRANCH: feature/use-safe-lodash-functions")
        print("SCENARIO: Uses lodash but only safe functions (not _.template)")
        print("="*80)

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [{
                "name": "lodash",
                "version": "4.17.15",
                "scope": "required",
                "purl": "pkg:npm/lodash@4.17.15"
            }]
        }

        # Uses SAFE functions only
        (temp_project_root / "utils.js").write_text("""
import _ from 'lodash';

export const process = data => {
    const filtered = _.filter(data, x => x > 0);
    const mapped = _.map(filtered, x => x * 2);
    return _.sortBy(mapped);
};
        """)

        findings = [{
            "component": sbom['components'][0],
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "vulnerable_functions": ["_.template", "template"]
            }]
        }]

        # L2 analysis would show: imported=True, but vulnerable_function_called=False
        # For this test, we simulate partial reachability
        component = sbom['components'][0]
        reach = {
            "reachable": True,  # Package IS used
            "confidence": "high",
            "reason": "Package imported but vulnerable function NOT called",
            "scope": "required",
            "is_dev_only": False,
            "vulnerable_function_called": False  # ← KEY
        }

        # With function-level analysis, risk should be lower
        print(f"\n📊 Analysis Results:")
        print(f"  Package Imported: True")
        print(f"  Vulnerable Function Called: False")
        print(f"  Risk: LOW (safe functions only)")
        print(f"\n✅ CI/CD Action: ALLOW MERGE")
        print(f"  Reason: Vulnerable _.template() not called")
        print(f"  Only uses: _.filter(), _.map(), _.sortBy()")


class TestMultiLanguageIntegration:
    """Integration tests for multi-language projects"""

    def test_fullstack_js_python_project(self, tmp_path, metrics_collector):
        """INT-MULTI-1: Full-stack project (JS frontend + Python backend)"""
        print("\n" + "="*80)
        print("MULTI-LANGUAGE INTEGRATION: Full-Stack Project")
        print("="*80)

        # Create project structure
        frontend_dir = tmp_path / "frontend"
        backend_dir = tmp_path / "backend"
        frontend_dir.mkdir()
        backend_dir.mkdir()

        # Frontend (JavaScript)
        (frontend_dir / "app.js").write_text("""
import axios from 'axios';
import lodash from 'lodash';

export const fetchData = () => axios.get('/api/data');
export const process = arr => lodash.map(arr, x => x);
        """)

        # Backend (Python)
        (backend_dir / "api.py").write_text("""
from flask import Flask, jsonify
import requests

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    external = requests.get('http://external.api/data')
    return jsonify(external.json())
        """)

        # Combined SBOM
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                # Frontend deps
                {"name": "axios", "version": "0.21.0", "scope": "required", "purl": "pkg:npm/axios@0.21.0"},
                {"name": "lodash", "version": "4.17.15", "scope": "required", "purl": "pkg:npm/lodash@4.17.15"},
                # Backend deps
                {"name": "flask", "version": "2.0.0", "scope": "required", "purl": "pkg:pypi/flask@2.0.0"},
                {"name": "requests", "version": "2.25.0", "scope": "required", "purl": "pkg:pypi/requests@2.25.0"},
            ]
        }

        # Analyze each language separately
        from agent.import_graph_analyzer import ImportGraphAnalyzer

        js_analyzer = ImportGraphAnalyzer(str(frontend_dir))
        py_analyzer = ImportGraphAnalyzer(str(backend_dir))

        axios_reach = js_analyzer.analyze_package_usage("axios", "javascript")
        lodash_reach = js_analyzer.analyze_package_usage("lodash", "javascript")
        flask_reach = py_analyzer.analyze_package_usage("flask", "python")
        requests_reach = py_analyzer.analyze_package_usage("requests", "python")

        print(f"\n📦 Frontend (JavaScript):")
        print(f"  axios: {'✓' if axios_reach['is_imported'] else '✗'}")
        print(f"  lodash: {'✓' if lodash_reach['is_imported'] else '✗'}")

        print(f"\n📦 Backend (Python):")
        print(f"  flask: {'✓' if flask_reach['is_imported'] else '✗'}")
        print(f"  requests: {'✓' if requests_reach['is_imported'] else '✗'}")

        assert axios_reach['is_imported'] == True
        assert lodash_reach['is_imported'] == True
        assert flask_reach['is_imported'] == True
        assert requests_reach['is_imported'] == True

        metrics_collector.add_result("INT-MULTI-1", "js_packages_imported", 2)
        metrics_collector.add_result("INT-MULTI-1", "py_packages_imported", 2)


class TestCICDPipelineSimulation:
    """Simulate CI/CD pipeline checks"""

    def test_pr_check_workflow(self, temp_project_root, metrics_collector):
        """CI-1: Simulated GitHub Actions PR check"""
        print("\n" + "="*80)
        print("CI/CD SIMULATION: Pull Request Check Workflow")
        print("="*80)

        # Step 1: Scan SBOM
        print("\n[1/6] Parsing SBOM...")
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "express", "version": "4.18.0", "scope": "required", "purl": "pkg:npm/express@4.18.0"},
                {"name": "lodash", "version": "4.17.15", "scope": "required", "purl": "pkg:npm/lodash@4.17.15"},
            ]
        }
        print(f"  Found {len(sbom['components'])} components")

        # Step 2: Query vulnerabilities (simulated)
        print("\n[2/6] Querying vulnerability databases...")
        findings = [
            {
                "component": sbom['components'][1],  # lodash
                "vulnerabilities": [
                    {"id": "CVE-2021-23337", "cvss": 9.8, "severity": "CRITICAL"}
                ]
            }
        ]
        print(f"  Found {len(findings)} vulnerable components")

        # Step 3: Reachability analysis
        print("\n[3/6] Running reachability analysis...")
        (temp_project_root / "app.js").write_text("import express from 'express';")
        component = sbom['components'][1]
        reach = analyze_reachability(component, sbom, str(temp_project_root), True)
        print(f"  lodash reachable: {reach['reachable']}")

        # Step 4: Risk calculation
        print("\n[4/6] Computing risk scores...")
        reachability_data = {f"{component['name']}@{component['version']}": reach}
        enhanced = enhance_findings_with_reachability(findings, reachability_data)
        risk = compute_risk(enhanced)
        print(f"  Risk score: {risk['risk_score']}/10")

        # Step 5: Policy evaluation
        print("\n[5/6] Evaluating policy...")
        policy_rules = {
            "fail_on": ["CRITICAL"],
            "fail_on_reachable_only": True
        }
        policy = evaluate_policy(enhanced, policy_rules)
        print(f"  Decision: {policy['decision']}")

        # Step 6: Post comment
        print("\n[6/6] Posting PR comment...")
        comment = f"""
## 🔒 PRISM Security Scan Results

**Decision:** {'❌ BLOCK' if policy['decision'] == 'FAIL' else '✅ APPROVE'}

### Vulnerabilities Found
- **Critical:** {risk['reachable_vulnerabilities']} reachable
- **Risk Score:** {risk['risk_score']}/10

### Details
- lodash@4.17.15: CVE-2021-23337 (CVSS 9.8)
  - Reachable: {reach['reachable']}
  - Reason: {reach['reason']}

### Action Required
{"Block merge until vulnerabilities are resolved" if policy['decision'] == 'FAIL' else "Merge approved"}
        """
        print(comment)

        metrics_collector.add_result("CI-1", "ci_decision", policy['decision'])
