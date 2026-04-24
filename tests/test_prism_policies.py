"""
PRISM Policy Engine Test Suite (Phase 3)

Tests the new policy types with exploitability support:
  - CVSS_ONLY: Block if CVSS >= 7
  - CVSS_STRICT: Block if CVSS >= 5
  - PRISM: Block if exploitability > 0.65
  - PRISM_STRICT: Block if exploitability > 0.45
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.policy_engine import (
    get_configured_policy_type,
    evaluate_cvss_only,
    evaluate_cvss_strict,
    evaluate_prism,
    evaluate_prism_strict,
    evaluate_policy_with_exploitability,
    SUPPORTED_POLICIES
)


class TestPolicyTypes:
    """Tests for policy type configuration and selection"""

    def test_supported_policies_defined(self):
        """Test: All required policy types are defined"""
        assert "CVSS_ONLY" in SUPPORTED_POLICIES
        assert "CVSS_STRICT" in SUPPORTED_POLICIES
        assert "PRISM" in SUPPORTED_POLICIES
        assert "PRISM_STRICT" in SUPPORTED_POLICIES

    def test_get_configured_policy_type_from_rules(self):
        """Test: Policy type is read from rules YAML"""
        rules = {"policy_type": "PRISM"}
        
        policy_type = get_configured_policy_type(rules)
        assert policy_type == "PRISM"

    def test_get_configured_policy_type_case_insensitive(self):
        """Test: Policy type matching is case-insensitive"""
        rules = {"policy_type": "prism_strict"}
        
        policy_type = get_configured_policy_type(rules)
        assert policy_type == "PRISM_STRICT"

    def test_get_configured_policy_type_default(self):
        """Test: Defaults to PRISM_STRICT if not configured"""
        policy_type = get_configured_policy_type()
        assert policy_type == "PRISM_STRICT"

    def test_get_configured_policy_type_invalid_falls_back(self):
        """Test: Invalid policy type falls back to PRISM_STRICT"""
        rules = {"policy_type": "INVALID_TYPE"}
        
        policy_type = get_configured_policy_type(rules)
        assert policy_type == "PRISM_STRICT"


class TestCVSSOnlyPolicy:
    """Tests for CVSS_ONLY policy (block if CVSS >= 7)"""

    def test_cvss_only_critical_cvss_9_5(self):
        """Test: CVSS 9.5 → FAIL"""
        risk_summary = {
            "max_cvss": 9.5,
            "overall_severity": "CRITICAL",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_only(risk_summary, findings)
        assert decision == "FAIL"
        assert "9.5" in reason

    def test_cvss_only_high_cvss_7_0(self):
        """Test: CVSS 7.0 → FAIL (boundary)"""
        risk_summary = {
            "max_cvss": 7.0,
            "overall_severity": "HIGH",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_only(risk_summary, findings)
        assert decision == "FAIL"

    def test_cvss_only_medium_cvss_5_5(self):
        """Test: CVSS 5.5 → WARN"""
        risk_summary = {
            "max_cvss": 5.5,
            "overall_severity": "MEDIUM",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_only(risk_summary, findings)
        assert decision == "WARN"

    def test_cvss_only_low_cvss_3_0(self):
        """Test: CVSS 3.0 → PASS"""
        risk_summary = {
            "max_cvss": 3.0,
            "overall_severity": "LOW",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_only(risk_summary, findings)
        assert decision == "PASS"


class TestCVSSStrictPolicy:
    """Tests for CVSS_STRICT policy (block if CVSS >= 5)"""

    def test_cvss_strict_cvss_8_0(self):
        """Test: CVSS 8.0 → FAIL"""
        risk_summary = {
            "max_cvss": 8.0,
            "overall_severity": "HIGH",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_strict(risk_summary, findings)
        assert decision == "FAIL"

    def test_cvss_strict_cvss_5_0_boundary(self):
        """Test: CVSS 5.0 → FAIL (boundary)"""
        risk_summary = {
            "max_cvss": 5.0,
            "overall_severity": "MEDIUM",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_strict(risk_summary, findings)
        assert decision == "FAIL"

    def test_cvss_strict_cvss_4_9(self):
        """Test: CVSS 4.9 → PASS"""
        risk_summary = {
            "max_cvss": 4.9,
            "overall_severity": "MEDIUM",
            "total_vulnerabilities": 1
        }
        findings = []
        
        decision, reason = evaluate_cvss_strict(risk_summary, findings)
        assert decision == "PASS"


class TestPRISMPolicy:
    """Tests for PRISM policy (block if exploitability > 0.65)"""

    def test_prism_exploitable_confidence_0_8(self):
        """Test: Exploitable with confidence 0.8 → FAIL"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": True,
                            "confidence": 0.8
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism(risk_summary, findings)
        assert decision == "FAIL"
        assert "exploitable" in reason.lower()

    def test_prism_not_exploitable_confidence_0_3(self):
        """Test: Not exploitable with confidence 0.3 → PASS"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 9.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.3
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism(risk_summary, findings)
        assert decision == "PASS"

    def test_prism_boundary_confidence_0_66(self):
        """Test: Confidence 0.66 (> 0.65) → FAIL"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": True,
                            "confidence": 0.66
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism(risk_summary, findings)
        assert decision == "FAIL"

    def test_prism_mixed_exploitability(self):
        """Test: Multiple vulns, only one exploitable → FAIL"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "pkg1", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-11111",
                        "cvss": 8.0,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.4
                        }
                    },
                    {
                        "id": "CVE-2021-22222",
                        "cvss": 7.0,
                        "exploitability": {
                            "exploitable": True,
                            "confidence": 0.75
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism(risk_summary, findings)
        assert decision == "FAIL"


class TestPRISMStrictPolicy:
    """Tests for PRISM_STRICT policy (block if exploitability > 0.45)"""

    def test_prism_strict_exploitable_confidence_0_8(self):
        """Test: Confidence 0.8 (> 0.65) → FAIL"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": True,
                            "confidence": 0.8
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism_strict(risk_summary, findings)
        assert decision == "FAIL"

    def test_prism_strict_moderate_confidence_0_55(self):
        """Test: Confidence 0.55 (0.45-0.65) → WARN"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.55
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism_strict(risk_summary, findings)
        assert decision == "WARN"

    def test_prism_strict_boundary_confidence_0_45(self):
        """Test: Confidence 0.45 (not > 0.45) → PASS or WARN"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.45
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism_strict(risk_summary, findings)
        # Should be PASS since 0.45 is not > 0.45
        assert decision == "PASS"

    def test_prism_strict_low_confidence_0_2(self):
        """Test: Confidence 0.2 (< 0.45) → PASS"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "lodash", "version": "4.17.20"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-23337",
                        "cvss": 9.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.2
                        }
                    }
                ]
            }
        ]
        
        decision, reason = evaluate_prism_strict(risk_summary, findings)
        assert decision == "PASS"


class TestPolicyWithExploitability:
    """Tests for the main policy evaluation function with exploitability"""

    def test_blocked_package_always_fails(self):
        """Test: Blocked package → FAIL regardless of policy type"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "blocked-pkg", "version": "1.0.0"},
                "vulnerabilities": []
            }
        ]
        rules = {"blocked_packages": ["blocked-pkg"]}
        
        for policy_type in SUPPORTED_POLICIES:
            decision, reason, details = evaluate_policy_with_exploitability(
                risk_summary, findings, rules, policy_type
            )
            assert decision == "FAIL"
            assert "Blocked" in reason

    def test_policy_selection_cvss_only(self):
        """Test: CVSS_ONLY policy is applied correctly"""
        risk_summary = {
            "max_cvss": 7.5,
            "overall_severity": "HIGH",
            "total_vulnerabilities": 1
        }
        findings = [
            {
                "component": {"name": "pkg1", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-11111",
                        "cvss": 7.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.2
                        }
                    }
                ]
            }
        ]
        
        decision, reason, details = evaluate_policy_with_exploitability(
            risk_summary, findings, None, "CVSS_ONLY"
        )
        # CVSS 7.5 >= 7 → FAIL
        assert decision == "FAIL"
        assert details["policy_type"] == "CVSS_ONLY"

    def test_policy_selection_prism(self):
        """Test: PRISM policy blocks only if exploitable"""
        risk_summary = {}
        findings = [
            {
                "component": {"name": "pkg1", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-11111",
                        "cvss": 9.5,  # Would fail CVSS_ONLY
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.3
                        }
                    }
                ]
            }
        ]
        
        decision, reason, details = evaluate_policy_with_exploitability(
            risk_summary, findings, None, "PRISM"
        )
        # Not exploitable → PASS (even with high CVSS)
        assert decision == "PASS"
        assert details["policy_type"] == "PRISM"

    def test_policy_auto_detection(self):
        """Test: Policy type is auto-detected from rules"""
        risk_summary = {
            "max_cvss": 5.5,
            "overall_severity": "MEDIUM",
            "total_vulnerabilities": 1
        }
        findings = [
            {
                "component": {"name": "pkg1", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-11111",
                        "cvss": 5.5,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.3
                        }
                    }
                ]
            }
        ]
        rules = {"policy_type": "CVSS_STRICT"}
        
        # CVSS 5.5 >= 5 with CVSS_STRICT → FAIL
        decision, reason, details = evaluate_policy_with_exploitability(
            risk_summary, findings, rules
        )
        assert decision == "FAIL"
        assert details["policy_type"] == "CVSS_STRICT"

    def test_comparison_policies_same_vuln(self):
        """
        Test: Same vulnerability evaluated under different policies shows context-aware difference.
        Scenario: High CVSS but not exploitable
        """
        risk_summary = {
            "max_cvss": 9.0,
            "overall_severity": "CRITICAL",
            "total_vulnerabilities": 1
        }
        findings = [
            {
                "component": {"name": "pkg1", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-11111",
                        "cvss": 9.0,
                        "exploitability": {
                            "exploitable": False,
                            "confidence": 0.2
                        }
                    }
                ]
            }
        ]
        
        # CVSS_ONLY should FAIL
        d1, _, _ = evaluate_policy_with_exploitability(risk_summary, findings, None, "CVSS_ONLY")
        assert d1 == "FAIL"
        
        # PRISM should PASS (not exploitable)
        d2, _, _ = evaluate_policy_with_exploitability(risk_summary, findings, None, "PRISM")
        assert d2 == "PASS"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
