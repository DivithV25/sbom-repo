import yaml
import re
from pathlib import Path
from typing import Tuple
from agent.config_loader import get_config

_PROJECT_ROOT = Path(__file__).parent.parent


def load_rules(rules_path=None):
    """Load policy rules from YAML file"""
    if rules_path is None:
        cfg = get_config()
        rules_path = cfg.get_python_rules_file()

    try:
        with open(rules_path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def check_blocked_packages(findings, rules):
    if not rules:
        return False, None

    blocked = rules.get("blocked_packages", [])

    for finding in findings:
        name = finding["component"]["name"]
        if name in blocked:
            return True, name

    return False, None


def evaluate_condition(condition: str, context: dict) -> bool:
    """
    Evaluate a simple conditional expression.

    Supports:
    - severity == "Critical"
    - reachable == true
    - severity in ["Low", "Medium"]
    - Combined with 'and', 'or'

    Args:
        condition: String like 'severity == "Critical" and reachable == true'
        context: Dict with values like {"severity": "CRITICAL", "reachable": True}

    Returns:
        bool: True if condition matches
    """
    # Normalize condition
    condition = condition.strip()

    # Replace context variables with their values
    # Handle quoted strings
    for key, value in context.items():
        # Convert Python booleans to lowercase for comparison
        if isinstance(value, bool):
            context[key] = str(value).lower()
        elif isinstance(value, str):
            context[key] = value

    # Simple pattern matching for common conditions
    # severity == "Critical"
    severity_match = re.search(r'severity\s*==\s*["\'](\w+)["\']', condition)
    if severity_match:
        expected_severity = severity_match.group(1).upper()
        actual_severity = context.get("severity", "UNKNOWN").upper()
        severity_ok = (expected_severity == actual_severity)
    else:
        severity_ok = True  # No severity condition

    # reachable == true/false
    reachable_match = re.search(r'reachable\s*==\s*(true|false)', condition, re.IGNORECASE)
    if reachable_match:
        expected_reachable = reachable_match.group(1).lower() == "true"
        actual_reachable = context.get("reachable", True)
        reachable_ok = (expected_reachable == actual_reachable)
    else:
        reachable_ok = True  # No reachability condition

    # severity in ["Low", "Medium"]
    severity_in_match = re.search(r'severity\s+in\s+\[(.*?)\]', condition)
    if severity_in_match:
        severity_list = [s.strip(' "\'').upper() for s in severity_in_match.group(1).split(',')]
        actual_severity = context.get("severity", "UNKNOWN").upper()
        severity_in_ok = actual_severity in severity_list
    else:
        severity_in_ok = True

    # Combine conditions with 'and'
    if ' and ' in condition.lower():
        return severity_ok and reachable_ok and severity_in_ok
    # Combine with 'or'
    elif ' or ' in condition.lower():
        # For OR, we need to re-evaluate each part
        # This is simplified - a full parser would be better
        return severity_ok or reachable_ok or severity_in_ok
    else:
        return severity_ok and reachable_ok and severity_in_ok


def evaluate_advanced_rules(risk_summary: dict, findings: list, rules: dict) -> tuple:
    """
    Evaluate advanced policy rules with conditional logic.

    Rules format:
    rules:
      - type: deny
        when: severity == "Critical" and reachable == true
        msg: "Critical & reachable → Block"
      - type: allow
        when: severity in ["Low", "Medium"]
        msg: "Low/Medium → Allow with warning"

    Returns:
        (decision, reason) or (None, None) if no rules match
    """
    if not rules or "rules" not in rules:
        return None, None

    rule_list = rules["rules"]
    max_severity = risk_summary.get("overall_severity", "UNKNOWN")
    reachable_vulns = risk_summary.get("reachable_vulnerabilities", 0)

    # Build context for condition evaluation
    context = {
        "severity": max_severity,
        "reachable": reachable_vulns > 0,
        "total_vulnerabilities": risk_summary.get("total_vulnerabilities", 0)
    }

    for rule in rule_list:
        rule_type = rule.get("type", "").lower()
        when_condition = rule.get("when", "")
        message = rule.get("msg", "Policy rule triggered")

        # Evaluate condition
        if evaluate_condition(when_condition, context):
            if rule_type == "deny":
                return "FAIL", message
            elif rule_type == "allow":
                return "PASS", message
            elif rule_type == "warn":
                return "WARN", message

    return None, None


def load_policy(policy_path=None):
    """Load policy gates from policies/default_policy.yaml (or a custom path)"""
    if policy_path is None:
        policy_path = _PROJECT_ROOT / "policies" / "default_policy.yaml"
    try:
        with open(policy_path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def evaluate_policy(risk_summary, findings, rules=None):
    """
    Evaluate security policy based on findings and configured rules.
    Simplified for Objectives 1 & 2 (no reachability analysis)

    Args:
        risk_summary: Risk summary with max_cvss, overall_severity
        findings: List of component findings with vulnerabilities
        rules: Optional rules dict from YAML file

    Returns:
        (decision, reason) tuple where decision is PASS/WARN/FAIL
    """
    # Rule 1: blocked package check
    if rules:
        blocked, pkg = check_blocked_packages(findings, rules)
        if blocked:
            return "FAIL", f"Blocked package detected: {pkg}"

    # Rule 2: Try advanced conditional rules (new format)
    if rules:
        decision, reason = evaluate_advanced_rules(risk_summary, findings, rules)
        if decision:
            return decision, reason

    # Rule 3: severity gate check (simple format - backward compatible)
    severity = risk_summary["overall_severity"]
    total_vulns = risk_summary.get("total_vulnerabilities", 0)

    # Get policy gates: rules file → policies/default_policy.yaml → hardcoded defaults
    if rules and "policy_gates" in rules:
        gates = rules["policy_gates"]
    else:
        policy = load_policy()
        gates = policy.get("policy_gates", {}) if policy else {}
    fail_on = gates.get("fail_on", ["CRITICAL", "HIGH"])
    warn_on = gates.get("warn_on", ["MEDIUM"])

    if severity in fail_on:
        return "FAIL", f"Severity threshold exceeded: {severity} vulnerabilities found ({total_vulns} total)"

    if severity in warn_on:
        return "WARN", f"Warning: {severity} severity vulnerabilities found - review recommended"

    # Check for UNKNOWN severity vulnerabilities (no CVSS score)
    unknown_count = sum(
        1 for f in findings
        for v in f["vulnerabilities"]
        if v.get("cvss", 0) == 0.0
    )

    if unknown_count > 0:
        return "WARN", f"Found {unknown_count} vulnerabilities without CVSS scores - manual review required"

    return "PASS", "No blocking issues"


# ============================================================================
# PRISM Phase 3: Policy Types with Exploitability Support
# ============================================================================

SUPPORTED_POLICIES = ["CVSS_ONLY", "CVSS_STRICT", "PRISM", "PRISM_STRICT"]

def get_configured_policy_type(rules=None, config=None) -> str:
    """
    Get the configured policy type from rules or config.

    Checks in order:
    1. rules["policy_type"] (from YAML)
    2. config setting
    3. Default: PRISM_STRICT

    Args:
        rules: Rules dict from YAML
        config: Config object from get_config()

    Returns:
        Policy type string (CVSS_ONLY, CVSS_STRICT, PRISM, PRISM_STRICT)
    """
    # Check rules first
    if rules and "policy_type" in rules:
        policy_type = rules["policy_type"].upper()
        if policy_type in SUPPORTED_POLICIES:
            return policy_type

    # Check config
    if config:
        try:
            policy_type = config.get_policy_type()
            if policy_type and policy_type.upper() in SUPPORTED_POLICIES:
                return policy_type.upper()
        except Exception:
            pass

    # Default to PRISM_STRICT
    return "PRISM_STRICT"


def evaluate_cvss_only(risk_summary: dict, findings: list) -> Tuple[str, str]:
    """
    CVSS_ONLY Policy: Block if CVSS >= 7

    Conservative CVSS-based approach (legacy).
    """
    max_cvss = risk_summary.get("max_cvss", 0.0)
    severity = risk_summary.get("overall_severity", "UNKNOWN")

    if max_cvss >= 7.0:
        return "FAIL", f"CVSS threshold exceeded: {max_cvss} >= 7.0 ({severity})"
    elif max_cvss >= 5.0:
        return "WARN", f"CVSS warning threshold: {max_cvss} (review recommended)"
    else:
        return "PASS", f"CVSS score acceptable: {max_cvss}"


def evaluate_cvss_strict(risk_summary: dict, findings: list) -> Tuple[str, str]:
    """
    CVSS_STRICT Policy: Block if CVSS >= 5

    Stricter CVSS-based approach.
    """
    max_cvss = risk_summary.get("max_cvss", 0.0)
    severity = risk_summary.get("overall_severity", "UNKNOWN")

    if max_cvss >= 5.0:
        return "FAIL", f"CVSS threshold exceeded: {max_cvss} >= 5.0 ({severity})"
    else:
        return "PASS", f"CVSS score acceptable: {max_cvss}"


def evaluate_prism(risk_summary: dict, findings: list) -> Tuple[str, str]:
    """
    PRISM Policy: Block if exploitability > 0.65

    Context-aware exploitability-based approach.
    Only blocks truly exploitable vulnerabilities.
    """
    # Count exploitable vulnerabilities
    exploitable_count = 0
    max_exploitability = 0.0

    for finding in findings:
        for vuln in finding.get("vulnerabilities", []):
            exploitability = vuln.get("exploitability", {})
            if isinstance(exploitability, dict):
                confidence = exploitability.get("confidence", 0.0)
                is_exploitable = exploitability.get("exploitable", False)

                if is_exploitable and confidence > 0.65:
                    exploitable_count += 1
                max_exploitability = max(max_exploitability, confidence)

    if exploitable_count > 0:
        return "FAIL", f"Found {exploitable_count} exploitable vulnerabilities (confidence > 0.65)"
    else:
        return "PASS", f"No highly exploitable vulnerabilities detected (max confidence: {max_exploitability:.2f})"


def evaluate_prism_strict(risk_summary: dict, findings: list) -> Tuple[str, str]:
    """
    PRISM_STRICT Policy: Block if exploitability > 0.45

    Strictest context-aware approach.
    """
    # Count exploitable vulnerabilities with stricter threshold
    exploitable_count = 0
    moderate_count = 0
    max_exploitability = 0.0

    for finding in findings:
        for vuln in finding.get("vulnerabilities", []):
            exploitability = vuln.get("exploitability", {})
            if isinstance(exploitability, dict):
                confidence = exploitability.get("confidence", 0.0)

                max_exploitability = max(max_exploitability, confidence)

                if confidence > 0.65:
                    exploitable_count += 1
                elif confidence > 0.45:
                    moderate_count += 1

    if exploitable_count > 0:
        return "FAIL", f"Found {exploitable_count} highly exploitable vulnerabilities"
    elif moderate_count > 0:
        return "WARN", f"Found {moderate_count} moderately exploitable vulnerabilities (0.45-0.65 confidence)"
    else:
        return "PASS", f"No exploitable vulnerabilities detected"


def evaluate_policy_with_exploitability(
    risk_summary: dict,
    findings: list,
    rules: dict = None,
    policy_type: str = None
) -> Tuple[str, str, dict]:
    """
    Evaluate security policy using PRISM phases (exploitability-aware).

    This is the new entry point for policy evaluation that supports
    both legacy CVSS-only and new PRISM exploitability-based policies.

    Args:
        risk_summary: Risk summary with max_cvss, overall_severity
        findings: List of findings with vulnerabilities
        rules: Optional rules dict from YAML
        policy_type: Policy type (CVSS_ONLY, CVSS_STRICT, PRISM, PRISM_STRICT)
                    If None, will be determined from rules/config

    Returns:
        (decision, reason, policy_details) tuple
    """
    # Determine policy type
    if not policy_type:
        cfg = get_config() if not rules else None
        policy_type = get_configured_policy_type(rules, cfg)

    policy_type = policy_type.upper()

    # Check blocked packages first (applies to all policies)
    if rules:
        blocked, pkg = check_blocked_packages(findings, rules)
        if blocked:
            return "FAIL", f"Blocked package detected: {pkg}", {
                "policy_type": policy_type,
                "reason": "blocked_package"
            }

    # Evaluate based on policy type
    if policy_type == "CVSS_ONLY":
        decision, reason = evaluate_cvss_only(risk_summary, findings)
    elif policy_type == "CVSS_STRICT":
        decision, reason = evaluate_cvss_strict(risk_summary, findings)
    elif policy_type == "PRISM":
        decision, reason = evaluate_prism(risk_summary, findings)
    elif policy_type == "PRISM_STRICT":
        decision, reason = evaluate_prism_strict(risk_summary, findings)
    else:
        # Fallback to legacy policy
        decision, reason = evaluate_policy(risk_summary, findings, rules)
        policy_type = "LEGACY"

    return decision, reason, {
        "policy_type": policy_type,
        "reason": reason
    }