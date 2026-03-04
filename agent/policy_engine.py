import yaml


def load_rules(rules_path):
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


def evaluate_policy(risk_summary, findings, rules=None):
    """
    Evaluate security policy based on findings and configured rules.
    
    Args:
        risk_summary: Risk summary with max_cvss, overall_severity, etc.
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
    
    # Rule 2: severity gate check (configurable)
    severity = risk_summary["overall_severity"]
    
    # Get policy gates from rules or use defaults
    if rules and "policy_gates" in rules:
        fail_on = rules["policy_gates"].get("fail_on", ["CRITICAL", "HIGH"])
        warn_on = rules["policy_gates"].get("warn_on", ["MEDIUM"])
    else:
        # Default behavior: FAIL on CRITICAL/HIGH, WARN on MEDIUM
        fail_on = ["CRITICAL", "HIGH"]
        warn_on = ["MEDIUM"]
    
    if severity in fail_on:
        return "FAIL", f"Severity threshold exceeded: {severity} vulnerabilities found"
    
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