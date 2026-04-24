from agent.utils import cvss_to_severity
from agent.config_loader import get_config
from agent.exploitability_engine import analyze_all_vulnerabilities
from typing import Dict, List, Any


def compute_risk(findings):
    """
    Compute risk score using formula: Risk = f(Vulnerability Count + CVSS)
    Simplified version for Objectives 1 & 2 (no reachability analysis)

    Returns:
        {
            "max_cvss": float,
            "overall_severity": str,
            "total_vulnerabilities": int,
            "risk_score": float,  # 0-10 scale
        }
    """
    max_cvss = 0.0
    total_vulns = 0

    # Cumulative risk factors
    weighted_cvss_sum = 0.0

    for finding in findings:
        for vuln in finding["vulnerabilities"]:
            total_vulns += 1
            cvss = vuln.get("cvss", 0.0) or 0.0

            weighted_cvss_sum += cvss

            # Track max CVSS overall
            if cvss > max_cvss:
                max_cvss = cvss

    # Calculate composite risk score (0-10 scale)
    # Load weights from configuration
    cfg = get_config()
    weights = cfg.get_risk_weights()
    max_vuln_factor = cfg.get_max_vuln_count_factor()
    multiplier = cfg.get_vuln_count_multiplier()

    # Vulnerability count factor (normalized, capped at max_vuln_factor)
    vuln_count_factor = min(total_vulns * multiplier, max_vuln_factor)

    # CVSS factor (use max CVSS)
    cvss_factor = max_cvss

    # Simplified weighted composite score (no reachability)
    risk_score = (
        (weights['vulnerability_count'] * vuln_count_factor) +
        (weights['cvss_score'] * cvss_factor)
    )
    risk_score = round(risk_score, 2)

    overall_severity = cvss_to_severity(max_cvss)

    return {
        "max_cvss": max_cvss,
        "overall_severity": overall_severity,
        "total_vulnerabilities": total_vulns,
        "risk_score": risk_score
    }


def compute_exploitability(findings: List[Dict[str, Any]], pr_diff: str = None) -> Dict[str, Any]:
    """
    PRISM Phase 1: Compute exploitability scores for all vulnerabilities.

    Enhances findings with exploitability assessment (confidence score).

    Args:
        findings: List of findings with component and vulnerabilities
        pr_diff: Optional git diff content for context-aware analysis

    Returns:
        Dictionary with exploitability summary:
        {
            "exploitable_count": int,
            "total_assessed": int,
            "avg_confidence": float,
            "max_confidence": float,
            "by_severity": {},  # Exploitable count by severity
            "findings": []  # Enhanced findings with exploitability
        }
    """
    # Analyze all vulnerabilities with exploitability engine
    enhanced_findings = []
    exploitable_count = 0
    confidences = []

    for finding in findings:
        component = finding.get("component", {})
        vulnerabilities = finding.get("vulnerabilities", [])

        enhanced_vulns = []
        for vuln in vulnerabilities:
            # Already has exploitability from analyze_all_vulnerabilities, or compute it
            if "exploitability" not in vuln:
                from agent.exploitability_engine import analyze_vulnerability
                assessment = analyze_vulnerability(
                    component_name=component.get("name", "unknown"),
                    component_version=component.get("version", "unknown"),
                    cve=vuln.get("id", "unknown"),
                    affected_functions=vuln.get("affected_functions", []),
                    pr_diff=pr_diff,
                    is_direct=component.get("is_direct", True),
                    ecosystem=component.get("ecosystem")
                )
                vuln["exploitability"] = assessment
            else:
                assessment = vuln["exploitability"]

            # Track metrics
            confidence = assessment.get("confidence", 0.0)
            confidences.append(confidence)

            if assessment.get("exploitable", False):
                exploitable_count += 1

            enhanced_vulns.append(vuln)

        enhanced_findings.append({
            "component": component,
            "vulnerabilities": enhanced_vulns
        })

    # Compute summary
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    max_confidence = max(confidences) if confidences else 0.0

    # Group exploitable by severity
    exploitable_by_severity = {}
    for finding in enhanced_findings:
        for vuln in finding["vulnerabilities"]:
            if vuln.get("exploitability", {}).get("exploitable"):
                severity = cvss_to_severity(vuln.get("cvss", 0.0))
                exploitable_by_severity[severity] = exploitable_by_severity.get(severity, 0) + 1

    return {
        "exploitable_count": exploitable_count,
        "total_assessed": len(confidences),
        "avg_confidence": round(avg_confidence, 3),
        "max_confidence": round(max_confidence, 3),
        "by_severity": exploitable_by_severity,
        "findings": enhanced_findings
    }


def compute_risk_with_exploitability(
    findings: List[Dict[str, Any]],
    pr_diff: str = None
) -> Dict[str, Any]:
    """
    Enhanced risk computation that includes exploitability analysis.

    Combines traditional CVSS risk scoring with PRISM exploitability.

    Args:
        findings: List of findings
        pr_diff: Optional PR diff for exploitability analysis

    Returns:
        Risk summary with both CVSS and exploitability metrics
    """
    # Compute traditional CVSS-based risk
    cvss_risk = compute_risk(findings)

    # Compute exploitability
    exploitability_analysis = compute_exploitability(findings, pr_diff)

    # Merge results
    return {
        **cvss_risk,
        "exploitability": exploitability_analysis,
        "truly_exploitable": exploitability_analysis["exploitable_count"],
        "exploitability_ratio": round(
            exploitability_analysis["exploitable_count"] / max(exploitability_analysis["total_assessed"], 1),
            3
        )
    }