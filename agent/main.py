import argparse
import json
import os
from pathlib import Path
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import generate_markdown_report, save_outputs
from agent.remediation_advisor import generate_remediation_summary


def save_decision_status(output_dir: str, decision: str, reason: str, risk_summary: dict):
    """
    Save decision status to a file for CI/CD pipeline to read.
    
    This creates a decision.json file that contains:
    - decision (PASS/WARN/FAIL)
    - reason (explanation)
    - risk_summary (severity, counts, etc.)
    
    Used by GitHub Actions workflow to determine if PR should be blocked.
    
    Args:
        output_dir: Output directory path
        decision: The security decision (PASS, WARN, FAIL)
        reason: Reason for the decision
        risk_summary: Summary of detected risks
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    decision_file = output_path / "decision.json"
    
    decision_data = {
        "decision": decision,
        "reason": reason,
        "overall_severity": risk_summary.get("overall_severity", "UNKNOWN"),
        "total_vulnerabilities": risk_summary.get("total_vulnerabilities", 0),
        "critical_vulnerabilities": risk_summary.get("critical_vulnerabilities", 0),
        "high_vulnerabilities": risk_summary.get("high_vulnerabilities", 0),
        "medium_vulnerabilities": risk_summary.get("medium_vulnerabilities", 0),
        "low_vulnerabilities": risk_summary.get("low_vulnerabilities", 0),
        "reachable_vulnerabilities": risk_summary.get("reachable_vulnerabilities", 0),
        "risk_score": risk_summary.get("risk_score", 0.0)
    }
    
    with open(str(decision_file), 'w') as f:
        json.dump(decision_data, f, indent=2)
    
    print(f"\n📋 Decision status saved to: {decision_file}")


def main():
    parser = argparse.ArgumentParser(
        description="PRISM - Pull-Request Integrated Security Mechanism (Objectives 1 & 2)"
    )
    parser.add_argument("sbom", help="Path to SBOM JSON file")
    parser.add_argument("--rules", help="Path to rules YAML file", default=None)
    parser.add_argument("--output", help="Output directory", default="output")
    parser.add_argument(
        "--no-ai",
        help="Disable AI-powered remediation (AI is enabled by default)",
        action="store_true"
    )

    args = parser.parse_args()

    # IMPORTANT: Cache invalidation happens in osv_client.query_osv()
    # When dependency manifests (package.json, requirements.txt, etc.) change,
    # the .prism_cache directory is automatically cleared to prevent stale
    # vulnerability data. This ensures accurate results even when running
    # multiple scans on the same PR with different package versions.
    # See: agent/osv_client.py::_invalidate_cache_if_needed()

    # Check AI configuration
    from agent.config_loader import get_config
    cfg = get_config()
    use_ai = (not args.no_ai) and cfg.is_ai_enabled()

    if use_ai:
        print("🤖 AI-powered smart remediation: ENABLED\n")

    # Load SBOM and extract components
    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    findings = []

    print(f"🔍 Scanning {len(components)} component(s) for vulnerabilities...")
    print(f"   Source: OSV (Open Source Vulnerabilities)\n")

    # Scan each component using OSV
    for comp in components:
        print(f"   🔍 Querying vulnerability databases for {comp.get('name')}@{comp.get('version')}...")
        vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"))

        findings.append({
            "component": comp,
            "vulnerabilities": vulns
        })

        print()  # Blank line between components

    risk_summary = compute_risk(findings)

    # Generate remediation advice
    print("\n💊 Generating remediation recommendations...")

    # Use AI remediation by default (unless --no-ai flag is set)
    if use_ai:
        from agent.ai_remediation_advisor import generate_ai_remediation_summary
        remediations = generate_ai_remediation_summary(findings)
    else:
        remediations = generate_remediation_summary(findings)

    # Propagate alternative packages from remediations back to findings for inline display
    for remediation in remediations:
        advice = remediation.get("advice", {})
        alternatives = advice.get("alternative_packages", [])
        if alternatives:
            # Find matching finding and add alternatives to component
            comp_name = remediation.get("component", {}).get("name")
            for finding in findings:
                if finding.get("component", {}).get("name") == comp_name:
                    finding["component"]["alternative_packages"] = alternatives
                    break

    rules = load_rules(args.rules)

    # Use Python-based policy evaluation (OPA removed)
    decision, reason = evaluate_policy(risk_summary, findings, rules)

    markdown = generate_markdown_report(
        risk_summary, findings, decision, reason, remediations, rules=rules
    )

    report_data = {
        "risk_summary": risk_summary,
        "decision": decision,
        "reason": reason,
        "findings": findings,
        "remediations": remediations
    }

    save_outputs(args.output, markdown, report_data)
    
    # Save decision status for CI/CD pipeline to read
    save_decision_status(args.output, decision, reason, risk_summary)

    print(markdown)


if __name__ == "__main__":
    main()