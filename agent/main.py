import argparse
import json
import os
from pathlib import Path
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv
from agent.risk_engine import compute_risk, compute_risk_with_exploitability
from agent.policy_engine import load_rules, evaluate_policy, evaluate_policy_with_exploitability, get_configured_policy_type
from agent.reporter import generate_markdown_report, save_outputs
from agent.remediation_advisor import generate_remediation_summary


def save_decision_status(output_dir: str, decision: str, reason: str, risk_summary: dict, policy_type: str = "PRISM_STRICT"):
    """
    Save decision status to a file for CI/CD pipeline to read.
    
    This creates a decision.json file that contains:
    - decision (PASS/WARN/FAIL)
    - reason (explanation)
    - risk_summary (severity, counts, CVSS, exploitability metrics)
    - policy_type (which policy was used)
    
    Used by GitHub Actions workflow to determine if PR should be blocked.
    
    Args:
        output_dir: Output directory path
        decision: The security decision (PASS, WARN, FAIL)
        reason: Reason for the decision
        risk_summary: Summary of detected risks (includes exploitability)
        policy_type: Policy type used for evaluation
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    decision_file = output_path / "decision.json"
    
    exploitability = risk_summary.get("exploitability", {})
    
    decision_data = {
        "decision": decision,
        "reason": reason,
        "policy_type": policy_type,
        "overall_severity": risk_summary.get("overall_severity", "UNKNOWN"),
        "total_vulnerabilities": risk_summary.get("total_vulnerabilities", 0),
        "critical_vulnerabilities": risk_summary.get("critical_vulnerabilities", 0),
        "high_vulnerabilities": risk_summary.get("high_vulnerabilities", 0),
        "medium_vulnerabilities": risk_summary.get("medium_vulnerabilities", 0),
        "low_vulnerabilities": risk_summary.get("low_vulnerabilities", 0),
        "reachable_vulnerabilities": risk_summary.get("reachable_vulnerabilities", 0),
        "risk_score": risk_summary.get("risk_score", 0.0),
        "exploitability": {
            "truly_exploitable": risk_summary.get("truly_exploitable", 0),
            "exploitability_ratio": risk_summary.get("exploitability_ratio", 0.0),
            "avg_confidence": exploitability.get("avg_confidence", 0.0),
            "max_confidence": exploitability.get("max_confidence", 0.0)
        }
    }
    
    with open(str(decision_file), 'w') as f:
        json.dump(decision_data, f, indent=2)
    
    print(f"📋 Decision status saved to: {decision_file}")


def main():
    parser = argparse.ArgumentParser(
        description="PRISM - Pull-Request Integrated Security Mechanism (Phases 1-3)"
    )
    parser.add_argument("sbom", help="Path to SBOM JSON file")
    parser.add_argument("--rules", help="Path to rules YAML file", default=None)
    parser.add_argument("--output", help="Output directory", default="output")
    parser.add_argument(
        "--no-ai",
        help="Disable AI-powered remediation (AI is enabled by default)",
        action="store_true"
    )
    parser.add_argument(
        "--diff",
        help="Path to git diff file for exploitability context analysis",
        default=None
    )
    parser.add_argument(
        "--policy",
        help=f"Policy type: CVSS_ONLY, CVSS_STRICT, PRISM, PRISM_STRICT (default: PRISM_STRICT)",
        default=None
    )

    args = parser.parse_args()

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

    # Load PR diff if provided
    pr_diff = None
    if args.diff and os.path.exists(args.diff):
        try:
            with open(args.diff, 'r') as f:
                pr_diff = f.read()
            print(f"📝 PR diff loaded from: {args.diff}\n")
        except Exception as e:
            print(f"⚠️  Failed to load PR diff: {e}\n")

    # Compute risk with exploitability analysis (Phase 1)
    print("🔬 PRISM Phase 1: Computing exploitability scores...")
    risk_summary = compute_risk_with_exploitability(findings, pr_diff)
    print(f"   ✓ Total vulnerabilities: {risk_summary['total_vulnerabilities']}")
    print(f"   ✓ Truly exploitable: {risk_summary.get('truly_exploitable', 0)}")
    print(f"   ✓ Avg. exploitability confidence: {risk_summary['exploitability']['avg_confidence']}\n")

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

    # PRISM Phase 3: Evaluate policy with exploitability (context-aware)
    print("🛡️  PRISM Phase 3: Evaluating security policy...")
    policy_type = args.policy or get_configured_policy_type(rules, cfg)
    print(f"   Policy Type: {policy_type}")
    
    # Use new exploitability-aware policy evaluation
    decision, reason, policy_details = evaluate_policy_with_exploitability(
        risk_summary, 
        risk_summary.get("exploitability", {}).get("findings", findings),
        rules,
        policy_type
    )
    print(f"   Decision: {decision} - {reason}\n")

    markdown = generate_markdown_report(
        risk_summary, findings, decision, reason, remediations, rules=rules, policy_type=policy_type
    )

    report_data = {
        "risk_summary": risk_summary,
        "decision": decision,
        "reason": reason,
        "policy_type": policy_type,
        "findings": findings,
        "remediations": remediations
    }

    save_outputs(args.output, markdown, report_data)
    
    # Save decision status for CI/CD pipeline to read
    save_decision_status(args.output, decision, reason, risk_summary, policy_type)

    print(markdown)


if __name__ == "__main__":
    main()