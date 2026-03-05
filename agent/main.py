import argparse
import os
from agent.sbom_parser import load_sbom, extract_components
from agent.osv_client import query_osv, get_cache_stats
from agent.risk_engine import compute_risk
from agent.policy_engine import load_rules, evaluate_policy
from agent.reporter import save_outputs
from agent.compact_reporter import generate_compact_markdown_report
from agent.remediation_advisor import generate_remediation_summary


def main():
    parser = argparse.ArgumentParser(
        description="PRISM - Pull-Request Integrated Security Mechanism (Enhanced)"
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
        "--previous-sbom",
        help="Path to previous SBOM for diff comparison",
        default=None
    )
    parser.add_argument(
        "--no-cache",
        help="Disable vulnerability caching",
        action="store_true"
    )
    parser.add_argument(
        "--no-parallel",
        help="Disable parallel scanning",
        action="store_true"
    )
    parser.add_argument(
        "--enable-updates",
        help="Enable automated update recommendations",
        action="store_true"
    )
    parser.add_argument(
        "--log-dashboard",
        help="Log results to dashboard",
        action="store_true"
    )

    args = parser.parse_args()

    # Check AI configuration
    from agent.config_loader import get_config
    cfg = get_config()
    use_ai = (not args.no_ai) and cfg.is_ai_enabled()
    use_cache = not args.no_cache
    use_parallel = not args.no_parallel

    print("🔐 PRISM - Pull-Request Integrated Security Mechanism\n")
    print(f"   🤖 AI Remediation: {'ENABLED' if use_ai else 'DISABLED'}")
    print(f"   ⚡ Performance Cache: {'ENABLED' if use_cache else 'DISABLED'}")
    print(f"   🚀 Parallel Scanning: {'ENABLED' if use_parallel else 'DISABLED'}")
    print(f"   📊 SBOM Diff: {'ENABLED' if args.previous_sbom else 'DISABLED'}")
    print(f"   🔄 Auto Updates: {'ENABLED' if args.enable_updates else 'DISABLED'}")
    print()

    # Load SBOM and extract components
    sbom_json = load_sbom(args.sbom)
    components = extract_components(sbom_json)

    # SBOM Diff Analysis
    sbom_diff_results = None
    if args.previous_sbom and os.path.exists(args.previous_sbom):
        print("📊 Analyzing dependency changes...")
        from agent.sbom_differ import SBOMDiffer
        from agent.change_analyzer import ChangeAnalyzer

        differ = SBOMDiffer()
        analyzer = ChangeAnalyzer()

        prev_sbom = load_sbom(args.previous_sbom)
        changes = differ.compare(prev_sbom, sbom_json)
        summary = differ.get_summary(changes)

        print(f"   ↳ {summary['total_changes']} changes detected")
        print(f"     Added: {summary['added']}, Removed: {summary['removed']}")
        print(f"     Upgraded: {summary['upgraded']}, Downgraded: {summary['downgraded']}\n")

        # Analyze security impact
        change_analysis = analyzer.analyze_all_changes(changes, scan_vulnerabilities=use_cache)

        sbom_diff_results = {
            'summary': summary,
            'changes': changes,
            'markdown': analyzer.format_markdown(change_analysis)
        }

    findings = []

    print(f"🔍 Scanning {len(components)} component(s) for vulnerabilities...")
    print(f"   Source: OSV (Open Source Vulnerabilities)\n")

    # Choose scanning strategy based on flags
    if use_parallel and len(components) > 1:
        print("   🚀 Using parallel scanning for faster results...")
        from agent.parallel_scanner import ParallelScanner

        scanner = ParallelScanner(max_workers=5, show_progress=True)
        vulnerability_map = scanner.scan_components(
            components,
            scanner_func=lambda c: query_osv(c["name"], c["version"], c.get("ecosystem"), use_cache=use_cache)
        )

        # Convert map to findings format
        for comp in components:
            key = f"{comp['name']}@{comp['version']}"
            vulns = vulnerability_map.get(key, [])
            findings.append({
                "component": comp,
                "vulnerabilities": vulns
            })
        print()
    else:
        # Sequential scanning (original behavior)
        for comp in components:
            print(f"   🔍 Querying for {comp.get('name')}@{comp.get('version')}...")
            vulns = query_osv(comp["name"], comp["version"], comp.get("ecosystem"), use_cache=use_cache)

            findings.append({
                "component": comp,
                "vulnerabilities": vulns
            })

        print()

    # Show cache statistics if caching was used
    if use_cache:
        cache_stats = get_cache_stats()
        if cache_stats['total_requests'] > 0:
            print(f"   📊 Cache Performance:")
            print(f"      Hits: {cache_stats['hits']}, Misses: {cache_stats['misses']}")
            print(f"      Hit Rate: {cache_stats['hit_rate_percent']:.1f}%\n")

    risk_summary = compute_risk(findings)

    # Automated Update Recommendations
    update_recommendations = None
    if args.enable_updates:
        print("🔄 Checking for automated update recommendations...")
        from agent.auto_updater import AutoUpdater

        updater = AutoUpdater()
        vulnerable_components = [f for f in findings if f.get('vulnerabilities')]

        if vulnerable_components:
            update_recommendations = updater.batch_analyze_updates(vulnerable_components)
            print(f"   ↳ {len(update_recommendations)} update(s) available\n")
        else:
            print(f"   ↳ No updates needed\n")

    # Generate remediation advice
    print("💊 Generating remediation recommendations...")

    # Use AI remediation by default (unless --no-ai flag is set)
    if use_ai:
        from agent.ai_remediation_advisor import generate_ai_remediation_summary
        remediations = generate_ai_remediation_summary(findings)
    else:
        remediations = generate_remediation_summary(findings)

    rules = load_rules(args.rules) if args.rules else None

    # Use Python-based policy evaluation
    decision, reason = evaluate_policy(risk_summary, findings, rules)

    # Generate compact markdown report with collapsible sections
    markdown = generate_compact_markdown_report(
        risk_summary,
        findings,
        decision,
        reason,
        remediations=remediations,
        sbom_diff=sbom_diff_results,
        update_recommendations=update_recommendations,
        cache_stats=get_cache_stats() if use_cache else None
    )

    report_data = {
        "risk_summary": risk_summary,
        "decision": decision,
        "reason": reason,
        "findings": findings,
        "remediations": remediations,
        "sbom_diff": sbom_diff_results,
        "update_recommendations": update_recommendations
    }

    save_outputs(args.output, markdown, report_data)

    # Log to dashboard if requested
    if args.log_dashboard:
        try:
            from agent.dashboard_aggregator import DashboardAggregator

            aggregator = DashboardAggregator()
            aggregator.log_scan_result(
                total_components=len(components),
                total_vulnerabilities=risk_summary['total_vulnerabilities'],
                max_cvss=risk_summary.get('max_cvss', 0),
                overall_severity=risk_summary.get('overall_severity', 'UNKNOWN'),
                risk_score=risk_summary.get('risk_score', 0),
                policy_decision=decision,
                branch=os.environ.get('GITHUB_REF_NAME', 'unknown'),
                commit_sha=os.environ.get('GITHUB_SHA', 'unknown')
            )
            print("\n📊 Results logged to dashboard")
        except Exception as e:
            print(f"\n⚠️  Dashboard logging failed: {e}")

    print(markdown)


if __name__ == "__main__":
    main()