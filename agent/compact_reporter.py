"""
Enhanced reporter with collapsible sections for better PR comment UX
"""

import json
import os


def generate_compact_markdown_report(
    risk_summary,
    findings,
    decision,
    reason,
    remediations=None,
    sbom_diff=None,
    update_recommendations=None,
    cache_stats=None
):
    """
    Generate compact markdown report with collapsible sections

    Args:
        risk_summary: Risk analysis summary
        findings: Vulnerability findings
        decision: Policy decision
        reason: Policy decision reason
        remediations: Remediation recommendations
        sbom_diff: SBOM diff results (optional)
        update_recommendations: Auto-update recommendations (optional)
        cache_stats: Performance cache statistics (optional)

    Returns:
        Markdown formatted string
    """
    lines = []

    # 🎯 Executive Summary (Always Visible)
    lines.append("# 🔐 PRISM Security Scan Results\n\n")

    # Decision badge
    decision_emoji = {
        "PASS": "✅",
        "WARN": "⚠️",
        "FAIL": "❌"
    }.get(decision, "❓")

    severity_badge = _get_severity_badge(risk_summary.get('overall_severity', 'UNKNOWN'))

    lines.append(f"## {decision_emoji} {decision}\n\n")
    lines.append("| Metric | Value |\n")
    lines.append("|--------|-------|\n")
    lines.append(f"| **Severity** | {severity_badge} |\n")
    lines.append(f"| **Risk Score** | {risk_summary.get('risk_score', 0):.1f} / 10 |\n")
    lines.append(f"| **Vulnerabilities** | {risk_summary['total_vulnerabilities']} found |\n")
    lines.append(f"| **Max CVSS** | {risk_summary.get('max_cvss', 0):.1f} |\n")

    if cache_stats:
        hit_rate = cache_stats.get('hit_rate_percent', 0)
        lines.append(f"| **Cache Performance** | {hit_rate:.0f}% hit rate |\n")

    lines.append("\n")

    # Policy reason
    if reason:
        lines.append(f"> {reason}\n\n")

    lines.append("---\n\n")

    # 📊 SBOM Changes (if available) - Collapsible
    if sbom_diff:
        summary = sbom_diff.get('summary', {})
        total_changes = summary.get('total_changes', 0)

        if total_changes > 0:
            lines.append("<details>\n")
            lines.append(f"<summary><b>📊 Dependency Changes ({total_changes} changes)</b></summary>\n\n")
            lines.append(sbom_diff.get('markdown', ''))
            lines.append("\n</details>\n\n")

    # 🔄 Update Recommendations (if available) - Collapsible
    if update_recommendations:
        update_count = len(update_recommendations)
        if update_count > 0:
            lines.append("<details>\n")
            lines.append(f"<summary><b>🔄 Automated Update Recommendations ({update_count} available)</b></summary>\n\n")

            # Group by priority
            high_priority = [r for r in update_recommendations if r.get('severity') in ['CRITICAL', 'HIGH']]
            other = [r for r in update_recommendations if r.get('severity') not in ['CRITICAL', 'HIGH']]

            if high_priority:
                lines.append("### 🔴 High Priority Updates\n\n")
                for rec in high_priority:
                    lines.append(f"- **`{rec['package_name']}`**: {rec['current_version']} → {rec['recommended_version']}\n")
                    lines.append(f"  - Fixes {rec['vulnerabilities_fixed']} vulnerabilities\n")
                    lines.append(f"  - Breaking changes: {'Yes' if rec['breaking_changes'] else 'No'}\n\n")

            if other:
                lines.append("<details>\n")
                lines.append(f"<summary>Other Updates ({len(other)})</summary>\n\n")
                for rec in other:
                    lines.append(f"- `{rec['package_name']}`: {rec['current_version']} → {rec['recommended_version']}\n")
                lines.append("\n</details>\n")

            lines.append("\n</details>\n\n")

    # 🐛 Vulnerable Components - Collapsible
    vuln_findings = [f for f in findings if f.get('vulnerabilities')]
    if vuln_findings:
        lines.append("<details>\n")
        lines.append(f"<summary><b>🐛 Vulnerable Components ({len(vuln_findings)} affected)</b></summary>\n\n")

        for finding in vuln_findings:
            comp = finding["component"]
            vulns = finding["vulnerabilities"]

            lines.append(f"### `{comp['name']}@{comp['version']}`\n\n")

            # Show top 3 vulnerabilities, collapse rest
            shown_vulns = vulns[:3]
            hidden_vulns = vulns[3:]

            for vuln in shown_vulns:
                lines.append(f"- **{vuln.get('id', 'UNKNOWN')}**")
                if vuln.get('cvss'):
                    severity = _cvss_to_severity(vuln['cvss'])
                    lines.append(f" - CVSS {vuln['cvss']} ({severity})")
                lines.append("\n")

            if hidden_vulns:
                lines.append(f"\n<details>\n<summary>Show {len(hidden_vulns)} more...</summary>\n\n")
                for vuln in hidden_vulns:
                    lines.append(f"- {vuln.get('id', 'UNKNOWN')}")
                    if vuln.get('cvss'):
                        lines.append(f" - CVSS {vuln['cvss']}")
                    lines.append("\n")
                lines.append("\n</details>\n")

            lines.append("\n")

        lines.append("</details>\n\n")
    else:
        lines.append("✅ **No vulnerabilities detected!**\n\n")

    # 💊 Remediation Advice - Collapsible
    if remediations:
        ai_remediations = [r for r in remediations if r.get('advice', {}).get('ai_generated')]
        basic_remediations = [r for r in remediations if not r.get('advice', {}).get('ai_generated')]

        if ai_remediations:
            lines.append("<details>\n")
            lines.append(f"<summary><b>🤖 AI-Powered Remediation Advice ({len(ai_remediations)} recommendations)</b></summary>\n\n")

            for remediation in ai_remediations:
                comp = remediation.get('component', {})
                advice = remediation.get('advice', {})

                lines.append(f"### `{comp.get('name')}@{comp.get('version')}`\n\n")

                if advice.get('summary'):
                    lines.append(f"**Summary:** {advice['summary']}\n\n")

                # Compact remediation plan
                plan = advice.get('remediation_plan')
                if isinstance(plan, dict):
                    if plan.get('recommended_version'):
                        lines.append(f"**Upgrade to:** `{plan['recommended_version']}`\n\n")
                    if plan.get('upgrade_command'):
                        lines.append(f"```bash\n{plan['upgrade_command']}\n```\n\n")

                # Collapse detailed analysis
                lines.append("<details>\n<summary>Show detailed analysis</summary>\n\n")

                if advice.get('impact_analysis'):
                    lines.append("**Impact Analysis:**\n")
                    _append_dict_or_text(lines, advice['impact_analysis'])

                if advice.get('risk_explanation'):
                    lines.append("\n**Why This Matters:**\n")
                    _append_dict_or_text(lines, advice['risk_explanation'])

                if advice.get('estimated_effort'):
                    lines.append("\n**Estimated Effort:**\n")
                    _append_dict_or_text(lines, advice['estimated_effort'])

                lines.append("\n</details>\n\n")

            lines.append("</details>\n\n")

    # Footer
    lines.append("---\n\n")
    lines.append("*Generated by PRISM - Pull-Request Integrated Security Mechanism*\n")
    lines.append(f"*Features: SBOM Generation | OSV Scanning | AI Remediation | Policy Gates*\n")

    return ''.join(lines)


def _get_severity_badge(severity):
    """Get colored severity badge"""
    badges = {
        'CRITICAL': '🔴 **CRITICAL**',
        'HIGH': '🟠 **HIGH**',
        'MEDIUM': '🟡 **MEDIUM**',
        'LOW': '🟢 **LOW**',
        'UNKNOWN': '⚪ **UNKNOWN**'
    }
    return badges.get(severity, severity)


def _cvss_to_severity(cvss):
    """Convert CVSS score to severity"""
    if cvss >= 9.0:
        return 'CRITICAL'
    elif cvss >= 7.0:
        return 'HIGH'
    elif cvss >= 4.0:
        return 'MEDIUM'
    elif cvss > 0:
        return 'LOW'
    return 'UNKNOWN'


def _append_dict_or_text(lines, content):
    """Helper to append dictionary or text content"""
    if isinstance(content, dict):
        for key, value in content.items():
            formatted_key = key.replace('_', ' ').title()
            lines.append(f"- **{formatted_key}:** {value}\n")
    else:
        lines.append(f"{content}\n")


# Keep original function for backward compatibility
def generate_markdown_report(risk_summary, findings, decision, reason, remediations=None):
    """Original reporter - kept for backward compatibility"""
    from agent.reporter import generate_markdown_report as original_reporter
    return original_reporter(risk_summary, findings, decision, reason, remediations)


def save_outputs(output_dir, markdown, report_data):
    """Save report outputs"""
    os.makedirs(output_dir, exist_ok=True)

    # Save markdown
    with open(f"{output_dir}/pr_comment.md", "w", encoding="utf-8") as f:
        f.write(markdown)

    # Save JSON
    with open(f"{output_dir}/report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
