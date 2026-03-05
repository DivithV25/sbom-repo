import json
import os


def generate_markdown_report(risk_summary, findings, decision, reason, remediations=None):
    lines = []
    lines.append("# PRISM Security Scan Results\n")

    # Decision indicator
    decision_symbol = {
        "PASS": "✓",
        "WARN": "!",
        "FAIL": "✗"
    }.get(decision, "?")

    lines.append(f"**Decision:** {decision_symbol} **{decision}**  ")
    lines.append(f"**Overall Severity:** {risk_summary['overall_severity']}  ")
    lines.append(f"**Risk Score:** {risk_summary.get('risk_score', 'N/A')} / 10  ")
    lines.append(f"**Max CVSS:** {risk_summary['max_cvss']} (Reachable: {risk_summary.get('max_reachable_cvss', 'N/A')})  ")
    lines.append(f"**Total Vulnerabilities:** {risk_summary['total_vulnerabilities']} ({risk_summary.get('reachable_vulnerabilities', 0)} reachable, {risk_summary.get('unreachable_vulnerabilities', 0)} unreachable)  \n")

    lines.append("---\n")
    lines.append("## Vulnerable Components\n")

    # Track vulnerabilities without CVSS scores and KEV status
    unknown_cvss_count = 0
    kev_count = 0

    for finding in findings:
        if finding["vulnerabilities"]:
            comp = finding["component"]
            reach_info = comp.get("reachability", {})
            reach_status = "[Reachable]" if reach_info.get("reachable", True) else "[Not Reachable]"
            reach_reason = reach_info.get("reason", "Unknown")

            lines.append(f"\n### {comp['name']}@{comp['version']} - {reach_status}")
            lines.append(f"*{reach_reason}*\n")

            for vuln in finding["vulnerabilities"]:
                cvss = vuln.get('cvss', 0.0)
                vuln_id = vuln.get('id', 'UNKNOWN')

                # Check for CISA KEV status
                kev_status = vuln.get("kev", {})
                is_kev = kev_status.get("in_kev", False)

                # Build vulnerability line
                vuln_line = f"- {vuln_id}"

                # Add KEV warning
                if is_kev:
                    vuln_line += " **[ACTIVELY EXPLOITED]**"
                    kev_count += 1

                # Add CVSS info
                if cvss == 0.0 or cvss is None:
                    vuln_line += " (CVSS: UNKNOWN - manual review needed)"
                    unknown_cvss_count += 1
                else:
                    from agent.utils import cvss_to_severity
                    severity = cvss_to_severity(cvss)
                    vuln_line += f" (CVSS: {cvss}, Severity: {severity})"

                # Add source info if from multiple databases
                sources = vuln.get("sources", [vuln.get("source")])
                if isinstance(sources, list) and len(sources) > 1:
                    source_str = ", ".join(sources)
                    vuln_line += f" [Sources: {source_str}]"
                elif sources:
                    source = sources[0] if isinstance(sources, list) else sources
                    vuln_line += f" [Source: {source}]"

                lines.append(vuln_line)

                # Add KEV details if available
                if is_kev:
                    due_date = kev_status.get("due_date", "")
                    required_action = kev_status.get("required_action", "")
                    if required_action:
                        lines.append(f"  - **Required Action:** {required_action}")
                    if due_date:
                        lines.append(f"  - **CISA Due Date:** {due_date}")

    if not any(f["vulnerabilities"] for f in findings):
        lines.append("\nNo vulnerabilities detected.  ")

    # Add warnings
    if kev_count > 0:
        lines.append(f"\n**CRITICAL:** {kev_count} vulnerabilities are in CISA's Known Exploited Vulnerabilities catalog - immediate remediation required!  ")

    if unknown_cvss_count > 0:
        lines.append(f"\n**Note:** {unknown_cvss_count} vulnerabilities have no CVSS score and require manual assessment.  ")

    # Add remediation section if available
    if remediations:
        lines.append("\n---\n")
        lines.append("## Remediation Recommendations\n")

        for remediation in remediations:
            # Handle AI remediation format (nested structure)
            if "advice" in remediation:
                advice = remediation["advice"]
                component = remediation["component"]
                comp_name = component.get("name", "unknown")
                comp_version = component.get("version", "unknown")

                is_ai = advice.get("ai_generated", False)

                if is_ai:
                    lines.append(f"\n### 🤖 AI-Powered Remediation for {comp_name}@{comp_version}\n")
                else:
                    lines.append(f"\n### {comp_name}@{comp_version}\n")

                # Summary
                if advice.get("summary"):
                    lines.append(f"**Summary:** {advice['summary']}\n")

                # Impact Analysis (AI-specific)
                if advice.get("impact_analysis"):
                    lines.append(f"\n**Impact Analysis:**\n{advice['impact_analysis']}\n")

                # Remediation Plan (AI-specific)
                if advice.get("remediation_plan"):
                    plan = advice["remediation_plan"]
                    lines.append(f"\n**Remediation Plan:**\n")

                    # Check if it's a dict with detailed structure or just text
                    if isinstance(plan, dict):
                        if plan.get("recommended_version"):
                            lines.append(f"- **Upgrade to:** {plan['recommended_version']}\n")
                        if plan.get("upgrade_command"):
                            lines.append(f"- **Command:** `{plan['upgrade_command']}`\n")
                        if plan.get("steps"):
                            lines.append(f"\n**Steps:**\n")
                            for step in plan["steps"]:
                                lines.append(f"{step}\n")
                        if plan.get("breaking_changes"):
                            lines.append(f"\n**Breaking Changes:**\n")
                            for change in plan["breaking_changes"]:
                                lines.append(f"- {change}\n")
                        if plan.get("testing_strategy"):
                            lines.append(f"\n**Testing Strategy:**\n{plan['testing_strategy']}\n")
                    else:
                        # Plain text plan
                        lines.append(f"{plan}\n")

                # Risk Explanation (AI-specific)
                if advice.get("risk_explanation"):
                    lines.append(f"\n**Why This Matters:**\n{advice['risk_explanation']}\n")

                # Estimated Effort
                if advice.get("estimated_effort"):
                    lines.append(f"\n**Estimated Effort:** {advice['estimated_effort']}\n")

                continue

            # Handle basic remediation format (flat structure)
            if not remediation.get("recommended_version"):
                continue

            comp = remediation["component"]
            current = remediation["current_version"]
            recommended = remediation["recommended_version"]
            priority = remediation["priority"].upper()

            # Priority indicator
            priority_indicator = {
                "CRITICAL": "[!]",
                "HIGH": "[!]",
                "MEDIUM": "[i]",
                "LOW": "[·]"
            }.get(priority, "[?]")

            lines.append(f"\n### {priority_indicator} {comp}@{current} → {recommended} ({priority} Priority)")

            # Add upgrade command
            if remediation.get("upgrade_command"):
                lines.append(f"\n**Suggested fix:**")
                lines.append(f"```bash")
                lines.append(remediation["upgrade_command"])
                lines.append(f"```\n")

            # Add actionable steps
            if remediation.get("actionable_steps"):
                for step in remediation["actionable_steps"]:
                    lines.append(f"{step}  ")

            # Add change analysis warning
            change = remediation.get("change_analysis", {})
            if change.get("warning"):
                lines.append(f"\n{change['warning']}  ")

    lines.append("\n---\n")
    lines.append(f"## Policy Decision\n\n{reason}\n")

    return "\n".join(lines)




def save_outputs(output_dir, markdown, json_data):
    import os
    import json

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "pr_comment.md"), "w", encoding="utf-8") as f:
        f.write(markdown)

    with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
