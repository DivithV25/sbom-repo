#!/usr/bin/env python3
"""
Multi-Language SBOM Scanning and Dependency Blocking

Scans applications written in multiple languages (Node.js, Python, Go, Maven)
and applies security policies to block vulnerable or unauthorized dependencies.

Usage:
    python scan_application.py <app-directory> [--output output-dir] [--rules rules.yaml] [--policy default]
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.multi_language_scanner import ManifestDetector, DependencyParser, SBOMGenerator, MultiLanguageScanner
from agent.sbom_parser import extract_components
from agent.osv_client import query_osv
from agent.policy_engine import load_rules, check_blocked_packages, evaluate_condition
from agent.risk_engine import compute_risk
from agent.reporter import generate_markdown_report, save_outputs


def scan_and_analyze(app_directory: str, output_dir: str = "output", rules_path: str = None):
    """
    Complete workflow: scan app → generate SBOM → check vulnerabilities → apply policies
    """
    print("=" * 70)
    print("🔍 PRISM Multi-Language Security Scanner")
    print("=" * 70)

    # Step 1: Generate SBOMs from manifests
    print("\n[Step 1/5] Detecting and parsing manifests...\n")
    
    manifests = ManifestDetector.detect_manifests(app_directory)
    
    if not manifests:
        print("❌ No manifest files found in:", app_directory)
        return False

    # Step 2: Load rules
    print("\n[Step 2/5] Loading security policies...\n")
    rules = load_rules(rules_path)
    if rules:
        print("✅ Policy loaded successfully")
        blocked_packages = rules.get('blocked_packages', [])
        if blocked_packages:
            print(f"   🚫 Blocked packages: {', '.join(blocked_packages)}")
    else:
        print("⚠️  No policy rules found")

    # Step 3: Parse manifests and collect all components
    print("\n[Step 3/5] Extracting dependencies from manifests...\n")
    
    all_components = []
    sbom_files = []
    
    for ecosystem, files in manifests.items():
        for manifest_path in files:
            print(f"📦 Parsing {ecosystem}: {os.path.basename(manifest_path)}")
            
            detected_ecosystem, components = DependencyParser.parse_manifest(manifest_path)
            
            if components:
                all_components.extend(components)
                
                # Generate SBOM for this manifest
                sbom = SBOMGenerator.generate_sbom(
                    components,
                    metadata={
                        "name": f"app-{ecosystem}",
                        "version": "1.0.0",
                        "description": f"{ecosystem.upper()} application dependencies"
                    }
                )
                
                # Save individual SBOM
                output_path = Path(output_dir) / "sboms"
                output_path.mkdir(parents=True, exist_ok=True)
                
                sbom_filename = f"sbom_{ecosystem}_{Path(manifest_path).stem}.json"
                sbom_path = output_path / sbom_filename
                
                SBOMGenerator.save_sbom(sbom, str(sbom_path))
                sbom_files.append(str(sbom_path))
                
                print(f"   ✅ Found {len(components)} dependencies")
    
    print(f"\n✅ Total dependencies found: {len(all_components)}")

    # Step 4: Check for policy violations (blocked packages)
    print("\n[Step 4/5] Applying security policies...\n")
    
    policy_violations = []
    for comp in all_components:
        name = comp['name']
        if rules and name in rules.get('blocked_packages', []):
            policy_violations.append({
                'package': name,
                'version': comp['version'],
                'ecosystem': comp['ecosystem'],
                'reason': 'Package is blocked by policy'
            })
            print(f"❌ BLOCKED: {name}@{comp['version']} ({comp['ecosystem']})")

    # Step 5: Scan for known vulnerabilities
    print("\n[Step 5/5] Scanning for known vulnerabilities (OSV)...\n")
    
    findings = []
    critical_found = False
    
    for i, comp in enumerate(all_components, 1):
        name = comp['name']
        version = comp['version']
        ecosystem = comp['ecosystem']
        
        print(f"   [{i}/{len(all_components)}] Scanning {ecosystem}: {name}@{version}...")
        
        vulns = query_osv(name, version, ecosystem)
        
        if vulns:
            print(f"      ⚠️  Found {len(vulns)} vulnerability(ies)")
            findings.append({
                'component': comp,
                'vulnerabilities': vulns
            })
            
            # Check severity
            for vuln in vulns:
                if vuln.get('severity', '').upper() == 'CRITICAL':
                    critical_found = True
        else:
            print(f"      ✅ Clean")

    # Step 6: Generate report
    print("\n" + "=" * 70)
    print("📊 SCAN RESULTS")
    print("=" * 70)

    decision = "PASS"
    reason = "All checks passed"

    if policy_violations:
        decision = "FAIL"
        reason = f"Policy violations found: {len(policy_violations)} blocked package(s)"
        print(f"\n🚫 POLICY VIOLATIONS: {len(policy_violations)}")
        for violation in policy_violations:
            print(f"   - {violation['package']}@{violation['version']}")

    if findings:
        if not decision == "FAIL":
            decision = "WARN"
            reason = f"Vulnerabilities detected: {len(findings)} affected package(s)"
        print(f"\n⚠️  VULNERABILITIES FOUND: {len(findings)} package(s) with known issues")
        for finding in findings:
            comp = finding['component']
            print(f"   - {comp['name']}@{comp['version']} ({comp['ecosystem']})")

    if critical_found:
        decision = "FAIL"
        reason = "Critical vulnerabilities detected"
        print("\n🔴 CRITICAL SEVERITY VULNERABILITIES DETECTED")

    print(f"\n{'✅' if decision == 'PASS' else '⚠️' if decision == 'WARN' else '❌'} Decision: {decision}")
    print(f"📝 Reason: {reason}\n")

    # Save results
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    results = {
        "decision": decision,
        "reason": reason,
        "scan_timestamp": "2024-01-01T00:00:00Z",
        "manifests_found": len(manifests),
        "total_dependencies": len(all_components),
        "dependencies_by_ecosystem": {
            ecosystem: len([c for c in all_components if c['ecosystem'] == ecosystem])
            for ecosystem in set(c['ecosystem'] for c in all_components)
        },
        "policy_violations": len(policy_violations),
        "vulnerabilities_found": len(findings),
        "critical_vulnerabilities": sum(1 for f in findings for v in f['vulnerabilities'] if v.get('severity', '').upper() == 'CRITICAL'),
        "sbom_files": sbom_files
    }

    results_path = output_path / "scan_results.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"📄 Results saved to: {results_path}\n")

    return decision != "FAIL"


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Language SBOM Scanner with Security Policy Enforcement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a Node.js application
  python scan_application.py ./application/nodejs-app

  # Scan a Python application with custom rules
  python scan_application.py ./application/python-app --rules ./policies/custom_policy.yaml

  # Scan entire application directory (multi-language)
  python scan_application.py ./application --output ./reports
        """
    )

    parser.add_argument("app_directory", help="Root directory of application to scan")
    parser.add_argument("--output", help="Output directory for results", default="output")
    parser.add_argument("--rules", help="Path to security policy YAML file", default=None)

    args = parser.parse_args()

    # Validate input
    if not os.path.isdir(args.app_directory):
        print(f"❌ Error: Directory not found: {args.app_directory}")
        sys.exit(1)

    # Run scan
    success = scan_and_analyze(args.app_directory, args.output, args.rules)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
