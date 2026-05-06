import json

# Check what ecosystems have remediations
d = json.load(open('test-output-all-ecosystems/report.json'))
rems = d.get('remediations', [])

ecosystems = {}
for r in rems:
    eco = r['component']['ecosystem']
    if eco not in ecosystems:
        ecosystems[eco] = []
    ecosystems[eco].append(r['component']['name'])

print("Remediations by ecosystem:")
for eco in ['npm', 'PyPI', 'Maven', 'Go']:
    packages = ecosystems.get(eco, [])
    if packages:
        print(f"✓ {eco}: {', '.join(packages)}")
    else:
        print(f"✗ {eco}: NO REMEDIATIONS")

# Check all findings to see if npm packages have vulnerabilities
print("\n\nAll findings by ecosystem:")
findings = d.get('findings', [])
eco_findings = {}
for f in findings:
    eco = f['component'].get('ecosystem', 'unknown')
    if eco not in eco_findings:
        eco_findings[eco] = []
    eco_findings[eco].append(f['component']['name'])

for eco in sorted(eco_findings.keys()):
    print(f"\n{eco}:")
    for pkg in eco_findings[eco]:
        print(f"  - {pkg}")
