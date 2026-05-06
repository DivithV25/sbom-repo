import json

d = json.load(open('test-output-all-ecosystems/report.json'))
rems = d.get('remediations', [])
print(f'Total remediations: {len(rems)}')
print('\nFirst remediation structure:')
r = rems[0]
print(f"Keys at top level: {list(r.keys())}")
print(f"Component keys: {list(r['component'].keys())}")
print(f"Advice keys: {list(r['advice'].keys())}")
print(f"\nRemediation plan keys: {list(r['advice'].get('remediation_plan', {}).keys())}")
print(f"\nFirst remediation details:")
print(f"  Component: {r['component']['name']} @ {r['component']['version']}")
print(f"  Ecosystem: {r['component']['ecosystem']}")
plan = r['advice'].get('remediation_plan', {})
print(f"  Recommended version: {plan.get('recommended_version')}")
print(f"  Upgrade command: {plan.get('upgrade_command')}")
