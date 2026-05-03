#!/usr/bin/env python3
"""
Multi-Ecosystem SBOM Verification Script
Validates that all required dependency files are present and properly formatted
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple


class EcosystemValidator:
    """Validates dependency files for all ecosystems"""
    
    def __init__(self, root_path: str = "."):
        self.root = Path(root_path)
        self.results = {
            "npm": {"present": False, "valid": False, "path": None, "issues": []},
            "python": {"present": False, "valid": False, "path": None, "issues": []},
            "go": {"present": False, "valid": False, "path": None, "issues": []},
            "maven": {"present": False, "valid": False, "path": None, "issues": []}
        }
    
    def check_npm(self) -> bool:
        """Check for Node.js/npm dependency files"""
        print("\n📦 Checking npm (Node.js)...")
        
        # Check package.json
        package_json = self.root / "package.json"
        package_lock = self.root / "package-lock.json"
        
        if not package_json.exists():
            print("   ❌ package.json not found")
            self.results["npm"]["issues"].append("package.json not found")
            return False
        
        self.results["npm"]["path"] = str(package_json)
        self.results["npm"]["present"] = True
        print("   ✓ package.json found")
        
        # Validate JSON format
        try:
            with open(package_json) as f:
                data = json.load(f)
            
            if "dependencies" not in data and "devDependencies" not in data:
                print("   ⚠️  No dependencies or devDependencies found")
                self.results["npm"]["issues"].append("No dependencies defined")
                return False
            
            print(f"   ✓ Valid JSON format")
            
            if package_lock.exists():
                print("   ✓ package-lock.json found (recommended)")
            else:
                print("   ⚠️  package-lock.json not found (recommended for consistency)")
                self.results["npm"]["issues"].append("package-lock.json missing (recommended)")
            
            self.results["npm"]["valid"] = True
            return True
            
        except json.JSONDecodeError as e:
            print(f"   ❌ Invalid JSON in package.json: {e}")
            self.results["npm"]["issues"].append(f"Invalid JSON: {str(e)}")
            return False
    
    def check_python(self) -> bool:
        """Check for Python/pip dependency files"""
        print("\n🐍 Checking Python...")
        
        requirements_txt = self.root / "requirements.txt"
        setup_py = self.root / "setup.py"
        pyproject_toml = self.root / "pyproject.toml"
        
        if not requirements_txt.exists() and not setup_py.exists() and not pyproject_toml.exists():
            print("   ❌ No Python dependency files found")
            print("      Looking for: requirements.txt, setup.py, or pyproject.toml")
            self.results["python"]["issues"].append("No Python dependency files found")
            return False
        
        # Check requirements.txt (most common)
        if requirements_txt.exists():
            self.results["python"]["path"] = str(requirements_txt)
            self.results["python"]["present"] = True
            print("   ✓ requirements.txt found")
            
            # Validate format
            try:
                with open(requirements_txt) as f:
                    lines = f.readlines()
                
                if len(lines) == 0:
                    print("   ⚠️  requirements.txt is empty")
                    self.results["python"]["issues"].append("requirements.txt is empty")
                    return False
                
                print(f"   ✓ Valid format ({len(lines)} packages)")
                
                # Check for pinned versions
                unpinned = [l for l in lines if l.strip() and "==" not in l and ">=" not in l]
                if unpinned:
                    print(f"   ⚠️  {len(unpinned)} packages without pinned versions")
                    self.results["python"]["issues"].append(f"{len(unpinned)} unpinned packages")
                else:
                    print("   ✓ All packages have pinned versions")
                
                self.results["python"]["valid"] = True
                return True
                
            except Exception as e:
                print(f"   ❌ Error reading requirements.txt: {e}")
                self.results["python"]["issues"].append(f"Read error: {str(e)}")
                return False
        
        # Check setup.py or pyproject.toml
        if setup_py.exists():
            self.results["python"]["path"] = str(setup_py)
            self.results["python"]["present"] = True
            print("   ✓ setup.py found")
            self.results["python"]["valid"] = True
            return True
        
        if pyproject_toml.exists():
            self.results["python"]["path"] = str(pyproject_toml)
            self.results["python"]["present"] = True
            print("   ✓ pyproject.toml found")
            self.results["python"]["valid"] = True
            return True
        
        return False
    
    def check_go(self) -> bool:
        """Check for Go dependency files"""
        print("\n🐹 Checking Go...")
        
        go_mod = self.root / "go.mod"
        go_sum = self.root / "go.sum"
        
        if not go_mod.exists():
            print("   ❌ go.mod not found")
            self.results["go"]["issues"].append("go.mod not found")
            return False
        
        self.results["go"]["path"] = str(go_mod)
        self.results["go"]["present"] = True
        print("   ✓ go.mod found")
        
        # Validate format
        try:
            with open(go_mod) as f:
                content = f.read()
            
            if "module" not in content:
                print("   ❌ go.mod missing 'module' declaration")
                self.results["go"]["issues"].append("No module declaration")
                return False
            
            if "require" not in content and "go" not in content:
                print("   ⚠️  go.mod has no requires or go version")
                self.results["go"]["issues"].append("No requires or go version")
                return False
            
            print("   ✓ Valid go.mod format")
            
            if go_sum.exists():
                print("   ✓ go.sum found (recommended)")
            else:
                print("   ⚠️  go.sum not found (recommended for consistency)")
                self.results["go"]["issues"].append("go.sum missing (recommended)")
            
            self.results["go"]["valid"] = True
            return True
            
        except Exception as e:
            print(f"   ❌ Error reading go.mod: {e}")
            self.results["go"]["issues"].append(f"Read error: {str(e)}")
            return False
    
    def check_maven(self) -> bool:
        """Check for Maven dependency files"""
        print("\n☕ Checking Maven...")
        
        pom_xml = self.root / "pom.xml"
        
        if not pom_xml.exists():
            print("   ❌ pom.xml not found")
            self.results["maven"]["issues"].append("pom.xml not found")
            return False
        
        self.results["maven"]["path"] = str(pom_xml)
        self.results["maven"]["present"] = True
        print("   ✓ pom.xml found")
        
        # Validate XML format
        try:
            with open(pom_xml) as f:
                content = f.read()
            
            # Basic XML validation
            if not content.strip().startswith("<?xml") and not content.strip().startswith("<project"):
                print("   ⚠️  pom.xml may not be valid XML")
                self.results["maven"]["issues"].append("Possibly invalid XML")
            
            if "<dependencies>" not in content:
                print("   ⚠️  pom.xml has no dependencies section")
                self.results["maven"]["issues"].append("No dependencies section")
                return False
            
            # Count dependencies
            dep_count = content.count("<dependency>")
            print(f"   ✓ Valid pom.xml format ({dep_count} dependencies)")
            
            self.results["maven"]["valid"] = True
            return True
            
        except Exception as e:
            print(f"   ❌ Error reading pom.xml: {e}")
            self.results["maven"]["issues"].append(f"Read error: {str(e)}")
            return False
    
    def check_workflow(self) -> bool:
        """Check if GitHub workflow exists and has multi-ecosystem support"""
        print("\n⚙️  Checking GitHub Workflow...")
        
        workflow_path = self.root / ".github" / "workflows" / "sbom.yml"
        
        if not workflow_path.exists():
            print("   ❌ Workflow file not found at .github/workflows/sbom.yml")
            return False
        
        print("   ✓ sbom.yml workflow found")
        
        # Check for multi-ecosystem support
        with open(workflow_path) as f:
            content = f.read()
        
        ecosystems_in_workflow = {
            "npm": "actions/setup-node" in content,
            "python": "actions/setup-python" in content,
            "go": "actions/setup-go" in content,
            "maven": "actions/setup-java" in content
        }
        
        for eco, present in ecosystems_in_workflow.items():
            if present:
                print(f"   ✓ {eco.upper()} setup found")
            else:
                print(f"   ❌ {eco.upper()} setup missing")
        
        return all(ecosystems_in_workflow.values())
    
    def validate_all(self) -> bool:
        """Run all validations"""
        print("\n" + "="*60)
        print("🔍 Multi-Ecosystem SBOM Validation")
        print("="*60)
        
        self.check_npm()
        self.check_python()
        self.check_go()
        self.check_maven()
        self.check_workflow()
        
        return self.print_summary()
    
    def print_summary(self) -> bool:
        """Print validation summary"""
        print("\n" + "="*60)
        print("📊 VALIDATION SUMMARY")
        print("="*60)
        
        total_present = sum(1 for r in self.results.values() if r["present"])
        total_valid = sum(1 for r in self.results.values() if r["valid"])
        
        print(f"\nEcosystem Status:")
        for eco, result in self.results.items():
            status = "✅" if result["valid"] else ("⚠️" if result["present"] else "❌")
            print(f"  {status} {eco.upper():8} - {'Valid' if result['valid'] else ('Present' if result['present'] else 'Missing')}")
            if result["issues"]:
                for issue in result["issues"]:
                    print(f"       • {issue}")
        
        print(f"\nDetected Ecosystems: {total_present}/4")
        print(f"Valid Ecosystems: {total_valid}/4")
        
        # Recommendations
        if total_valid < total_present:
            print("\n⚠️  Some files need attention:")
            for eco, result in self.results.items():
                if result["present"] and not result["valid"]:
                    print(f"   • Fix {eco} - check issues above")
        
        if total_present == 0:
            print("\n❌ No dependency files found!")
            print("   Add at least one of: package.json, requirements.txt, go.mod, pom.xml")
        elif total_present < 4:
            print(f"\n✓ {total_present} ecosystems detected (add more for full multi-ecosystem support)")
        else:
            print(f"\n✅ All 4 ecosystems detected!")
        
        print("\n" + "="*60)
        
        return total_valid > 0  # At least one ecosystem should be valid


def main():
    parser = argparse.ArgumentParser(
        description="Validate multi-ecosystem SBOM setup"
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Path to validate (default: current directory)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    
    args = parser.parse_args()
    
    validator = EcosystemValidator(args.path)
    success = validator.validate_all()
    
    if args.json:
        print("\n" + json.dumps(validator.results, indent=2))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
