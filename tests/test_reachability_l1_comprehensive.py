"""
Level 1 Reachability Analysis - Comprehensive Test Suite
=========================================================

Tests metadata-based reachability analysis (SBOM scope, properties, dependencies)

Test Categories:
1. SCOPE ANALYSIS - required, optional, excluded
2. DEV DEPENDENCY DETECTION - npm devDeps, Maven test scope
3. COMPONENT TYPE ANALYSIS - build-tool, dev-dependency
4. EDGE CASES - Missing metadata, conflicting signals
5. INTEGRATION - Full SBOM with mixed dependencies
"""

import pytest
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.reachability_analyzer import analyze_reachability, calculate_reachability_score


class TestScopeAnalysis:
    """Test dependency scope field"""

    def test_scope_required_reachable(self, metrics_collector):
        """L1-SCOPE-1: Required scope → REACHABLE"""
        print("\n" + "="*70)
        print("L1-SCOPE-1: Required Dependency (Production)")
        print("="*70)

        component = {
            "name": "axios",
            "version": "0.21.0",
            "scope": "required",
            "purl": "pkg:npm/axios@0.21.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        print(f"Reachable: {result['reachable']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Reason: {result['reason']}")
        print(f"Score: {calculate_reachability_score(result)}")

        assert result['reachable'] == True
        assert result['confidence'] in ['medium', 'high']
        assert result['scope'] == 'required'
        assert calculate_reachability_score(result) >= 0.5

        metrics_collector.add_result("L1-SCOPE-1", "reachable", True)
        metrics_collector.add_result("L1-SCOPE-1", "score", calculate_reachability_score(result))

    def test_scope_optional_unreachable(self, metrics_collector):
        """L1-SCOPE-2: Optional scope → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-SCOPE-2: Optional Dependency")
        print("="*70)

        component = {
            "name": "fsevents",
            "version": "2.3.0",
            "scope": "optional",  # macOS-only optional dependency
            "purl": "pkg:npm/fsevents@2.3.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        print(f"Reachable: {result['reachable']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Reason: {result['reason']}")
        print(f"Score: {calculate_reachability_score(result)}")

        assert result['reachable'] == False
        assert result['confidence'] == 'high'
        assert result['scope'] == 'optional'
        assert calculate_reachability_score(result) == 0.0

        metrics_collector.add_result("L1-SCOPE-2", "reachable", False)
        metrics_collector.add_result("L1-SCOPE-2", "score", 0.0)

    def test_scope_excluded_unreachable(self, metrics_collector):
        """L1-SCOPE-3: Excluded scope → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-SCOPE-3: Excluded Dependency")
        print("="*70)

        component = {
            "name": "some-excluded-package",
            "version": "1.0.0",
            "scope": "excluded",
            "purl": "pkg:npm/some-excluded-package@1.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False
        assert result['confidence'] == 'high'
        assert result['scope'] == 'excluded'
        assert calculate_reachability_score(result) == 0.0

        print(f"✓ Excluded packages correctly marked unreachable")


class TestDevDependencyDetection:
    """Test development dependency markers"""

    def test_npm_dev_dependency(self, metrics_collector):
        """L1-DEV-1: npm devDependency → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-DEV-1: npm devDependency")
        print("="*70)

        component = {
            "name": "jest",
            "version": "27.0.0",
            "scope": "required",  # Scope says required, but...
            "properties": [
                {
                    "name": "cdx:npm:package:development",
                    "value": "true"  # ← Dev dependency marker
                }
            ],
            "purl": "pkg:npm/jest@27.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        print(f"Reachable: {result['reachable']}")
        print(f"Is Dev Only: {result['is_dev_only']}")
        print(f"Reason: {result['reason']}")

        assert result['reachable'] == False
        assert result['is_dev_only'] == True
        assert result['confidence'] == 'high'
        assert calculate_reachability_score(result) == 0.0

        metrics_collector.add_result("L1-DEV-1", "dev_detected", True)

    def test_maven_test_scope(self, metrics_collector):
        """L1-DEV-2: Maven test scope → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-DEV-2: Maven Test Scope")
        print("="*70)

        component = {
            "name": "junit",
            "version": "4.13.2",
            "properties": [
                {
                    "name": "cdx:maven:scope",
                    "value": "test"  # ← Maven test scope
                }
            ],
            "purl": "pkg:maven/junit/junit@4.13.2"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False
        assert result['is_dev_only'] == True
        assert calculate_reachability_score(result) == 0.0

        print(f"✓ Maven test dependencies correctly filtered")

    def test_maven_provided_scope(self, metrics_collector):
        """L1-DEV-3: Maven provided scope → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-DEV-3: Maven Provided Scope")
        print("="*70)

        component = {
            "name": "servlet-api",
            "version": "2.5",
            "properties": [
                {
                    "name": "cdx:maven:scope",
                    "value": "provided"  # ← Provided by container
                }
            ],
            "purl": "pkg:maven/javax/servlet-api@2.5"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False
        assert result['is_dev_only'] == True
        assert "provided" in result['reason']

    def test_production_dependency_without_markers(self, metrics_collector):
        """L1-DEV-4: Production dependency (no dev markers) → REACHABLE"""
        print("\n" + "="*70)
        print("L1-DEV-4: Production Dependency (No Dev Markers)")
        print("="*70)

        component = {
            "name": "express",
            "version": "4.17.0",
            "properties": [
                {
                    "name": "cdx:npm:package:development",
                    "value": "false"  # ← Explicitly production
                }
            ],
            "purl": "pkg:npm/express@4.17.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == True
        assert result['is_dev_only'] == False


class TestComponentType:
    """Test component type detection"""

    def test_build_tool_unreachable(self, metrics_collector):
        """L1-TYPE-1: Build tool → UNREACHABLE"""
        print("\n" + "="*70)
        print("L1-TYPE-1: Build Tool Component")
        print("="*70)

        component = {
            "name": "webpack",
            "version": "5.0.0",
            "type": "build-tool",  # ← Not runtime dependency
            "purl": "pkg:npm/webpack@5.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False
        assert result['is_dev_only'] == True
        assert result['confidence'] == 'medium'

    def test_dev_dependency_type(self, metrics_collector):
        """L1-TYPE-2: dev-dependency type → UNREACHABLE"""
        component = {
            "name": "eslint",
            "version": "8.0.0",
            "type": "dev-dependency",
            "purl": "pkg:npm/eslint@8.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False

    def test_test_dependency_type(self, metrics_collector):
        """L1-TYPE-3: test-dependency type → UNREACHABLE"""
        component = {
            "name": "mocha",
            "version": "9.0.0",
            "type": "test-dependency",
            "purl": "pkg:npm/mocha@9.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == False

    def test_library_type_reachable(self, metrics_collector):
        """L1-TYPE-4: library type → REACHABLE (default)"""
        component = {
            "name": "lodash",
            "version": "4.17.21",
            "type": "library",  # ← Normal runtime library
            "scope": "required",
            "purl": "pkg:npm/lodash@4.17.21"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        assert result['reachable'] == True


class TestEdgeCases:
    """Edge cases and missing metadata"""

    def test_no_scope_field(self, metrics_collector):
        """L1-EDGE-1: Missing scope field → Assume REACHABLE (fail-safe)"""
        print("\n" + "="*70)
        print("L1-EDGE-1: No Scope Field (Fail-Safe)")
        print("="*70)

        component = {
            "name": "mystery-package",
            "version": "1.0.0",
            # No scope field
            "purl": "pkg:npm/mystery-package@1.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        # Should default to reachable (fail-safe)
        assert result['reachable'] == True
        assert result['confidence'] == 'low'
        assert "No scope information" in result['reason']

        print(f"✓ Missing metadata defaults to REACHABLE (fail-safe)")

    def test_conflicting_signals(self, metrics_collector):
        """L1-EDGE-2: Conflicting signals (scope=required but type=dev)"""
        print("\n" + "="*70)
        print("L1-EDGE-2: Conflicting Signals")
        print("="*70)

        component = {
            "name": "babel-core",
            "version": "7.0.0",
            "scope": "required",  # Says required
            "type": "build-tool",  # But it's a build tool
            "purl": "pkg:npm/babel-core@7.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        # Type should take precedence
        assert result['reachable'] == False
        assert result['is_dev_only'] == True

        print(f"✓ Component type overrides scope when conflicting")

    def test_empty_properties_array(self, metrics_collector):
        """L1-EDGE-3: Empty properties array"""
        component = {
            "name": "some-package",
            "version": "1.0.0",
            "properties": [],  # Empty array
            "purl": "pkg:npm/some-package@1.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        # No crash, should handle gracefully
        assert result is not None

    def test_malformed_properties(self, metrics_collector):
        """L1-EDGE-4: Malformed properties (missing name/value)"""
        component = {
            "name": "bad-package",
            "version": "1.0.0",
            "properties": [
                {"name": "cdx:npm:package:development"},  # Missing value
                {"value": "true"}  # Missing name
            ],
            "purl": "pkg:npm/bad-package@1.0.0"
        }
        sbom_data = {"components": [component]}

        result = analyze_reachability(component, sbom_data)

        # Should handle gracefully without crashing
        assert result is not None


class TestIntegrationScenarios:
    """Real-world integration scenarios"""

    def test_full_npm_project_sbom(self, metrics_collector):
        """L1-INT-1: Full npm project with mixed dependencies"""
        print("\n" + "="*70)
        print("L1-INT-1: Full npm Project SBOM")
        print("="*70)

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                # Production dependencies
                {
                    "name": "express",
                    "version": "4.18.0",
                    "scope": "required",
                    "purl": "pkg:npm/express@4.18.0"
                },
                {
                    "name": "lodash",
                    "version": "4.17.15",  # Vulnerable version
                    "scope": "required",
                    "purl": "pkg:npm/lodash@4.17.15"
                },
                # Dev dependencies
                {
                    "name": "jest",
                    "version": "27.0.0",
                    "properties": [
                        {"name": "cdx:npm:package:development", "value": "true"}
                    ],
                    "purl": "pkg:npm/jest@27.0.0"
                },
                {
                    "name": "webpack",
                    "version": "5.0.0",
                    "type": "build-tool",
                    "purl": "pkg:npm/webpack@5.0.0"
                },
                # Optional dependency
                {
                    "name": "fsevents",
                    "version": "2.3.0",
                    "scope": "optional",
                    "purl": "pkg:npm/fsevents@2.3.0"
                }
            ]
        }

        results = {}
        for component in sbom_data['components']:
            name = component['name']
            result = analyze_reachability(component, sbom_data)
            results[name] = result

        # Verify production dependencies are reachable
        assert results['express']['reachable'] == True
        assert results['lodash']['reachable'] == True

        # Verify dev dependencies are unreachable
        assert results['jest']['reachable'] == False
        assert results['webpack']['reachable'] == False
        assert results['fsevents']['reachable'] == False

        reachable_count = sum(1 for r in results.values() if r['reachable'])
        unreachable_count = sum(1 for r in results.values() if not r['reachable'])

        print(f"\nReachable: {reachable_count}/5")
        print(f"Unreachable: {unreachable_count}/5")

        metrics_collector.add_result("L1-INT-1", "total_components", 5)
        metrics_collector.add_result("L1-INT-1", "reachable", reachable_count)
        metrics_collector.add_result("L1-INT-1", "unreachable", unreachable_count)

    def test_maven_project_sbom(self, metrics_collector):
        """L1-INT-2: Maven project with various scopes"""
        print("\n" + "="*70)
        print("L1-INT-2: Maven Project SBOM")
        print("="*70)

        sbom_data = {
            "bomFormat": "CycloneDX",
            "components": [
                # Compile scope (production)
                {
                    "name": "spring-boot",
                    "version": "2.7.0",
                    "properties": [{"name": "cdx:maven:scope", "value": "compile"}],
                    "purl": "pkg:maven/org.springframework.boot/spring-boot@2.7.0"
                },
                # Test scope
                {
                    "name": "junit",
                    "version": "4.13.2",
                    "properties": [{"name": "cdx:maven:scope", "value": "test"}],
                    "purl": "pkg:maven/junit/junit@4.13.2"
                },
                # Provided scope
                {
                    "name": "servlet-api",
                    "version": "2.5",
                    "properties": [{"name": "cdx:maven:scope", "value": "provided"}],
                    "purl": "pkg:maven/javax/servlet-api@2.5"
                }
            ]
        }

        results = {}
        for component in sbom_data['components']:
            name = component['name']
            result = analyze_reachability(component, sbom_data)
            results[name] = result

        # Compile scope → Reachable
        assert results['spring-boot']['reachable'] == True

        # Test & provided → Unreachable
        assert results['junit']['reachable'] == False
        assert results['servlet-api']['reachable'] == False

        print(f"✓ Maven scopes correctly analyzed")


class TestReachabilityScoreCalculation:
    """Test score calculation logic"""

    def test_score_unreachable_high_confidence(self):
        """L1-SCORE-1: Unreachable + high confidence → 0.0"""
        result = {
            "reachable": False,
            "confidence": "high"
        }
        score = calculate_reachability_score(result)
        assert score == 0.0

    def test_score_unreachable_medium_confidence(self):
        """L1-SCORE-2: Unreachable + medium confidence → 0.2"""
        result = {
            "reachable": False,
            "confidence": "medium"
        }
        score = calculate_reachability_score(result)
        assert score == 0.2

    def test_score_reachable_high_confidence(self):
        """L1-SCORE-3: Reachable + high confidence → 1.0"""
        result = {
            "reachable": True,
            "confidence": "high"
        }
        score = calculate_reachability_score(result)
        assert score == 1.0

    def test_score_reachable_medium_confidence(self):
        """L1-SCORE-4: Reachable + medium confidence → 0.7"""
        result = {
            "reachable": True,
            "confidence": "medium"
        }
        score = calculate_reachability_score(result)
        assert score == 0.7

    def test_score_reachable_low_confidence(self):
        """L1-SCORE-5: Reachable + low confidence → 0.5"""
        result = {
            "reachable": True,
            "confidence": "low"
        }
        score = calculate_reachability_score(result)
        assert score == 0.5
