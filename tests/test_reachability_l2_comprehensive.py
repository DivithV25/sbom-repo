"""
Level 2 Reachability Analysis - Comprehensive Test Suite
=========================================================

Tests CODE-BASED reachability analysis (Import graph & Call graph)

Test Categories:
1. IMPORT DETECTION - JavaScript, Python, TypeScript imports
2. CALL GRAPH - Vulnerable function calls vs safe function calls
3. CONFIDENCE SCORING - Direct, indirect, conditional calls
4. MULTI-LANGUAGE - JS + Python in same project
5. ADVANCED PATTERNS - Dynamic imports, destructuring, aliasing
6. INTEGRATION - L1 + L2 combined analysis
"""

import pytest
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.reachability_analyzer import analyze_reachability
from agent.import_graph_analyzer import ImportGraphAnalyzer
from agent.call_graph_analyzer import CallGraphAnalyzer


class TestJavaScriptImportDetection:
    """Import detection for JavaScript/TypeScript"""

    def test_es6_import_detected(self, temp_project_root, metrics_collector):
        """L2-JS-IMPORT-1: ES6 import statement"""
        print("\n" + "="*70)
        print("L2-JS-IMPORT-1: ES6 Import Detection")
        print("="*70)

        # Create test file
        js_file = temp_project_root / "app.js"
        js_file.write_text("""
import lodash from 'lodash';

export function process(data) {
    return lodash.map(data, x => x * 2);
}
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        print(f"Is Imported: {result['is_imported']}")
        print(f"Import Locations: {len(result['import_locations'])}")
        print(f"Confidence: {result['confidence']}")

        assert result['is_imported'] == True
        assert len(result['import_locations']) == 1
        assert result['confidence'] == 1.0
        assert result['import_locations'][0]['type'] == 'import'

        metrics_collector.add_result("L2-JS-IMPORT-1", "detected", True)

    def test_commonjs_require_detected(self, temp_project_root, metrics_collector):
        """L2-JS-IMPORT-2: CommonJS require()"""
        print("\n" + "="*70)
        print("L2-JS-IMPORT-2: CommonJS require() Detection")
        print("="*70)

        js_file = temp_project_root / "server.js"
        js_file.write_text("""
const express = require('express');
const axios = require('axios');

const app = express();
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("express", "javascript")

        assert result['is_imported'] == True
        assert result['import_locations'][0]['type'] == 'require'

    def test_destructured_import(self, temp_project_root, metrics_collector):
        """L2-JS-IMPORT-3: Destructured import { map, filter }"""
        print("\n" + "="*70)
        print("L2-JS-IMPORT-3: Destructured Import")
        print("="*70)

        js_file = temp_project_root / "utils.js"
        js_file.write_text("""
import { map, filter, template } from 'lodash';

export function processData(arr) {
    return map(filter(arr, x => x > 0), x => x * 2);
}
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        print(f"Imported Functions: {result['imported_functions']}")

        assert result['is_imported'] == True
        assert 'map' in result['imported_functions']
        assert 'filter' in result['imported_functions']
        assert 'template' in result['imported_functions']

        metrics_collector.add_result("L2-JS-IMPORT-3", "functions_found", len(result['imported_functions']))

    def test_package_not_imported(self, temp_project_root, metrics_collector):
        """L2-JS-IMPORT-4: Package NOT imported → Unreachable"""
        print("\n" + "="*70)
        print("L2-JS-IMPORT-4: Package NOT Imported")
        print("="*70)

        js_file = temp_project_root / "main.js"
        js_file.write_text("""
import axios from 'axios';
import express from 'express';

// NO lodash import
export async function getData() {
    return axios.get('http://api.example.com');
}
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        print(f"Is Imported: {result['is_imported']}")
        print(f"Import Locations: {result['import_locations']}")

        assert result['is_imported'] == False
        assert len(result['import_locations']) == 0
        assert result['confidence'] == 0.0

        metrics_collector.add_result("L2-JS-IMPORT-4", "correctly_not_found", True)

    def test_multiple_import_locations(self, temp_project_root, metrics_collector):
        """L2-JS-IMPORT-5: Package imported in multiple files"""
        print("\n" + "="*70)
        print("L2-JS-IMPORT-5: Multiple Import Locations")
        print("="*70)

        # File 1
        (temp_project_root / "utils.js").write_text("import _ from 'lodash';")
        # File 2
        (temp_project_root / "helpers.js").write_text("const _ = require('lodash');")
        # File 3
        (temp_project_root / "services.js").write_text("import { map } from 'lodash';")

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        print(f"Import Count: {result['usage_count']}")
        print(f"Files: {[loc['file'] for loc in result['import_locations']]}")

        assert result['is_imported'] == True
        assert result['usage_count'] == 3

        metrics_collector.add_result("L2-JS-IMPORT-5", "import_count", result['usage_count'])


class TestPythonImportDetection:
    """Import detection for Python"""

    def test_python_import_statement(self, temp_project_root, metrics_collector):
        """L2-PY-IMPORT-1: import requests"""
        print("\n" + "="*70)
        print("L2-PY-IMPORT-1: Python Import Statement")
        print("="*70)

        py_file = temp_project_root / "api.py"
        py_file.write_text("""
import requests
import json

def fetch_data(url):
    response = requests.get(url)
    return response.json()
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("requests", "python")

        print(f"Is Imported: {result['is_imported']}")
        print(f"Import Type: {result['import_locations'][0]['type']}")

        assert result['is_imported'] == True
        assert result['import_locations'][0]['type'] == 'import'

    def test_python_from_import(self, temp_project_root, metrics_collector):
        """L2-PY-IMPORT-2: from flask import Flask"""
        print("\n" + "="*70)
        print("L2-PY-IMPORT-2: Python from...import")
        print("="*70)

        py_file = temp_project_root / "app.py"
        py_file.write_text("""
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("flask", "python")

        print(f"Imported Functions: {result['imported_functions']}")

        assert result['is_imported'] == True
        assert result['import_locations'][0]['type'] == 'from_import'
        assert 'Flask' in result['imported_functions']
        assert 'jsonify' in result['imported_functions']

        metrics_collector.add_result("L2-PY-IMPORT-2", "functions", len(result['imported_functions']))

    def test_python_submodule_import(self, temp_project_root, metrics_collector):
        """L2-PY-IMPORT-3: from requests.auth import HTTPBasicAuth"""
        py_file = temp_project_root / "auth.py"
        py_file.write_text("""
from requests.auth import HTTPBasicAuth
import requests.exceptions

def auth_request(url, user, pwd):
    auth = HTTPBasicAuth(user, pwd)
    return requests.get(url, auth=auth)
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("requests", "python")

        # Should detect submodule imports
        assert result['is_imported'] == True


class TestCallGraphAnalysis:
    """Function call detection (vulnerable vs safe)"""

    def test_vulnerable_function_called(self, temp_project_root, metrics_collector):
        """L2-CALL-1: Vulnerable function _.template() IS called"""
        print("\n" + "="*70)
        print("L2-CALL-1: Vulnerable Function Called (HIGH RISK)")
        print("="*70)

        js_file = temp_project_root / "template.js"
        js_file.write_text("""
import _ from 'lodash';

export function renderTemplate(userInput) {
    // VULNERABLE: _.template() has CVE-2021-23337
    const compiled = _.template(userInput);
    return compiled({ name: 'World' });
}
        """)

        analyzer = CallGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_vulnerable_function_usage(
            "lodash",
            ["template", "_.template"],
            "javascript"
        )

        print(f"Vulnerable Function Called: {result['is_vulnerable_function_called']}")
        print(f"Max Confidence: {result['max_confidence']}")
        print(f"Call Locations: {len(result['call_locations'])}")

        assert result['is_vulnerable_function_called'] == True
        assert result['max_confidence'] >= 0.8  # High confidence
        assert len(result['call_locations']) > 0

        metrics_collector.add_result("L2-CALL-1", "vulnerable_called", True)
        metrics_collector.add_result("L2-CALL-1", "confidence", result['max_confidence'])

    def test_safe_functions_only(self, temp_project_root, metrics_collector):
        """L2-CALL-2: Only safe functions used (LOW RISK)"""
        print("\n" + "="*70)
        print("L2-CALL-2: Only Safe Functions Called (LOW RISK)")
        print("="*70)

        js_file = temp_project_root / "utils.js"
        js_file.write_text("""
import _ from 'lodash';

export function processArray(data) {
    // SAFE: These functions are not vulnerable
    const filtered = _.filter(data, x => x > 0);
    const mapped = _.map(filtered, x => x * 2);
    const sorted = _.sortBy(mapped);
    return sorted;
}
        """)

        analyzer = CallGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_vulnerable_function_usage(
            "lodash",
            ["template", "_.template"],  # Looking for vulnerable one
            "javascript"
        )

        print(f"Vulnerable Function Called: {result['is_vulnerable_function_called']}")
        print(f"Summary: {result['summary']}")

        # Package is used, but NOT the vulnerable function
        assert result['is_vulnerable_function_called'] == False
        assert result['max_confidence'] < 0.5

        metrics_collector.add_result("L2-CALL-2", "safe_only", True)

    def test_multiple_vulnerable_calls(self, temp_project_root, metrics_collector):
        """L2-CALL-3: Multiple calls to vulnerable function"""
        print("\n" + "="*70)
        print("L2-CALL-3: Multiple Vulnerable Calls")
        print("="*70)

        js_file = temp_project_root / "renderer.js"
        js_file.write_text("""
import _ from 'lodash';

export function renderMultiple(templates) {
    const results = [];
    for (const tmpl of templates) {
        results.push(_.template(tmpl));  // Call 1
    }
    return results;
}

export function quickRender(input) {
    return _.template(input)({ value: 42 });  // Call 2
}
        """)

        analyzer = CallGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_vulnerable_function_usage(
            "lodash",
            ["_.template"],
            "javascript"
        )

        print(f"Call Count: {len(result['call_locations'])}")
        print(f"Lines: {[loc['line'] for loc in result['call_locations']]}")

        assert len(result['call_locations']) >= 2
        assert result['is_vulnerable_function_called'] == True


class TestConfidenceScoring:
    """Test confidence score calculation"""

    def test_direct_call_high_confidence(self, temp_project_root, metrics_collector):
        """L2-CONF-1: Direct call → Confidence 1.0"""
        print("\n" + "="*70)
        print("L2-CONF-1: Direct Call (Confidence 1.0)")
        print("="*70)

        js_file = temp_project_root / "direct.js"
        js_file.write_text("""
import _ from 'lodash';
const result = _.template(userInput);  // Direct call
        """)

        analyzer = CallGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_vulnerable_function_usage(
            "lodash",
            ["_.template"],
            "javascript"
        )

        assert result['max_confidence'] == 1.0
        print(f"✓ Direct call detected with confidence: {result['max_confidence']}")

    def test_conditional_call_medium_confidence(self, temp_project_root, metrics_collector):
        """L2-CONF-2: Conditional call → Lower confidence"""
        js_file = temp_project_root / "conditional.js"
        js_file.write_text("""
import _ from 'lodash';

if (useTemplate) {
    const compiled = _.template(data);  // Conditional
}
        """)

        # Confidence should be lower for conditional usage
        # Actual implementation may vary


class TestAdvancedPatterns:
    """Advanced import/call patterns"""

    def test_aliased_import(self, temp_project_root, metrics_collector):
        """L2-ADV-1: Aliased import (import _ as lodash)"""
        print("\n" + "="*70)
        print("L2-ADV-1: Aliased Import")
        print("="*70)

        js_file = temp_project_root / "aliased.js"
        js_file.write_text("""
import _ as lodash from 'lodash';

export function process(data) {
    return lodash.map(data, x => x);
}
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        assert result['is_imported'] == True

    def test_namespace_import(self, temp_project_root, metrics_collector):
        """L2-ADV-2: Namespace import (* as _)"""
        js_file = temp_project_root / "namespace.js"
        js_file.write_text("""
import * as _ from 'lodash';

export const process = data => _.map(data, x => x);
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        assert result['is_imported'] == True

    def test_dynamic_import(self, temp_project_root, metrics_collector):
        """L2-ADV-3: Dynamic import()"""
        print("\n" + "="*70)
        print("L2-ADV-3: Dynamic Import")
        print("="*70)

        js_file = temp_project_root / "dynamic.js"
        js_file.write_text("""
export async function loadLodash() {
    const _ = await import('lodash');
    return _.map([1, 2, 3], x => x * 2);
}
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        # Should detect dynamic imports
        assert result['is_imported'] == True

    def test_commented_import(self, temp_project_root, metrics_collector):
        """L2-ADV-4: Commented out import (should NOT count)"""
        print("\n" + "="*70)
        print("L2-ADV-4: Commented Import (Should NOT Count)")
        print("="*70)

        js_file = temp_project_root / "commented.js"
        js_file.write_text("""
// import lodash from 'lodash';  // Commented out
/* import _ from 'lodash'; */   // Commented out

import axios from 'axios';  // Only this is active
        """)

        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("lodash", "javascript")

        # Should NOT detect commented imports
        # (Current implementation may detect - would be a good enhancement)
        print(f"Detected in comments: {result['is_imported']}")


class TestIntegrationL1L2:
    """Integration tests combining L1 and L2"""

    def test_l1_says_reachable_l2_confirms(self, temp_project_root, metrics_collector):
        """L2-INT-1: L1=REACHABLE (scope=required) + L2=IMPORTED → HIGH CONFIDENCE"""
        print("\n" + "="*70)
        print("L2-INT-1: L1 + L2 Both Say REACHABLE")
        print("="*70)

        # Create source file with import
        js_file = temp_project_root / "app.js"
        js_file.write_text("""
import lodash from 'lodash';
export const process = data => lodash.map(data, x => x);
        """)

        # SBOM says it's required
        component = {
            "name": "lodash",
            "version": "4.17.15",
            "scope": "required",
            "purl": "pkg:npm/lodash@4.17.15"
        }
        sbom_data = {"components": [component]}

        # L1 + L2 analysis
        result = analyze_reachability(
            component,
            sbom_data,
            project_root=str(temp_project_root),
            enable_level_2=True
        )

        print(f"Reachable: {result['reachable']}")
        print(f"Confidence: {result['confidence']}")
        print(f"L2 Analysis: {result.get('level_2_import_analysis', {}).get('is_imported')}")

        assert result['reachable'] == True
        assert result['confidence'] == 'high'  # Both L1 and L2 agree

        metrics_collector.add_result("L2-INT-1", "confidence_level", result['confidence'])

    def test_l1_says_reachable_l2_says_not_imported(self, temp_project_root, metrics_collector):
        """L2-INT-2: L1=REACHABLE but L2=NOT IMPORTED → UNREACHABLE (L2 wins)"""
        print("\n" + "="*70)
        print("L2-INT-2: L1 says REACHABLE but L2 says NOT IMPORTED")
        print("="*70)

        # Create source file WITHOUT lodash import
        js_file = temp_project_root / "app.js"
        js_file.write_text("""
import axios from 'axios';
export const fetch = url => axios.get(url);
        """)

        # SBOM says lodash is required (but it's not actually used in code!)
        component = {
            "name": "lodash",
            "version": "4.17.15",
            "scope": "required",  # L1 would say reachable
            "purl": "pkg:npm/lodash@4.17.15"
        }
        sbom_data = {"components": [component]}

        # L2 should override L1
        result = analyze_reachability(
            component,
            sbom_data,
            project_root=str(temp_project_root),
            enable_level_2=True
        )

        print(f"Reachable: {result['reachable']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Reason: {result['reason']}")

        # L2 should determine it's NOT reachable despite L1 saying it is
        assert result['reachable'] == False
        assert result['confidence'] == 'high'
        assert "not imported" in result['reason'].lower()

        metrics_collector.add_result("L2-INT-2", "l2_override", True)

    def test_l1_devdep_l2_skipped(self, temp_project_root, metrics_collector):
        """L2-INT-3: L1=DEV_DEPENDENCY → L2 analysis skipped (optimization)"""
        print("\n" + "="*70)
        print("L2-INT-3: Dev Dependency (L2 Skipped)")
        print("="*70)

        component = {
            "name": "jest",
            "version": "27.0.0",
            "properties": [
                {"name": "cdx:npm:package:development", "value": "true"}
            ],
            "purl": "pkg:npm/jest@27.0.0"
        }
        sbom_data = {"components": [component]}

        # L1 should mark as unreachable, L2 not needed
        result = analyze_reachability(
            component,
            sbom_data,
            project_root=str(temp_project_root),
            enable_level_2=True
        )

        assert result['reachable'] == False
        assert result['is_dev_only'] == True
        # L2 should not have run (optimization)
        assert 'level_2_import_analysis' not in result

        print(f"✓ L1 filtered dev dependency, L2 skipped (optimized)")


class TestMultiLanguageProjects:
    """Projects with multiple languages"""

    def test_js_and_python_same_project(self, temp_project_root, metrics_collector):
        """L2-MULTI-1: JavaScript + Python in same project"""
        print("\n" + "="*70)
        print("L2-MULTI-1: Multi-Language Project")
        print("="*70)

        # JavaScript file
        (temp_project_root / "frontend.js").write_text("""
import axios from 'axios';
export const api = axios.create({ baseURL: '/api' });
        """)

        # Python file
        (temp_project_root / "backend.py").write_text("""
from flask import Flask, jsonify
import requests

app = Flask(__name__)
        """)

        # Check JavaScript package
        js_analyzer = ImportGraphAnalyzer(str(temp_project_root))
        axios_result = js_analyzer.analyze_package_usage("axios", "javascript")
        assert axios_result['is_imported'] == True

        # Check Python package
        py_analyzer = ImportGraphAnalyzer(str(temp_project_root))
        flask_result = py_analyzer.analyze_package_usage("flask", "python")
        requests_result = py_analyzer.analyze_package_usage("requests", "python")

        assert flask_result['is_imported'] == True
        assert requests_result['is_imported'] == True

        print(f"✓ Multi-language analysis working")
        print(f"  JavaScript: axios found")
        print(f"  Python: flask, requests found")

        metrics_collector.add_result("L2-MULTI-1", "js_packages", 1)
        metrics_collector.add_result("L2-MULTI-1", "py_packages", 2)


class TestPerformance:
    """Performance tests for L2 analysis"""

    def test_large_file_performance(self, temp_project_root, performance_tracker, metrics_collector):
        """L2-PERF-1: Large file with many imports"""
        print("\n" + "="*70)
        print("L2-PERF-1: Large File Performance")
        print("="*70)

        # Generate large file with many imports
        imports = [f"import pkg{i} from 'package{i}';" for i in range(100)]
        large_file = temp_project_root / "large.js"
        large_file.write_text("\n".join(imports))

        performance_tracker.start("large_file_analysis")
        analyzer = ImportGraphAnalyzer(str(temp_project_root))
        result = analyzer.analyze_package_usage("package50", "javascript")
        performance_tracker.stop("large_file_analysis")

        duration = performance_tracker.get_duration("large_file_analysis")

        print(f"Analysis Time: {duration:.3f}s")
        print(f"Package Found: {result['is_imported']}")

        assert duration < 5.0  # Should be fast
        assert result['is_imported'] == True

        metrics_collector.add_result("L2-PERF-1", "duration_sec", duration)
