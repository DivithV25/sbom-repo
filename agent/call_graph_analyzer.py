"""
Level 2 Reachability Analyzer - Call Graph Analysis

Builds call graphs to determine if specific vulnerable functions are actually invoked.
This provides function-level precision for vulnerability reachability.

Supported Languages:
- JavaScript/TypeScript (function calls, method calls)
- Python (AST-based function call detection)
- Java (method calls, static methods)
- Go (function calls, method calls)
- C# (method calls, static methods)
- Ruby (method calls with/without parens)
- Rust (function calls, macro calls)
- PHP (function calls, method calls, static methods)

Example:
- Package: lodash
- Vulnerable Function: _.template() (CVE-2021-23337)
- Analysis: Checks if your code calls _.template() specifically, not just imports lodash

Confidence Levels:
- 1.0 (HIGH): Direct call found (e.g., _.template(userInput))
- 0.8 (MEDIUM-HIGH): Indirect call through wrapper
- 0.6 (MEDIUM): Conditional call (inside if/try)
- 0.3 (LOW): Imported but no usage found
- 0.0 (NONE): Not imported at all
"""

import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Set, Optional, Tuple
from agent.config_loader import get_config


class CallGraphAnalyzer:
    """Analyzes function calls to determine if vulnerable functions are invoked"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.config = get_config()
        self.call_graph_config = self.config.get_call_graph_config()
        self.supported_languages = self.call_graph_config.get('supported_languages', ['javascript', 'python'])
        self.confidence_scores = self.call_graph_config.get('confidence', {
            'direct_call': 1.0,
            'indirect_call': 0.8,
            'conditional_call': 0.6,
            'unused_import': 0.2
        })

    def analyze_vulnerable_function_usage(
        self,
        package_name: str,
        vulnerable_functions: List[str],
        language: str = "javascript"
    ) -> Dict[str, Any]:
        """
        Analyze if vulnerable functions are actually called.

        Args:
            package_name: Name of the package (e.g., "lodash")
            vulnerable_functions: List of vulnerable function names (e.g., ["template", "_.template"])
            language: Programming language

        Returns:
            {
                "package": str,
                "vulnerable_functions": [str],
                "call_locations": [{"file": str, "line": int, "function": str, "context": str, "confidence": float}],
                "is_vulnerable_function_called": bool,
                "max_confidence": float,
                "summary": str
            }
        """

        if language.lower() in ["javascript", "typescript", "js", "ts"]:
            return self._analyze_javascript_calls(package_name, vulnerable_functions)
        elif language.lower() in ["python", "py"]:
            return self._analyze_python_calls(package_name, vulnerable_functions)
        elif language.lower() in ["java"]:
            return self._analyze_java_calls(package_name, vulnerable_functions)
        elif language.lower() in ["go", "golang"]:
            return self._analyze_go_calls(package_name, vulnerable_functions)
        elif language.lower() in ["csharp", "c#", "cs"]:
            return self._analyze_csharp_calls(package_name, vulnerable_functions)
        elif language.lower() in ["ruby", "rb"]:
            return self._analyze_ruby_calls(package_name, vulnerable_functions)
        elif language.lower() in ["rust", "rs"]:
            return self._analyze_rust_calls(package_name, vulnerable_functions)
        elif language.lower() in ["php"]:
            return self._analyze_php_calls(package_name, vulnerable_functions)
        else:
            return {
                "package": package_name,
                "vulnerable_functions": vulnerable_functions,
                "call_locations": [],
                "is_vulnerable_function_called": False,
                "max_confidence": 0.0,
                "summary": f"Unsupported language: {language}"
            }

    def _analyze_javascript_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript function calls"""

        call_locations = []

        # Find all JS/TS files
        js_files = list(self.project_root.glob("**/*.js"))
        ts_files = list(self.project_root.glob("**/*.ts"))
        tsx_files = list(self.project_root.glob("**/*.tsx"))
        jsx_files = list(self.project_root.glob("**/*.jsx"))

        all_files = js_files + ts_files + tsx_files + jsx_files

        # Build regex patterns for each vulnerable function
        # Handle variations: _.template, lodash.template, template (if destructured)
        patterns = []
        for func in vulnerable_functions:
            # Direct call: _.template(...)
            patterns.append((rf'\b{re.escape(func)}\s*\(', func, 'direct'))

            # Package call: lodash.template(...)
            patterns.append((rf'{package_name}\.{func}\s*\(', func, 'direct'))

            # Destructured: const { template } = lodash; template(...)
            func_clean = func.replace('_.', '').replace(f'{package_name}.', '')
            patterns.append((rf'\b{func_clean}\s*\(', func_clean, 'possibly_destructured'))

        for file_path in all_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # First pass: Check if package is imported
                    package_imported = any(
                        package_name in line and ('import' in line or 'require' in line)
                        for line in lines
                    )

                    if not package_imported:
                        continue  # Skip files that don't import the package

                    # Second pass: Look for function calls
                    for line_num, line in enumerate(lines, 1):
                        for pattern, func_name, call_type in patterns:
                            if re.search(pattern, line):
                                # Determine confidence based on context
                                confidence = self._determine_js_call_confidence (
                                    line,
                                    content,
                                    line_num,
                                    call_type,
                                    package_imported
                                )

                                call_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "function": func_name,
                                    "context": self._extract_context(lines, line_num),
                                    "confidence": confidence,
                                    "code_snippet": line.strip()
                                })

            except Exception as e:
                continue

        # Calculate summary
        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3  # Threshold for "actually called"

        summary = self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": summary
        }

    def _analyze_python_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze Python function calls using AST"""

        call_locations = []

        # Find all Python files
        py_files = list(self.project_root.glob("**/*.py"))

        for file_path in py_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                # Parse Python AST
                try:
                    tree = ast.parse(content, filename=str(file_path))
                except SyntaxError:
                    continue

                # Track imports to understand aliases
                imports = self._extract_python_imports(tree, package_name)

                if not imports:
                    continue  # Skip if package not imported

                # Walk AST to find function calls
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        call_info = self._identify_python_call(node, vulnerable_functions, imports)

                        if call_info:
                            func_name, confidence = call_info

                            call_locations.append({
                                "file": str(file_path.relative_to(self.project_root)),
                                "line": node.lineno,
                                "function": func_name,
                                "context": self._extract_context(lines, node.lineno),
                                "confidence": confidence,
                                "code_snippet": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                            })

            except Exception as e:
                continue

        # Calculate summary
        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        summary = self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": summary
        }

    def _determine_js_call_confidence(
        self,
        line: str,
        content: str,
        line_num: int,
        call_type: str,
        package_imported: bool
    ) -> float:
        """Determine confidence level for JavaScript call"""

        if not package_imported:
            return 0.0

        # Direct call to known vulnerable function
        if call_type == 'direct':
            # Check if it's in a conditional
            if any(keyword in line for keyword in ['if (', 'if(', '? ', 'try ', 'catch ']):
                return self.confidence_scores['conditional_call']
            else:
                return self.confidence_scores['direct_call']

        # Possibly destructured - less certain
        elif call_type == 'possibly_destructured':
            # Check if function was actually destructured from package
            # This is a heuristic - full analysis would need data flow
            return self.confidence_scores['indirect_call']

        return self.confidence_scores['unused_import']

    def _extract_python_imports(self, tree: ast.AST, package_name: str) -> Dict[str, str]:
        """
        Extract import information from Python AST.

        Returns:
            Dict mapping alias to actual module (e.g., {"pd": "pandas"})
        """
        imports = {}

        for node in ast.walk(tree):
            # import package_name as alias
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == package_name:
                        name = alias.asname if alias.asname else alias.name
                        imports[name] = alias.name

            # from package_name import func
            elif isinstance(node, ast.ImportFrom):
                if node.module == package_name:
                    for alias in node.names:
                        name = alias.asname if alias.asname else alias.name
                        imports[name] = f"{package_name}.{alias.name}"

        return imports

    def _identify_python_call(
        self,
        node: ast.Call,
        vulnerable_functions: List[str],
        imports: Dict[str, str]
    ) -> Optional[Tuple[str, float]]:
        """
        Identify if AST Call node matches a vulnerable function.

        Returns:
            Tuple of (function_name, confidence) or None
        """

        # Get function being called
        if isinstance(node.func, ast.Name):
            # Direct call: template(...)
            func_name = node.func.id

            if func_name in imports:
                # This is an imported function
                full_name = imports[func_name]

                for vuln_func in vulnerable_functions:
                    if vuln_func in full_name or func_name == vuln_func:
                        return (vuln_func, self.confidence_scores['direct_call'])

        elif isinstance(node.func, ast.Attribute):
            # Attribute call: package.function(...)
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
                method_name = node.func.attr

                if obj_name in imports:
                    full_call = f"{imports[obj_name]}.{method_name}"

                    for vuln_func in vulnerable_functions:
                        if vuln_func in full_call or method_name == vuln_func:
                            return (vuln_func, self.confidence_scores['direct_call'])

        return None

    def _extract_context(self, lines: List[str], line_num: int, context_size: int = 2) -> str:
        """Extract code context around a line"""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)

        context_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "
            context_lines.append(f"{marker} {lines[i]}")

        return "\n".join(context_lines)

    def _analyze_java_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze Java method calls"""
        call_locations = []
        java_files = list(self.project_root.glob("**/*.java"))

        for file_path in java_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if package is imported
                    package_imported = any(
                        'import' in line and package_name.replace('-', '.') in line
                        for line in lines
                    )

                    if not package_imported:
                        continue

                    # Look for method calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # Match: object.method(), Class.method(), method()
                            patterns = [
                                rf'\b{func}\s*\(',  # Direct call
                                rf'\.\s*{func}\s*\(',  # Method call
                            ]

                            for pattern in patterns:
                                if re.search(pattern, line):
                                    confidence = 1.0 if '.' in pattern else 0.8

                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": confidence,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _analyze_go_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze Go function calls"""
        call_locations = []
        go_files = list(self.project_root.glob("**/*.go"))

        for file_path in go_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if package is imported
                    package_imported = any(
                        'import' in line and package_name in line
                        for line in lines
                    )

                    if not package_imported:
                        continue

                    # Look for function calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # Go: package.Function(), alias.Function()
                            patterns = [
                                rf'\b{package_name}\.{func}\s*\(',
                                rf'\w+\.{func}\s*\(',  # Aliased import
                                rf'\b{func}\s*\('  # Direct (if dot-imported)
                            ]

                            for idx, pattern in enumerate(patterns):
                                if re.search(pattern, line):
                                    confidence = 1.0 if idx == 0 else 0.7

                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": confidence,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _analyze_csharp_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze C# method calls"""
        call_locations = []
        cs_files = list(self.project_root.glob("**/*.cs"))

        for file_path in cs_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if namespace is used
                    namespace_used = any(
                        'using' in line and package_name.replace('-', '.') in line
                        for line in lines
                    )

                    if not namespace_used:
                        continue

                    # Look for method calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # C#: Object.Method(), Class.Method(), Method()
                            patterns = [
                                rf'\b{func}\s*\(',
                                rf'\.\s*{func}\s*\(',
                            ]

                            for pattern in patterns:
                                if re.search(pattern, line):
                                    confidence = 1.0 if '.' in line else 0.7

                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": confidence,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _analyze_ruby_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze Ruby method calls"""
        call_locations = []
        rb_files = list(self.project_root.glob("**/*.rb"))

        for file_path in rb_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if gem is required
                    gem_required = any(
                        ('require' in line or 'gem' in line) and package_name in line
                        for line in lines
                    )

                    if not gem_required:
                        continue

                    # Look for method calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # Ruby: object.method, Module.method, method()
                            patterns = [
                                rf'\b{func}\s*\(',  # Method call with parens
                                rf'\b{func}\s+',    # Method call without parens
                                rf'\.\s*{func}\b',  # Chained method
                            ]

                            for pattern in patterns:
                                if re.search(pattern, line):
                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": 0.9,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _analyze_rust_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze Rust function calls"""
        call_locations = []
        rs_files = list(self.project_root.glob("**/*.rs"))

        rust_crate_name = package_name.replace('-', '_')

        for file_path in rs_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if crate is used
                    crate_used = any(
                        'use' in line and rust_crate_name in line
                        for line in lines
                    )

                    if not crate_used:
                        continue

                    # Look for function calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # Rust: crate::function(), module::function(), function!()
                            patterns = [
                                rf'{rust_crate_name}::{func}\s*\(',
                                rf'\b{func}\s*\(',
                                rf'{func}!',  # Macro call
                            ]

                            for pattern in patterns:
                                if re.search(pattern, line):
                                    confidence = 1.0 if rust_crate_name in pattern else 0.7

                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": confidence,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _analyze_php_calls(
        self,
        package_name: str,
        vulnerable_functions: List[str]
    ) -> Dict[str, Any]:
        """Analyze PHP function/method calls"""
        call_locations = []
        php_files = list(self.project_root.glob("**/*.php"))

        for file_path in php_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    # Check if package is used
                    package_used = any(
                        ('use' in line or 'require' in line) and package_name in line
                        for line in lines
                    )

                    if not package_used:
                        continue

                    # Look for function/method calls
                    for line_num, line in enumerate(lines, 1):
                        for func in vulnerable_functions:
                            # PHP: $object->method(), Class::method(), function()
                            patterns = [
                                rf'->\s*{func}\s*\(',  # Instance method
                                rf'::\s*{func}\s*\(',  # Static method
                                rf'\b{func}\s*\(',     # Function call
                            ]

                            for pattern in patterns:
                                if re.search(pattern, line):
                                    confidence = 1.0 if '->' in pattern or '::' in pattern else 0.7

                                    call_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "function": func,
                                        "context": self._extract_context(lines, line_num),
                                        "confidence": confidence,
                                        "code_snippet": line.strip()
                                    })

            except Exception:
                continue

        max_confidence = max([loc['confidence'] for loc in call_locations], default=0.0)
        is_called = max_confidence > 0.3

        return {
            "package": package_name,
            "vulnerable_functions": vulnerable_functions,
            "call_locations": call_locations,
            "is_vulnerable_function_called": is_called,
            "max_confidence": max_confidence,
            "summary": self._generate_call_summary(package_name, vulnerable_functions, call_locations, max_confidence)
        }

    def _generate_call_summary(
        self,
        package_name: str,
        vulnerable_functions: List[str],
        call_locations: List[Dict],
        max_confidence: float
    ) -> str:
        """Generate human-readable summary of call analysis"""

        if max_confidence == 0.0:
            return f"{package_name} is not imported or vulnerable functions are not called"

        elif max_confidence >= 0.8:
            return f"HIGH RISK: {len(call_locations)} direct call(s) to vulnerable functions found"

        elif max_confidence >= 0.6:
            return f"MEDIUM RISK: {len(call_locations)} conditional/indirect call(s) found"

        elif max_confidence >= 0.3:
            return f"LOW RISK: Vulnerable functions imported but limited usage detected"

        else:
            return f"MINIMAL RISK: Package imported but vulnerable functions appear unused"

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be excluded"""
        exclude_patterns = self.config.get_code_context_config().get('exclude_patterns', [])

        file_str = str(file_path)
        for pattern in exclude_patterns:
            pattern_clean = pattern.replace('**/', '').replace('/**', '')
            if pattern_clean in file_str:
                return True
        return False


# Convenience functions
def analyze_vulnerable_function(
    package_name: str,
    vulnerable_functions: List[str],
    project_root: str,
    language: str = "javascript"
) -> Dict[str, Any]:
    """
    Quick analysis of vulnerable function usage.

    Example:
        result = analyze_vulnerable_function(
            "lodash",
            ["_.template", "template"],
            "/path/to/project",
            "javascript"
        )
    """
    analyzer = CallGraphAnalyzer(project_root)
    return analyzer.analyze_vulnerable_function_usage(package_name, vulnerable_functions, language)


# Known vulnerable functions database (can be expanded)
KNOWN_VULNERABLE_FUNCTIONS = {
    "lodash": {
        "CVE-2021-23337": ["_.template", "template"],
        "CVE-2020-8203": ["_.zipObjectDeep", "zipObjectDeep"],
        "CVE-2019-10744": ["_.defaultsDeep", "defaultsDeep"]
    },
    "axios": {
        "CVE-2021-3749": ["axios.get", "axios.post", "axios.request"]
    },
    "express": {
        "CVE-2022-24999": ["res.redirect"]
    },
    "jquery": {
        "CVE-2020-11023": ["$.html", ".html"]
    }
}


def get_vulnerable_functions_for_cve(package_name: str, cve_id: str) -> List[str]:
    """Get list of vulnerable functions for a given CVE"""
    return KNOWN_VULNERABLE_FUNCTIONS.get(package_name, {}).get(cve_id, [])


if __name__ == "__main__":
    # Test call graph analysis
    import sys

    if len(sys.argv) < 4:
        print("Usage: python call_graph_analyzer.py <package> <functions> <project_root> [language]")
        print("Example: python call_graph_analyzer.py lodash '_.template,template' /path/to/project javascript")
        sys.exit(1)

    package = sys.argv[1]
    functions = sys.argv[2].split(',')
    project = sys.argv[3]
    lang = sys.argv[4] if len(sys.argv) > 4 else "javascript"

    result = analyze_vulnerable_function(package, functions, project, lang)

    print(f"\n=== Call Graph Analysis: {package} ===\n")
    print(f"Vulnerable Functions: {', '.join(result['vulnerable_functions'])}")
    print(f"Is Function Called: {result['is_vulnerable_function_called']}")
    print(f"Max Confidence: {result['max_confidence']:.2f}")
    print(f"\n{result['summary']}\n")

    if result['call_locations']:
        print("Call Locations:")
        for i, loc in enumerate(result['call_locations'][:5], 1):  # Show first 5
            print(f"\n{i}. {loc['file']}:{loc['line']} (Confidence: {loc['confidence']:.2f})")
            print(f"   Function: {loc['function']}")
            print(f"   Code: {loc['code_snippet']}")
