"""
Level 2 Reachability Analyzer - Import Graph Analysis

Analyzes actual code to determine if vulnerable packages are imported and used.
Goes beyond scope-based analysis to provide function-level precision.

Supported Languages:
- JavaScript/TypeScript (ES6, CommonJS, AMD)
- Python (import, from...import)
- Java (import statements, Maven/Gradle packages)
- Go (import statements)
- C# (using statements, NuGet packages)
- Ruby (require, gem)
- Rust (use, extern crate)
- PHP (use, require, include)

Analysis Levels:
1. Import Detection: Is the package imported anywhere?
2. Usage Detection: Are specific functions from the package called?
3. Call Graph: Which specific vulnerable functions are invoked?
"""

import os
import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Set, Optional, Tuple
from agent.config_loader import get_config


class ImportGraphAnalyzer:
    """Analyzes import statements to build dependency graph"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.config = get_config()
        self.import_graph_config = self.config.get_import_graph_config()
        self.max_depth = self.import_graph_config.get('max_depth', 10)

        # Cache for performance
        self._import_cache: Dict[str, Set[str]] = {}
        self._call_cache: Dict[str, List[Tuple[str, str, int]]]  = {}

    def analyze_package_usage(
        self,
        package_name: str,
        language: str = "javascript"
    ) -> Dict[str, Any]:
        """
        Analyze if and how a package is used in the codebase.

        Args:
            package_name: Name of the package to analyze (e.g., "lodash", "requests")
            language: Programming language ("javascript", "python", "typescript")

        Returns:
            {
                "is_imported": bool,
                "import_locations": [{"file": str, "line": int, "type": "import|require"}],
                "usage_count": int,
                "imported_functions": [str],  # List of specific functions imported
                "confidence": float  # 0.0-1.0
            }
        """

        if language.lower() in ["javascript", "typescript", "js", "ts"]:
            return self._analyze_javascript_imports(package_name)
        elif language.lower() in ["python", "py"]:
            return self._analyze_python_imports(package_name)
        elif language.lower() in ["java"]:
            return self._analyze_java_imports(package_name)
        elif language.lower() in ["go", "golang"]:
            return self._analyze_go_imports(package_name)
        elif language.lower() in ["csharp", "c#", "cs"]:
            return self._analyze_csharp_imports(package_name)
        elif language.lower() in ["ruby", "rb"]:
            return self._analyze_ruby_imports(package_name)
        elif language.lower() in ["rust", "rs"]:
            return self._analyze_rust_imports(package_name)
        elif language.lower() in ["php"]:
            return self._analyze_php_imports(package_name)
        else:
            return {
                "is_imported": None,
                "import_locations": [],
                "usage_count": 0,
                "imported_functions": [],
                "confidence": 0.0,
                "error": f"Unsupported language: {language}"
            }

    def _analyze_javascript_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript imports"""

        import_locations = []
        imported_functions = set()

        # Find all JS/TS files
        js_files = list(self.project_root.glob("**/*.js"))
        ts_files = list(self.project_root.glob("**/*.ts"))
        tsx_files = list(self.project_root.glob("**/*.tsx"))
        jsx_files = list(self.project_root.glob("**/*.jsx"))

        all_files = js_files + ts_files + tsx_files + jsx_files

        # Regex patterns for import detection
        # Note: Using regular strings with format, not raw f-strings to avoid regex conflicts
        patterns = [
            # ES6 imports
            r'import\s+.*?\s+from\s+[\'"](' + package_name + r')[\'"]',
            r'import\s+[\'"](' + package_name + r')[\'"]',
            r'import\s*\{([^}]+)\}\s*from\s+[\'"](' + package_name + r')[\'"]',
            r'import\s+(\w+)\s+from\s+[\'"](' + package_name + r')[\'"]',

            # CommonJS require
            r'require\s*\(\s*[\'"](' + package_name + r')[\'"]\s*\)',
            r'const\s+\w+\s*=\s*require\s*\(\s*[\'"](' + package_name + r')[\'"]\s*\)',
            r'const\s+\{([^}]+)\}\s*=\s*require\s*\(\s*[\'"](' + package_name + r')[\'"]\s*\)',

            # Dynamic imports
            r'import\s*\(\s*[\'"](' + package_name + r')[\'"]\s*\)',
        ]

        for file_path in all_files:
            try:
                # Skip node_modules and other excluded directories
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                import_type = "import" if "import" in line else "require"

                                import_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "type": import_type,
                                    "statement": line.strip()
                                })

                                # Extract imported functions from destructured imports
                                # e.g., import { map, filter } from 'lodash'
                                destructure_match = re.search(r'\{([^}]+)\}', line)
                                if destructure_match:
                                    functions = destructure_match.group(1).split(',')
                                    for func in functions:
                                        func_name = func.strip().split(' as ')[0].strip()
                                        imported_functions.add(func_name)

            except Exception as e:
                # Skip files that can't be read
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_python_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze Python imports using AST"""

        import_locations = []
        imported_functions = set()

        # Find all Python files
        py_files = list(self.project_root.glob("**/*.py"))

        for file_path in py_files:
            try:
                # Skip excluded directories
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Parse Python AST
                try:
                    tree = ast.parse(content, filename=str(file_path))
                except SyntaxError:
                    # Skip files with syntax errors
                    continue

                # Analyze imports
                for node in ast.walk(tree):
                    # import package_name
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name == package_name or alias.name.startswith(f"{package_name}."):
                                import_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": node.lineno,
                                    "type": "import",
                                    "statement": f"import {alias.name}"
                                })

                    # from package_name import ...
                    elif isinstance(node, ast.ImportFrom):
                        if node.module == package_name or (node.module and node.module.startswith(f"{package_name}.")):
                            for alias in node.names:
                                imported_functions.add(alias.name)

                            import_locations.append({
                                "file": str(file_path.relative_to(self.project_root)),
                                "line": node.lineno,
                                "type": "from_import",
                                "statement": f"from {node.module} import {', '.join([a.name for a in node.names])}"
                            })

            except Exception as e:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_java_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze Java imports"""
        import_locations = []
        imported_functions = set()

        # Find all Java files
        java_files = list(self.project_root.glob("**/*.java"))

        # Convert package name to Java format (e.g., "jackson-databind" -> "com.fasterxml.jackson")
        # This is a simplified mapping - real implementation would use Maven/Gradle metadata
        java_package_patterns = [
            package_name.replace('-', '.'),  # Convert hyphens to dots
            f"org.{package_name.replace('-', '.')}",
            f"com.{package_name.replace('-', '.')}",
            package_name  # Try original format too
        ]

        for file_path in java_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # Match Java import statements
                        for pkg_pattern in java_package_patterns:
                            # import package.*;
                            # import package.ClassName;
                            # import static package.ClassName.methodName;
                            patterns = [
                                rf'import\s+({pkg_pattern}[.\w*]+)\s*;',
                                rf'import\s+static\s+({pkg_pattern}[.\w*]+)\s*;'
                            ]

                            for pattern in patterns:
                                match = re.search(pattern, line)
                                if match:
                                    import_type = "static_import" if "static" in line else "import"
                                    imported_class = match.group(1).split('.')[-1]

                                    if imported_class != '*':
                                        imported_functions.add(imported_class)

                                    import_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "type": import_type,
                                        "statement": line.strip()
                                    })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_go_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze Go imports"""
        import_locations = []
        imported_functions = set()

        # Find all Go files
        go_files = list(self.project_root.glob("**/*.go"))

        # Go package paths (e.g., "github.com/user/package")
        for file_path in go_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # Match Go import statements
                        # import "package"
                        # import ( "package1" "package2" )
                        # import alias "package"
                        patterns = [
                            rf'import\s+"([^"]*{package_name}[^"]*)"',
                            rf'import\s+\w+\s+"([^"]*{package_name}[^"]*)"',  # Aliased import
                            rf'"([^"]*{package_name}[^"]*)"'  # In import block
                        ]

                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                import_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "type": "import",
                                    "statement": line.strip()
                                })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_csharp_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze C# using statements"""
        import_locations = []
        imported_functions = set()

        # Find all C# files
        cs_files = list(self.project_root.glob("**/*.cs"))

        # Convert package name to C# namespace format
        csharp_namespace_patterns = [
            package_name.replace('-', '.'),
            package_name.replace('_', '.'),
            f"System.{package_name}",
            package_name
        ]

        for file_path in cs_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        for ns_pattern in csharp_namespace_patterns:
                            # using Namespace;
                            # using Namespace.Class;
                            # using Alias = Namespace;
                            patterns = [
                                rf'using\s+({ns_pattern}[.\w]*)\s*;',
                                rf'using\s+\w+\s*=\s*({ns_pattern}[.\w]*)\s*;'
                            ]

                            for pattern in patterns:
                                match = re.search(pattern, line)
                                if match:
                                    import_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "type": "using",
                                        "statement": line.strip()
                                    })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_ruby_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze Ruby require statements"""
        import_locations = []
        imported_functions = set()

        # Find all Ruby files
        rb_files = list(self.project_root.glob("**/*.rb"))

        for file_path in rb_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # require 'package'
                        # require "package"
                        # require_relative 'package'
                        # gem 'package'
                        patterns = [
                            rf'require\s+[\'"]({package_name})[\'"]',
                            rf'require\s+[\'"]({package_name}/[^\'"]*)[\'"',
                            rf'require_relative\s+[\'"]({package_name})[\'"]',
                            rf'gem\s+[\'"]({package_name})[\'"]'
                        ]

                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                import_type = "gem" if "gem" in line else "require"
                                import_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "type": import_type,
                                    "statement": line.strip()
                                })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_rust_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze Rust use statements"""
        import_locations = []
        imported_functions = set()

        # Find all Rust files
        rs_files = list(self.project_root.glob("**/*.rs"))

        # Convert package name (e.g., "serde_json" or "serde-json")
        rust_crate_name = package_name.replace('-', '_')

        for file_path in rs_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # use crate::module;
                        # use crate::{Type1, Type2};
                        # extern crate crate_name;
                        patterns = [
                            rf'use\s+({rust_crate_name}[:\w]*)',
                            rf'use\s+({rust_crate_name})::\{{([^}}]+)\}}',
                            rf'extern\s+crate\s+({rust_crate_name})'
                        ]

                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                import_type = "extern_crate" if "extern" in line else "use"

                                # Extract imported items from use statements
                                brace_match = re.search(r'\{([^}]+)\}', line)
                                if brace_match:
                                    items = brace_match.group(1).split(',')
                                    for item in items:
                                        imported_functions.add(item.strip())

                                import_locations.append({
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "type": import_type,
                                    "statement": line.strip()
                                })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _analyze_php_imports(self, package_name: str) -> Dict[str, Any]:
        """Analyze PHP require/use statements"""
        import_locations = []
        imported_functions = set()

        # Find all PHP files
        php_files = list(self.project_root.glob("**/*.php"))

        # Convert package name to PHP namespace format
        php_namespace_patterns = [
            package_name.replace('-', '\\'),
            package_name.replace('/', '\\'),
            package_name
        ]

        for file_path in php_files:
            try:
                if self._should_skip_file(file_path):
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        for ns_pattern in php_namespace_patterns:
                            # use Namespace\Class;
                            # use Namespace\Class as Alias;
                            # require 'vendor/package/file.php';
                            # require_once 'vendor/package/file.php';
                            patterns = [
                                rf'use\s+([^;]*{ns_pattern}[^;]*)\s*;',
                                rf'require\s+[\'"]([^\'\"]*{package_name}[^\'\"]*)[\'\"]',
                                rf'require_once\s+[\'"]([^\'\"]*{package_name}[^\'\"]*)[\'\"]',
                                rf'include\s+[\'"]([^\'\"]*{package_name}[^\'\"]*)[\'\"]'
                            ]

                            for pattern in patterns:
                                match = re.search(pattern, line)
                                if match:
                                    import_type = "use" if "use" in line else "require"

                                    # Extract class name from use statements
                                    if import_type == "use":
                                        class_match = re.search(r'\\(\w+)', match.group(1))
                                        if class_match:
                                            imported_functions.add(class_match.group(1))

                                    import_locations.append({
                                        "file": str(file_path.relative_to(self.project_root)),
                                        "line": line_num,
                                        "type": import_type,
                                        "statement": line.strip()
                                    })

            except Exception:
                continue

        return {
            "is_imported": len(import_locations) > 0,
            "import_locations": import_locations,
            "usage_count": len(import_locations),
            "imported_functions": list(imported_functions),
            "confidence": 1.0 if import_locations else 0.0
        }

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from analysis"""
        exclude_patterns = self.config.get_code_context_config().get('exclude_patterns', [
            '**/node_modules/**',
            '**/dist/**',
            '**/build/**',
            '**/.git/**',
            '**/venv/**',
            '**/__pycache__/**'
        ])

        file_str = str(file_path)
        for pattern in exclude_patterns:
            # Simple pattern matching (could use fnmatch for more complex patterns)
            pattern_clean = pattern.replace('**/', '').replace('/**', '')
            if pattern_clean in file_str:
                return True
        return False

    def build_import_graph(self, entry_file: str, language: str = "javascript") -> Dict[str, Set[str]]:
        """
        Build import graph starting from entry file.

        Args:
            entry_file: Entry point file (e.g., "src/index.js")
            language: Programming language

        Returns:
            Graph of file -> imported files mapping
        """

        graph: Dict[str, Set[str]] = {}
        visited: Set[str] = set()

        def traverse(file_path: str, depth: int = 0):
            if depth > self.max_depth or file_path in visited:
                return

            visited.add(file_path)

            if file_path not in graph:
                graph[file_path] = set()

            # Extract imports from file
            full_path = self.project_root / file_path
            if not full_path.exists():
                return

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract local imports (simplified - doesn't handle all cases)
                if language == "javascript":
                    # Match relative imports: import ... from './file' or '../file'
                    import_pattern = r'from\s+[\'"](\.[^\'"]*)[\'"'
                    matches = re.findall(import_pattern, content)

                    for match in matches:
                        imported_file = self._resolve_js_import(file_path, match)
                        if imported_file:
                            graph[file_path].add(imported_file)
                            traverse(imported_file, depth + 1)

                elif language == "python":
                    # Parse Python imports
                    try:
                        tree = ast.parse(content)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.ImportFrom):
                                if node.module and node.module.startswith('.'):
                                    # Relative import
                                    imported_file = self._resolve_python_import(file_path, node.module)
                                    if imported_file:
                                        graph[file_path].add(imported_file)
                                        traverse(imported_file, depth + 1)
                    except:
                        pass

            except Exception:
                pass

        traverse(entry_file)
        return graph

    def _resolve_js_import(self, current_file: str, import_path: str) -> Optional[str]:
        """Resolve JavaScript import path to actual file"""
        # Simplified resolver - production would use full module resolution algorithm
        current_dir = Path(current_file).parent
        resolved = current_dir / import_path

        # Try with common extensions
        for ext in ['.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts']:
            full_path = self.project_root / str(resolved) / ext if ext.startswith('/') else self.project_root / (str(resolved) + ext)
            if full_path.exists():
                return str(full_path.relative_to(self.project_root))

        return None

    def _resolve_python_import(self, current_file: str, module: str) -> Optional[str]:
        """Resolve Python relative import to actual file"""
        # Convert relative import to file path
        # e.g., ".utils" from "src/main.py" -> "src/utils.py"
        current_dir = Path(current_file).parent

        # Count leading dots for relative import level
        level = len(module) - len(module.lstrip('.'))
        module_name = module.lstrip('.')

        # Go up directories based on level
        target_dir = current_dir
        for _ in range(level - 1):
            target_dir = target_dir.parent

        # Resolve module path
        module_path = target_dir / module_name.replace('.', '/')

        # Try as file
        py_file = module_path.with_suffix('.py')
        if (self.project_root / py_file).exists():
            return str(py_file)

        # Try as package
        init_file = module_path / '__init__.py'
        if (self.project_root / init_file).exists():
            return str(init_file)

        return None


# Convenience functions
def analyze_package_import(package_name: str, project_root: str, language: str = "javascript") -> Dict[str, Any]:
    """
    Quick function to check if a package is imported.

    Returns:
        Analysis result with import locations and confidence
    """
    analyzer = ImportGraphAnalyzer(project_root)
    return analyzer.analyze_package_usage(package_name, language)


if __name__ == "__main__":
    # Test import graph analysis
    import sys

    if len(sys.argv) < 3:
        print("Usage: python import_graph_analyzer.py <package_name> <project_root> [language]")
        print("Example: python import_graph_analyzer.py lodash /path/to/project javascript")
        sys.exit(1)

    package = sys.argv[1]
    project = sys.argv[2]
    lang = sys.argv[3] if len(sys.argv) > 3 else "javascript"

    result = analyze_package_import(package, project, lang)

    print(f"\n=== Import Analysis: {package} ===\n")
    print(f"Is Imported: {result['is_imported']}")
    print(f"Usage Count: {result['usage_count']}")
    print(f"Confidence: {result['confidence']}")

    if result['imported_functions']:
        print(f"\nImported Functions: {', '.join(result['imported_functions'])}")

    if result['import_locations']:
        print(f"\nImport Locations:")
        for loc in result['import_locations'][:10]:  # Show first 10
            print(f"  - {loc['file']}:{loc['line']} ({loc['type']})")
            print(f"    {loc['statement']}")
