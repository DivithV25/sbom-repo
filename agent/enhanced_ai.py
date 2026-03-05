"""
Enhanced AI Features for PRISM
Code patch generation and context-aware remediation
"""

import os
import json
from typing import Dict, List, Any, Optional
from pathlib import Path


class CodePatchGenerator:
    """Generate code patches to fix vulnerabilities"""

    def __init__(self, openai_api_key: str = None):
        """
        Initialize code patch generator

        Args:
            openai_api_key: OpenAI API key
        """
        self.api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        self.model = "gpt-4"

    def generate_patch(
        self,
        vulnerability: Dict[str, Any],
        component: Dict[str, Any],
        code_context: Optional[str] = None
    ) -> Optional[Dict[str, str]]:
        """
        Generate a code patch to fix a vulnerability

        Args:
            vulnerability: Vulnerability details
            component: Component details
            code_context: Optional code snippet showing usage

        Returns:
            Patch dict with 'description', 'diff', 'instructions'
        """
        if not self.api_key:
            return None

        # Prepare context
        vuln_id = vulnerability.get('id', 'Unknown')
        vuln_summary = vulnerability.get('summary', 'No description')
        package_name = component.get('name')
        current_version = component.get('version')

        # Build prompt
        prompt = f"""You are a security expert. Generate a code patch to fix this vulnerability.

Vulnerability: {vuln_id}
Package: {package_name}@{current_version}
Description: {vuln_summary}

"""

        if code_context:
            prompt += f"""Current code usage:
```
{code_context}
```

"""

        prompt += """Generate:
1. A brief description of the fix
2. A unified diff patch (if code changes needed)
3. Step-by-step instructions

Format as JSON:
{
  "description": "Brief description",
  "diff": "Unified diff format or 'N/A'",
  "instructions": ["Step 1", "Step 2", ...]
}
"""

        try:
            import requests

            response = requests.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                },
                json={
                    'model': self.model,
                    'messages': [
                        {'role': 'system', 'content': 'You are a security expert who generates precise code patches.'},
                        {'role': 'user', 'content': prompt}
                    ],
                    'temperature': 0.3,
                    'max_tokens': 1500
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']

                # Parse JSON from response
                # Remove markdown code blocks if present
                content = content.strip()
                if content.startswith('```'):
                    lines = content.split('\n')
                    content = '\n'.join(lines[1:-1])  # Remove first and last lines

                patch_data = json.loads(content)
                return patch_data
            else:
                print(f"[CODE_PATCHER] API error: {response.status_code}")
                return None

        except Exception as e:
            print(f"[CODE_PATCHER] Error generating patch: {e}")
            return None


class ContextAnalyzer:
    """Analyze codebase context for better AI remediation"""

    def __init__(self, project_root: str = "."):
        """
        Initialize context analyzer

        Args:
            project_root: Root directory of the project
        """
        self.project_root = Path(project_root)

    def detect_framework(self) -> Optional[str]:
        """
        Detect the framework used in the project

        Returns:
            Framework name or None
        """
        # Check package.json for JavaScript/Node frameworks
        package_json = self.project_root / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}

                    if 'react' in deps:
                        return 'React'
                    elif 'vue' in deps:
                        return 'Vue.js'
                    elif 'angular' in deps:
                        return 'Angular'
                    elif 'express' in deps:
                        return 'Express.js'
                    elif 'next' in deps:
                        return 'Next.js'
            except Exception:
                pass

        # Check for Python frameworks
        requirements = self.project_root / "requirements.txt"
        if requirements.exists():
            try:
                with open(requirements, 'r', encoding='utf-8') as f:
                    content = f.read().lower()
                    if 'django' in content:
                        return 'Django'
                    elif 'flask' in content:
                        return 'Flask'
                    elif 'fastapi' in content:
                        return 'FastAPI'
            except Exception:
                pass

        return None

    def find_package_usage(self, package_name: str, max_files: int = 10) -> List[Dict[str, Any]]:
        """
        Find where a package is used in the codebase

        Args:
            package_name: Package to search for
            max_files: Maximum number of files to return

        Returns:
            List of usage locations
        """
        usages = []

        # Common source directories
        source_dirs = ['src', 'lib', 'app', 'components', 'pages', 'views', 'controllers']

        # Search patterns
        import_patterns = [
            f"import {package_name}",
            f"from {package_name}",
            f"require('{package_name}')",
            f'require("{package_name}")'
        ]

        for source_dir in source_dirs:
            dir_path = self.project_root / source_dir
            if not dir_path.exists():
                continue

            # Search files
            for file_path in dir_path.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx', '.py']:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()

                            for pattern in import_patterns:
                                if pattern in content:
                                    # Find the line number
                                    lines = content.split('\n')
                                    for line_num, line in enumerate(lines, 1):
                                        if pattern in line:
                                            usages.append({
                                                'file': str(file_path.relative_to(self.project_root)),
                                                'line': line_num,
                                                'code': line.strip()
                                            })
                                            break

                                    if len(usages) >= max_files:
                                        return usages

                    except Exception:
                        continue

        return usages

    def get_context_summary(self, package_name: str) -> Dict[str, Any]:
        """
        Get comprehensive context summary for a package

        Args:
            package_name: Package name

        Returns:
            Context summary dict
        """
        framework = self.detect_framework()
        usages = self.find_package_usage(package_name)

        return {
            'framework': framework,
            'usage_count': len(usages),
            'usage_locations': usages[:5],  # Limit to first 5
            'has_usage': len(usages) > 0
        }

    def generate_context_prompt(self, package_name: str, vulnerability: Dict) -> str:
        """
        Generate context-aware prompt for AI

        Args:
            package_name: Package name
            vulnerability: Vulnerability details

        Returns:
            Enhanced prompt string
        """
        context = self.get_context_summary(package_name)

        prompt = f"Package: {package_name}\n"
        prompt += f"Vulnerability: {vulnerability.get('id', 'Unknown')}\n"

        if context['framework']:
            prompt += f"Framework: {context['framework']}\n"
            prompt += f"Provide {context['framework']}-specific migration guidance.\n"

        if context['has_usage']:
            prompt += f"\nThis package is used in {context['usage_count']} file(s):\n"
            for usage in context['usage_locations']:
                prompt += f"- {usage['file']} (line {usage['line']}): {usage['code']}\n"
            prompt += "\nProvide migration steps specific to these usage patterns.\n"
        else:
            prompt += "\nNote: Package appears to be a transitive dependency (not directly imported).\n"

        return prompt
