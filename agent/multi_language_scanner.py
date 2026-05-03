"""
Multi-Language Manifest Detector and SBOM Generator

Supports:
- Node.js (package.json)
- Python (requirements.txt, Pipfile)
- Go (go.mod)
- Maven/Java (pom.xml)
"""
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class ManifestDetector:
    """Detects and locates dependency manifest files"""

    MANIFEST_PATTERNS = {
        "npm": {"files": ["package.json"], "ecosystem": "npm"},
        "python": {"files": ["requirements.txt", "Pipfile", "setup.py"], "ecosystem": "pypi"},
        "go": {"files": ["go.mod"], "ecosystem": "golang"},
        "maven": {"files": ["pom.xml"], "ecosystem": "maven"},
    }

    @staticmethod
    def detect_manifests(root_path: str) -> Dict[str, List[str]]:
        """
        Recursively detect all manifest files in a directory tree.

        Args:
            root_path: Root directory to search

        Returns:
            Dict mapping manifest type to list of file paths
        """
        found = {pkg_type: [] for pkg_type in ManifestDetector.MANIFEST_PATTERNS}

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Skip common unneeded directories
            dirnames[:] = [d for d in dirnames if d not in ['.git', 'node_modules', '.venv', 'venv', 'target']]

            for pkg_type, config in ManifestDetector.MANIFEST_PATTERNS.items():
                for manifest_file in config["files"]:
                    if manifest_file in filenames:
                        full_path = os.path.join(dirpath, manifest_file)
                        found[pkg_type].append(full_path)

        return {k: v for k, v in found.items() if v}


class DependencyParser:
    """Parse different manifest file formats"""

    @staticmethod
    def parse_package_json(path: str) -> List[Dict]:
        """Parse Node.js package.json"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            components = []
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}

            for name, version in deps.items():
                # Clean version (remove ^, ~, etc.)
                clean_version = re.sub(r'^[\^~>=<]+', '', version).split('+')[0]
                components.append({
                    'name': name,
                    'version': clean_version,
                    'ecosystem': 'npm',
                    'purl': f'pkg:npm/{name}@{clean_version}'
                })

            return components
        except Exception as e:
            print(f"❌ Error parsing {path}: {e}")
            return []

    @staticmethod
    def parse_requirements_txt(path: str) -> List[Dict]:
        """Parse Python requirements.txt"""
        try:
            components = []

            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Parse requirement: package==version or package>=version
                    match = re.match(r'^([a-zA-Z0-9\-_.]+)\s*([=!<>~]+)\s*(.+)$', line)
                    if match:
                        name, op, version = match.groups()
                        clean_version = version.split(';')[0].strip()
                        components.append({
                            'name': name,
                            'version': clean_version,
                            'ecosystem': 'pypi',
                            'purl': f'pkg:pypi/{name}@{clean_version}'
                        })

            return components
        except Exception as e:
            print(f"❌ Error parsing {path}: {e}")
            return []

    @staticmethod
    def parse_go_mod(path: str) -> List[Dict]:
        """Parse Go go.mod"""
        try:
            components = []

            with open(path, 'r', encoding='utf-8') as f:
                in_require = False
                for line in f:
                    line = line.strip()

                    if line == 'require (':
                        in_require = True
                        continue
                    elif line == ')' and in_require:
                        in_require = False
                        continue

                    if in_require or (line.startswith('require ') and not line.endswith('(')):
                        # Parse: require github.com/user/pkg v1.2.3
                        match = re.match(r'^require\s+([^\s]+)\s+([^\s]+)', line)
                        if not match:
                            match = re.match(r'^([^\s]+)\s+([^\s]+)', line)

                        if match:
                            name, version = match.groups()
                            clean_version = version.lstrip('v')
                            components.append({
                                'name': name,
                                'version': clean_version,
                                'ecosystem': 'golang',
                                'purl': f'pkg:golang/{name}@{clean_version}'
                            })

            return components
        except Exception as e:
            print(f"❌ Error parsing {path}: {e}")
            return []

    @staticmethod
    def parse_pom_xml(path: str) -> List[Dict]:
        """Parse Maven pom.xml"""
        try:
            components = []
            tree = ET.parse(path)
            root = tree.getroot()

            # Define namespace
            ns = {'mvn': 'http://maven.apache.org/POM/4.0.0'}

            # Find all dependencies
            for dep in root.findall('.//mvn:dependency', ns):
                group_id_elem = dep.find('mvn:groupId', ns)
                artifact_id_elem = dep.find('mvn:artifactId', ns)
                version_elem = dep.find('mvn:version', ns)

                if artifact_id_elem is not None and version_elem is not None:
                    group_id = group_id_elem.text if group_id_elem is not None else 'unknown'
                    artifact_id = artifact_id_elem.text
                    version = version_elem.text

                    # Format Maven name as group:artifact
                    name = f'{group_id}:{artifact_id}'
                    components.append({
                        'name': name,
                        'version': version,
                        'ecosystem': 'maven',
                        'purl': f'pkg:maven/{group_id}/{artifact_id}@{version}'
                    })

            return components
        except Exception as e:
            print(f"❌ Error parsing {path}: {e}")
            return []

    @staticmethod
    def parse_manifest(manifest_path: str) -> Tuple[str, List[Dict]]:
        """
        Auto-detect and parse a manifest file.

        Returns:
            Tuple of (ecosystem, components)
        """
        filename = os.path.basename(manifest_path)
        ecosystem = None

        if filename == 'package.json':
            return 'npm', DependencyParser.parse_package_json(manifest_path)
        elif filename in ['requirements.txt', 'Pipfile']:
            return 'pypi', DependencyParser.parse_requirements_txt(manifest_path)
        elif filename == 'go.mod':
            return 'golang', DependencyParser.parse_go_mod(manifest_path)
        elif filename == 'pom.xml':
            return 'maven', DependencyParser.parse_pom_xml(manifest_path)
        else:
            return None, []


class SBOMGenerator:
    """Generate CycloneDX SBOM from dependency lists"""

    @staticmethod
    def generate_sbom(components: List[Dict], metadata: Optional[Dict] = None) -> Dict:
        """
        Generate CycloneDX 1.4 compliant SBOM.

        Args:
            components: List of component dictionaries with name, version, ecosystem
            metadata: Optional metadata (name, version, description)

        Returns:
            SBOM as dictionary
        """
        if metadata is None:
            metadata = {}

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": metadata.get("timestamp", ""),
                "tools": [{"name": "PRISM-Scanner"}],
                "component": {
                    "bom-ref": "application",
                    "type": "application",
                    "name": metadata.get("name", "scanned-application"),
                    "version": metadata.get("version", "1.0.0"),
                    "description": metadata.get("description", "Application scanned by PRISM")
                }
            },
            "components": []
        }

        for comp in components:
            sbom_comp = {
                "type": "library",
                "bom-ref": f"{comp['name']}@{comp['version']}",
                "name": comp['name'],
                "version": comp['version'],
                "purl": comp.get('purl', ''),
            }
            sbom["components"].append(sbom_comp)

        return sbom

    @staticmethod
    def save_sbom(sbom: Dict, output_path: str) -> None:
        """Save SBOM to JSON file"""
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sbom, f, indent=2)
        print(f"✅ SBOM saved to: {output_path}")


class MultiLanguageScanner:
    """Orchestrate scanning for multiple languages"""

    @staticmethod
    def scan_directory(directory: str, output_dir: str = "output/sboms") -> Dict[str, str]:
        """
        Scan a directory for all manifest files and generate SBOMs.

        Args:
            directory: Root directory to scan
            output_dir: Directory to save generated SBOMs

        Returns:
            Dict mapping ecosystem to generated SBOM file path
        """
        results = {}

        # Detect manifests
        print(f"\n🔍 Scanning {directory} for dependency manifests...\n")
        manifests = ManifestDetector.detect_manifests(directory)

        if not manifests:
            print("❌ No manifest files found!")
            return results

        # Process each manifest
        for ecosystem, files in manifests.items():
            print(f"📦 Found {len(files)} {ecosystem} manifest(s)")

            for manifest_path in files:
                print(f"   └─ {manifest_path}")

                detected_ecosystem, components = DependencyParser.parse_manifest(manifest_path)

                if components:
                    print(f"      ✅ Extracted {len(components)} dependencies")

                    # Generate SBOM
                    sbom = SBOMGenerator.generate_sbom(
                        components,
                        metadata={
                            "name": f"app-{ecosystem}",
                            "version": "1.0.0",
                            "description": f"{ecosystem.upper()} application"
                        }
                    )

                    # Save SBOM
                    sbom_filename = f"sbom_{ecosystem}_{os.path.basename(manifest_path).replace('.', '_')}.json"
                    sbom_path = os.path.join(output_dir, sbom_filename)
                    SBOMGenerator.save_sbom(sbom, sbom_path)

                    results[ecosystem] = sbom_path
                else:
                    print(f"      ❌ No dependencies found or error parsing")

        return results
