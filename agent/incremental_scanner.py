"""
Incremental scanner for PRISM
Scans only changed/new components by comparing with previous SBOM
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


class IncrementalScanner:
    """Incremental scanner that only scans changed components"""

    def __init__(self, cache_dir: str = ".prism_cache"):
        """
        Initialize incremental scanner

        Args:
            cache_dir: Directory to store previous SBOM snapshots
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def _get_snapshot_path(self, sbom_identifier: str) -> Path:
        """Get path for SBOM snapshot file"""
        return self.cache_dir / f"sbom_snapshot_{sbom_identifier}.json"

    def _component_key(self, component: Dict[str, Any]) -> str:
        """Generate unique key for a component"""
        name = component.get("name", "")
        version = component.get("version", "")
        return f"{name}@{version}"

    def _extract_components_dict(self, sbom: Dict) -> Dict[str, Dict]:
        """
        Extract components from SBOM as a dictionary

        Args:
            sbom: SBOM dictionary

        Returns:
            Dict mapping component keys to component dicts
        """
        components = {}

        # Handle CycloneDX format
        if "components" in sbom:
            for comp in sbom.get("components", []):
                key = self._component_key(comp)
                components[key] = comp

        return components

    def get_changed_components(
        self,
        current_sbom: Dict,
        sbom_identifier: str = "default"
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Compare current SBOM with previous snapshot

        Args:
            current_sbom: Current SBOM dictionary
            sbom_identifier: Identifier for this SBOM (e.g., repo name, branch)

        Returns:
            Tuple of (new_components, changed_components, unchanged_components)
        """
        snapshot_path = self._get_snapshot_path(sbom_identifier)

        current_comps = self._extract_components_dict(current_sbom)

        # Load previous snapshot if it exists
        if snapshot_path.exists():
            try:
                with open(snapshot_path, 'r', encoding='utf-8') as f:
                    previous_sbom = json.load(f)
                previous_comps = self._extract_components_dict(previous_sbom)
            except Exception as e:
                print(f"[INCREMENTAL] Error loading snapshot: {e}")
                # Treat all as new if snapshot is corrupt
                return list(current_comps.values()), [], []
        else:
            # No previous snapshot - all components are new
            print("[INCREMENTAL] No previous snapshot found - scanning all components")
            return list(current_comps.values()), [], []

        new_components = []
        changed_components = []
        unchanged_components = []

        # Find new and changed components
        for key, comp in current_comps.items():
            if key not in previous_comps:
                new_components.append(comp)
            elif current_comps[key] != previous_comps[key]:
                # Component changed (version upgrade/downgrade or metadata change)
                changed_components.append(comp)
            else:
                unchanged_components.append(comp)

        return new_components, changed_components, unchanged_components

    def save_snapshot(
        self,
        sbom: Dict,
        sbom_identifier: str = "default"
    ) -> bool:
        """
        Save current SBOM as snapshot for future comparisons

        Args:
            sbom: SBOM dictionary to save
            sbom_identifier: Identifier for this SBOM

        Returns:
            True if successful
        """
        snapshot_path = self._get_snapshot_path(sbom_identifier)

        try:
            with open(snapshot_path, 'w', encoding='utf-8') as f:
                json.dump(sbom, f, indent=2)

            print(f"[INCREMENTAL] Snapshot saved: {snapshot_path.name}")
            return True

        except Exception as e:
            print(f"[INCREMENTAL] Error saving snapshot: {e}")
            return False

    def incremental_scan(
        self,
        current_sbom: Dict,
        scanner_func,
        sbom_identifier: str = "default",
        save_after_scan: bool = True
    ) -> Dict[str, Any]:
        """
        Perform incremental scan: only scan changed/new components

        Args:
            current_sbom: Current SBOM dictionary
            scanner_func: Function to scan components
            sbom_identifier: SBOM identifier
            save_after_scan: Whether to save snapshot after scanning

        Returns:
            Scan results with metadata about changes
        """
        # Get changed components
        new_comps, changed_comps, unchanged_comps = self.get_changed_components(
            current_sbom,
            sbom_identifier
        )

        # Components that need scanning
        to_scan = new_comps + changed_comps

        scan_stats = {
            "total_components": len(new_comps) + len(changed_comps) + len(unchanged_comps),
            "new_components": len(new_comps),
            "changed_components": len(changed_comps),
            "unchanged_components": len(unchanged_comps),
            "scanned_components": len(to_scan),
            "skipped_components": len(unchanged_comps)
        }

        print(f"[INCREMENTAL] Scan strategy:")
        print(f"   📊 Total components: {scan_stats['total_components']}")
        print(f"   🆕 New: {scan_stats['new_components']}")
        print(f"   🔄 Changed: {scan_stats['changed_components']}")
        print(f"   ✓  Unchanged (skipped): {scan_stats['unchanged_components']}")

        # Scan only new/changed components
        scan_results = []
        if to_scan:
            print(f"   🔍 Scanning {len(to_scan)} component(s)...")

            for comp in to_scan:
                try:
                    vulns = scanner_func(
                        comp.get("name"),
                        comp.get("version"),
                        comp.get("ecosystem")
                    )

                    if vulns:
                        scan_results.append({
                            "component": comp,
                            "vulnerabilities": vulns
                        })

                except Exception as e:
                    print(f"   ⚠️  Error scanning {comp.get('name')}: {e}")
        else:
            print("   ✓ No components need scanning (all unchanged)")

        # Save snapshot for next time
        if save_after_scan:
            self.save_snapshot(current_sbom, sbom_identifier)

        return {
            "findings": scan_results,
            "stats": scan_stats
        }
