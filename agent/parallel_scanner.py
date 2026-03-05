"""
Parallel vulnerability scanner for PRISM
Enables concurrent scanning of multiple components for improved performance
"""

import concurrent.futures
from typing import List, Dict, Any, Callable
from tqdm import tqdm


class ParallelScanner:
    """Parallel scanner for vulnerability queries"""

    def __init__(self, max_workers: int = 5):
        """
        Initialize parallel scanner

        Args:
            max_workers: Maximum number of concurrent workers (default: 5)
        """
        self.max_workers = max_workers

    def scan_components(
        self,
        components: List[Dict],
        scanner_func: Callable,
        show_progress: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple components in parallel

        Args:
            components: List of component dicts with 'name', 'version', 'ecosystem'
            scanner_func: Function to call for each component (e.g., query_osv)
            show_progress: Whether to show progress bar

        Returns:
            Dictionary mapping component keys to vulnerability lists
        """
        results = {}
        errors = []

        def scan_single_component(comp):
            """Scan a single component"""
            try:
                name = comp.get("name")
                version = comp.get("version")
                ecosystem = comp.get("ecosystem")

                # Call the scanner function
                vulns = scanner_func(name, version, ecosystem)

                # Create unique key for this component
                key = f"{name}@{version}"

                return (key, vulns, None)

            except Exception as e:
                return (None, None, f"{comp.get('name')}: {str(e)}")

        # Use ThreadPoolExecutor for I/O-bound tasks (API calls)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            futures = [executor.submit(scan_single_component, comp) for comp in components]

            # Collect results with optional progress bar
            iterator = concurrent.futures.as_completed(futures)
            if show_progress:
                iterator = tqdm(iterator, total=len(components), desc="🔍 Scanning components", unit="pkg")

            for future in iterator:
                try:
                    key, vulns, error = future.result()

                    if error:
                        errors.append(error)
                    elif key:
                        results[key] = vulns

                except Exception as e:
                    errors.append(f"Future error: {str(e)}")

        # Print errors if any
        if errors:
            print(f"\n⚠️  {len(errors)} component(s) failed to scan:")
            for error in errors[:5]:  # Show first 5 errors
                print(f"   - {error}")
            if len(errors) > 5:
                print(f"   ... and {len(errors) - 5} more")

        return results

    def scan_with_aggregation(
        self,
        components: List[Dict],
        scanner_func: Callable,
        show_progress: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Scan components and aggregate vulnerabilities into finding objects

        Args:
            components: List of component dicts
            scanner_func: Scanner function
            show_progress: Show progress bar

        Returns:
            List of finding dicts with component info and vulnerabilities
        """
        scan_results = self.scan_components(components, scanner_func, show_progress)

        findings = []
        for comp in components:
            key = f"{comp.get('name')}@{comp.get('version')}"
            vulns = scan_results.get(key, [])

            if vulns:  # Only include components with vulnerabilities
                findings.append({
                    "component": comp,
                    "vulnerabilities": vulns,
                    "vulnerability_count": len(vulns)
                })

        return findings
