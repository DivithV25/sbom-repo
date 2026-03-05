"""
Dashboard data aggregator for PRISM
Aggregates scan results into dashboard-ready metrics
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict


class DashboardAggregator:
    """Aggregate scan results for dashboard visualization"""

    def __init__(self, data_dir: str = "dashboard_data"):
        """
        Initialize dashboard aggregator

        Args:
            data_dir: Directory to store dashboard data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.history_file = self.data_dir / "scan_history.json"

    def log_scan_result(
        self,
        scan_result: Dict[str, Any],
        branch: str = "main",
        commit_sha: str = None
    ) -> None:
        """
        Log a scan result to history

        Args:
            scan_result: Scan result dictionary
            branch: Git branch name
            commit_sha: Git commit SHA
        """
        # Load existing history
        history = self._load_history()

        # Create new entry
        entry = {
            "timestamp": datetime.now().isoformat(),
            "branch": branch,
            "commit_sha": commit_sha,
            "total_components": scan_result.get('total_components', 0),
            "total_vulnerabilities": scan_result.get('total_vulnerabilities', 0),
            "max_cvss": scan_result.get('max_cvss', 0),
            "overall_severity": scan_result.get('overall_severity', 'UNKNOWN'),
            "risk_score": scan_result.get('risk_score', 0),
            "policy_decision": scan_result.get('policy_decision', 'UNKNOWN')
        }

        # Append to history
        history.append(entry)

        # Keep only last 100 scans
        if len(history) > 100:
            history = history[-100:]

        # Save history
        self._save_history(history)

    def get_trend_data(self, days: int = 30) -> Dict[str, Any]:
        """
        Get trend data for charts

        Args:
            days: Number of days to include

        Returns:
            Trend data dictionary
        """
        history = self._load_history()

        # Filter by date
        cutoff = datetime.now()
        recent_scans = []
        for entry in history:
            try:
                scan_date = datetime.fromisoformat(entry['timestamp'])
                days_ago = (cutoff - scan_date).days
                if days_ago <= days:
                    recent_scans.append(entry)
            except Exception:
                pass

        # Aggregate data
        timestamps = [scan['timestamp'] for scan in recent_scans]
        vuln_counts = [scan['total_vulnerabilities'] for scan in recent_scans]
        risk_scores = [scan['risk_score'] for scan in recent_scans]
        cvss_scores = [scan['max_cvss'] for scan in recent_scans]

        return {
            "timestamps": timestamps,
            "vulnerability_counts": vuln_counts,
            "risk_scores": risk_scores,
            "cvss_scores": cvss_scores
        }

    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get severity distribution from recent scans

        Returns:
            Dict mapping severity levels to counts
        """
        history = self._load_history()

        distribution = defaultdict(int)
        for scan in history[-30:]:  # Last 30 scans
            severity = scan.get('overall_severity', 'UNKNOWN')
            distribution[severity] += 1

        return dict(distribution)

    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics

        Returns:
            Summary statistics dictionary
        """
        history = self._load_history()

        if not history:
            return {
                "total_scans": 0,
                "avg_vulnerabilities": 0,
                "avg_risk_score": 0,
                "highest_risk_scan": None
            }

        # Calculate stats
        total_scans = len(history)
        avg_vulns = sum(s['total_vulnerabilities'] for s in history) / total_scans
        avg_risk = sum(s['risk_score'] for s in history) / total_scans

        # Find highest risk scan
        highest_risk = max(history, key=lambda x: x.get('risk_score', 0))

        return {
            "total_scans": total_scans,
            "avg_vulnerabilities": round(avg_vulns, 2),
            "avg_risk_score": round(avg_risk, 2),
            "highest_risk_scan": {
                "timestamp": highest_risk.get('timestamp'),
                "risk_score": highest_risk.get('risk_score'),
                "vulnerabilities": highest_risk.get('total_vulnerabilities')
            }
        }

    def get_component_stats(self, history_data: List[Dict] = None) -> Dict[str, Any]:
        """
        Get component-level statistics

        Args:
            history_data: Optional history data with component details

        Returns:
            Component statistics
        """
        # This would require storing component-level data in history
        # For now, return placeholder
        return {
            "most_vulnerable_packages": [],
            "total_unique_components": 0
        }

    def generate_dashboard_json(self) -> Dict[str, Any]:
        """
        Generate complete dashboard data as JSON

        Returns:
            Complete dashboard data dictionary
        """
        dashboard_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.get_summary_stats(),
            "trends": self.get_trend_data(30),
            "severity_distribution": self.get_severity_distribution(),
            "component_stats": self.get_component_stats()
        }

        # Save to file
        output_file = self.data_dir / "dashboard_data.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dashboard_data, f, indent=2)

        return dashboard_data

    def _load_history(self) -> List[Dict]:
        """Load scan history from file"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[DASHBOARD] Error loading history: {e}")
                return []
        return []

    def _save_history(self, history: List[Dict]) -> None:
        """Save scan history to file"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"[DASHBOARD] Error saving history: {e}")
