"""
OSV API cache wrapper
Caches OSV vulnerability query results to reduce API calls
"""

from typing import List, Dict, Any
from .cache_manager import CacheManager


class OSVCache:
    """Cache layer for OSV vulnerability queries"""

    def __init__(self, cache_manager: CacheManager):
        """
        Initialize OSV cache

        Args:
            cache_manager: CacheManager instance
        """
        self.cache = cache_manager
        self.namespace = "osv"

    def _generate_key(self, package_name: str, version: str, ecosystem: str = None) -> str:
        """
        Generate cache key for OSV query

        Args:
            package_name: Package name
            version: Package version
            ecosystem: Package ecosystem (npm, pypi, etc.)

        Returns:
            Cache key string
        """
        ecosystem_str = ecosystem or "unknown"
        return f"{ecosystem_str}:{package_name}:{version}"

    def get(self, package_name: str, version: str, ecosystem: str = None) -> List[Dict[str, Any]]:
        """
        Retrieve cached OSV results

        Args:
            package_name: Package name
            version: Package version
            ecosystem: Package ecosystem

        Returns:
            List of vulnerabilities or None if not cached
        """
        key = self._generate_key(package_name, version, ecosystem)
        return self.cache.get(self.namespace, key)

    def set(self, package_name: str, version: str, vulnerabilities: List[Dict[str, Any]],
            ecosystem: str = None) -> bool:
        """
        Cache OSV results

        Args:
            package_name: Package name
            version: Package version
            vulnerabilities: List of vulnerability dicts
            ecosystem: Package ecosystem

        Returns:
            True if cached successfully
        """
        key = self._generate_key(package_name, version, ecosystem)
        return self.cache.set(self.namespace, key, vulnerabilities)

    def clear(self) -> int:
        """
        Clear all OSV cache entries

        Returns:
            Number of entries cleared
        """
        return self.cache.clear(self.namespace)
