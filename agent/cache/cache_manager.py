"""
Generic cache manager for PRISM
Supports multiple backends: disk, memory, Redis (future)
"""

import os
import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    """Generic cache manager with TTL support"""

    def __init__(self, cache_dir: str = ".prism_cache", ttl_seconds: int = 86400):
        """
        Initialize cache manager

        Args:
            cache_dir: Directory to store cache files
            ttl_seconds: Time-to-live for cache entries (default: 24 hours)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.stats = {
            "hits": 0,
            "misses": 0,
            "writes": 0
        }

    def _get_cache_key(self, namespace: str, key: str) -> str:
        """
        Generate cache key hash

        Args:
            namespace: Namespace for the cache entry (e.g., 'osv', 'github')
            key: Unique key for the entry

        Returns:
            Hashed cache key
        """
        full_key = f"{namespace}:{key}"
        return hashlib.sha256(full_key.encode()).hexdigest()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get file path for cache key"""
        return self.cache_dir / f"{cache_key}.json"

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """
        Retrieve value from cache

        Args:
            namespace: Cache namespace
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        cache_key = self._get_cache_key(namespace, key)
        cache_path = self._get_cache_path(cache_key)

        if not cache_path.exists():
            self.stats["misses"] += 1
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            # Check if expired
            if time.time() > cache_data.get("expires_at", 0):
                cache_path.unlink()  # Delete expired entry
                self.stats["misses"] += 1
                return None

            self.stats["hits"] += 1
            return cache_data.get("value")

        except Exception as e:
            print(f"[CACHE] Error reading cache: {e}")
            self.stats["misses"] += 1
            return None

    def set(self, namespace: str, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Store value in cache

        Args:
            namespace: Cache namespace
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl: Custom TTL in seconds (overrides default)

        Returns:
            True if successful
        """
        cache_key = self._get_cache_key(namespace, key)
        cache_path = self._get_cache_path(cache_key)

        ttl = ttl if ttl is not None else self.ttl_seconds
        expires_at = time.time() + ttl

        cache_data = {
            "value": value,
            "created_at": time.time(),
            "expires_at": expires_at,
            "namespace": namespace,
            "key": key
        }

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)

            self.stats["writes"] += 1
            return True

        except Exception as e:
            print(f"[CACHE] Error writing cache: {e}")
            return False

    def clear(self, namespace: Optional[str] = None) -> int:
        """
        Clear cache entries

        Args:
            namespace: If provided, only clear entries from this namespace

        Returns:
            Number of entries cleared
        """
        cleared = 0

        for cache_file in self.cache_dir.glob("*.json"):
            if namespace:
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)

                    if cache_data.get("namespace") != namespace:
                        continue
                except:
                    pass

            cache_file.unlink()
            cleared += 1

        return cleared

    def get_stats(self) -> dict:
        """
        Get cache statistics

        Returns:
            Dictionary with hit/miss/write counts and hit rate
        """
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            **self.stats,
            "hit_rate_percent": round(hit_rate, 2)
        }

    def cleanup_expired(self) -> int:
        """
        Remove all expired cache entries

        Returns:
            Number of entries removed
        """
        removed = 0
        current_time = time.time()

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)

                if current_time > cache_data.get("expires_at", 0):
                    cache_file.unlink()
                    removed += 1

            except Exception:
                continue

        return removed
