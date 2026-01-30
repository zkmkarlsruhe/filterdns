"""Versioned profile configuration cache for DNS filtering.

Naming convention (museum-focused):
- Profile: DNS filtering configuration (e.g., "ps5-gaming-exhibition")
- Device: Individual machine using a profile (e.g., PS5 in Hall 3)
- Preset: Predefined blocking rule set (e.g., "block-social-media")
"""

import time
from typing import NamedTuple

import structlog

from filterdns.db.models import ProfileConfig

logger = structlog.get_logger()


class CacheEntry(NamedTuple):
    """Cache entry with version tracking."""

    config: ProfileConfig
    profile_version: int
    global_version: int
    timestamp: float


class ProfileConfigCache:
    """In-memory cache for profile configurations with dual-version invalidation.

    Cache entries are only valid if BOTH profile and global versions match,
    and the entry hasn't exceeded its TTL.

    This ensures cache consistency when:
    - Profile-specific changes occur (rules, blocklists, presets, maintenance)
    - Global changes occur (preset domain changes, preset creation/deletion)
    """

    def __init__(self, ttl_seconds: int = 30):
        """Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for cache entries in seconds.
        """
        self._cache: dict[str, CacheEntry] = {}
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    def get(
        self,
        profile_id: str,
        profile_version: int,
        global_version: int,
    ) -> ProfileConfig | None:
        """Get cached config only if BOTH versions match and TTL valid.

        Args:
            profile_id: Profile ID to look up
            profile_version: Expected profile config version
            global_version: Expected global config version

        Returns:
            Cached ProfileConfig if valid, None otherwise
        """
        if profile_id not in self._cache:
            self._misses += 1
            return None

        entry = self._cache[profile_id]

        # Check version match
        if entry.profile_version != profile_version:
            self._misses += 1
            logger.debug(
                "Cache miss: profile version mismatch",
                profile_id=profile_id,
                cached_version=entry.profile_version,
                current_version=profile_version,
            )
            return None

        if entry.global_version != global_version:
            self._misses += 1
            logger.debug(
                "Cache miss: global version mismatch",
                profile_id=profile_id,
                cached_version=entry.global_version,
                current_version=global_version,
            )
            return None

        # Check TTL
        if time.time() - entry.timestamp > self._ttl:
            self._misses += 1
            del self._cache[profile_id]
            logger.debug("Cache miss: TTL expired", profile_id=profile_id)
            return None

        self._hits += 1
        return entry.config

    def set(
        self,
        profile_id: str,
        config: ProfileConfig,
        profile_version: int,
        global_version: int,
    ) -> None:
        """Store a config in the cache with version tracking.

        Args:
            profile_id: Profile ID
            config: Profile configuration to cache
            profile_version: Current profile config version
            global_version: Current global config version
        """
        self._cache[profile_id] = CacheEntry(
            config=config,
            profile_version=profile_version,
            global_version=global_version,
            timestamp=time.time(),
        )
        logger.debug(
            "Cache set",
            profile_id=profile_id,
            profile_version=profile_version,
            global_version=global_version,
        )

    def invalidate(self, profile_id: str) -> None:
        """Explicitly remove a profile from the cache.

        Args:
            profile_id: Profile ID to invalidate
        """
        if profile_id in self._cache:
            del self._cache[profile_id]
            logger.debug("Cache invalidated", profile_id=profile_id)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        logger.info("Cache cleared")

    def cleanup_expired(self) -> int:
        """Remove all expired entries from the cache.

        Called by background cleanup task to prevent unbounded growth
        from profiles that are never accessed after caching.

        Returns:
            Number of entries removed
        """
        now = time.time()
        # Iterate over copy of keys to avoid mutation during iteration
        expired = [
            profile_id
            for profile_id, entry in list(self._cache.items())
            if now - entry.timestamp > self._ttl
        ]
        for profile_id in expired:
            self._cache.pop(profile_id, None)

        if expired:
            logger.debug("Cache cleanup removed expired entries", count=len(expired))

        return len(expired)

    def get_stats(self) -> dict[str, int]:
        """Get cache statistics.

        Returns:
            Dict with hits, misses, entries, and hit_rate
        """
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "entries": len(self._cache),
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0,
        }

    def __len__(self) -> int:
        """Return number of cached entries."""
        return len(self._cache)


# Backwards compatibility alias
ClientConfigCache = ProfileConfigCache


# Global cache instance
_cache: ProfileConfigCache | None = None


def get_config_cache() -> ProfileConfigCache:
    """Get the global config cache instance."""
    global _cache
    if _cache is None:
        _cache = ProfileConfigCache()
    return _cache


def reset_config_cache() -> None:
    """Reset the global config cache (for testing)."""
    global _cache
    _cache = None
