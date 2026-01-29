"""Tests for client configuration cache."""

import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from filterdns.cache import ProfileConfigCache, get_config_cache, reset_config_cache
from filterdns.db.models import ProfileConfig


@pytest.fixture
def cache():
    """Create a fresh cache for testing."""
    return ProfileConfigCache(ttl_seconds=30)


@pytest.fixture
def sample_config():
    """Create a sample profile config."""
    return ProfileConfig(
        profile_id=uuid4(),
        profile_name="test-profile",
        config_version=1,
        filtering_paused_until=None,
        maintenance_mode=False,
        maintenance_allowlist=set(),
        allow_rules={"allowed.com"},
        deny_rules={"blocked.com"},
        active_blocklist_ids=["hagezi-multi-normal"],
        active_preset_ids=["windows-updates"],
    )


class TestProfileConfigCache:
    """Tests for ProfileConfigCache."""

    def test_cache_miss_on_empty(self, cache):
        """Test cache miss when cache is empty."""
        result = cache.get("client-1", 1, 1)
        assert result is None

    def test_cache_hit_when_versions_match(self, cache, sample_config):
        """Test cache hit when both versions match."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        result = cache.get(profile_id, profile_version=1, global_version=1)
        assert result is not None
        assert result.profile_name == "test-profile"

    def test_cache_miss_on_profile_version_mismatch(self, cache, sample_config):
        """Test cache miss when client version doesn't match."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        # Client version changed
        result = cache.get(profile_id, profile_version=2, global_version=1)
        assert result is None

    def test_cache_miss_on_global_version_mismatch(self, cache, sample_config):
        """Test cache miss when global version doesn't match."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        # Global version changed
        result = cache.get(profile_id, profile_version=1, global_version=2)
        assert result is None

    def test_cache_miss_on_ttl_expired(self, sample_config):
        """Test cache miss when TTL expires."""
        cache = ProfileConfigCache(ttl_seconds=0)  # Immediate expiration
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        # Wait for TTL to expire
        time.sleep(0.01)

        result = cache.get(profile_id, profile_version=1, global_version=1)
        assert result is None

    def test_cache_invalidate(self, cache, sample_config):
        """Test explicit cache invalidation."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        cache.invalidate(profile_id)

        result = cache.get(profile_id, profile_version=1, global_version=1)
        assert result is None

    def test_cache_clear(self, cache, sample_config):
        """Test clearing all cache entries."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)
        cache.set("other-client", sample_config, profile_version=1, global_version=1)

        cache.clear()

        assert len(cache) == 0

    def test_cache_stats(self, cache, sample_config):
        """Test cache statistics."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        # Hit
        cache.get(profile_id, 1, 1)
        # Miss (wrong version)
        cache.get(profile_id, 2, 1)
        # Miss (not in cache)
        cache.get("nonexistent", 1, 1)

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 2
        assert stats["entries"] == 1

    def test_cache_overwrite(self, cache, sample_config):
        """Test that setting a new value overwrites the old one."""
        profile_id = str(sample_config.profile_id)
        cache.set(profile_id, sample_config, profile_version=1, global_version=1)

        # Create updated config
        updated_config = ProfileConfig(
            profile_id=sample_config.profile_id,
            profile_name="test-profile-updated",
            config_version=2,
            filtering_paused_until=None,
            maintenance_mode=True,
            maintenance_allowlist={"time.windows.com"},
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        cache.set(profile_id, updated_config, profile_version=2, global_version=1)

        # Old version should miss
        result = cache.get(profile_id, 1, 1)
        assert result is None

        # New version should hit
        result = cache.get(profile_id, 2, 1)
        assert result is not None
        assert result.maintenance_mode is True


class TestGlobalCacheInstance:
    """Tests for global cache instance management."""

    def test_get_config_cache_singleton(self):
        """Test that get_config_cache returns singleton."""
        reset_config_cache()
        cache1 = get_config_cache()
        cache2 = get_config_cache()
        assert cache1 is cache2

    def test_reset_config_cache(self):
        """Test that reset creates new instance."""
        cache1 = get_config_cache()
        reset_config_cache()
        cache2 = get_config_cache()
        assert cache1 is not cache2
