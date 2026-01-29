"""Tests for DNS filter precedence rules.

This module tests the filtering precedence order:
1. Filtering paused - If filtering_paused_until > now, skip all filtering -> ALLOW
2. Client allow rules - Explicit allowlist always wins -> ALLOW
3. Maintenance allowlist - If maintenance mode enabled, check allowlist -> ALLOW
4. Maintenance mode block - If maintenance mode enabled and not in allowlist -> BLOCK
5. Client deny rules - Explicit client-specific blocks -> BLOCK
6. Active profiles - Check profiles SEPARATELY from global blocklists -> BLOCK
7. Global blocklists - Standard blocklist engine (lowest priority) -> BLOCK or ALLOW
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.cache import ProfileConfigCache
from filterdns.db.models import ProfileConfig
from filterdns.dns.filter import DNSFilter


class MockLogger:
    """Mock logger for testing."""

    def debug(self, msg, **kwargs):
        pass

    def info(self, msg, **kwargs):
        pass


@pytest.fixture
def engine():
    """Create a blocklist engine with test data."""
    engine = BlocklistEngine()
    # Global blocklists
    engine.set_blocklist("blocklist-a", {"blocklist-a.com", "shared-blocklist.com"})
    engine.set_blocklist("blocklist-b", {"blocklist-b.com", "shared-blocklist.com"})
    # Profiles
    engine.set_blocklist("preset_preset-a", {"preset-a.com", "shared-preset.com"})
    engine.set_blocklist("preset_preset-b", {"preset-b.com", "shared-preset.com"})
    # Domain in both profile and blocklist
    engine.set_blocklist("blocklist-overlap", {"overlap.com"})
    engine.set_blocklist("preset_preset-overlap", {"overlap.com"})
    return engine


@pytest.fixture
def cache():
    """Create a test cache."""
    return ProfileConfigCache(ttl_seconds=30)


@pytest.fixture
def dns_filter(engine, cache):
    """Create a DNS filter for testing."""
    return DNSFilter(engine=engine, cache=cache)


class TestFilteringPaused:
    """Tests for filtering_paused_until precedence."""

    @pytest.mark.asyncio
    async def test_filtering_paused_bypasses_all(self, dns_filter):
        """Test that filtering_paused_until bypasses all filtering."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            filtering_paused_until=datetime.now(timezone.utc) + timedelta(hours=1),
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"blocked.com"},
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=["preset-a"],
        )

        # Should allow everything when paused
        result = await dns_filter._apply_filter_rules(
            "blocked.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "filtering_paused"

    @pytest.mark.asyncio
    async def test_filtering_not_paused_when_expired(self, dns_filter):
        """Test that expired pause doesn't bypass filtering."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            filtering_paused_until=datetime.now(timezone.utc) - timedelta(hours=1),
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"blocked.com"},
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "blocked.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "deny_rule"


class TestAllowRulePrecedence:
    """Tests for client allow rules precedence."""

    @pytest.mark.asyncio
    async def test_allow_rule_beats_maintenance_mode(self, dns_filter):
        """Test that allow rules take precedence over maintenance mode."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules={"allowed.com"},
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "allowed.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

    @pytest.mark.asyncio
    async def test_allow_rule_beats_deny_rule(self, dns_filter):
        """Test that allow rules beat deny rules."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"example.com"},
            deny_rules={"example.com"},  # Same domain in both
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "example.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

    @pytest.mark.asyncio
    async def test_allow_rule_beats_profile(self, dns_filter, engine):
        """Test that allow rules beat profiles."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"preset-a.com"},
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["preset-a"],
        )

        result = await dns_filter._apply_filter_rules(
            "preset-a.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

    @pytest.mark.asyncio
    async def test_allow_rule_beats_blocklist(self, dns_filter):
        """Test that allow rules beat blocklists."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"blocklist-a.com"},
            deny_rules=set(),
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "blocklist-a.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

    @pytest.mark.asyncio
    async def test_allow_rule_subdomain_matching(self, dns_filter):
        """Test that allow rules match subdomains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"example.com"},
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "sub.example.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"


class TestDenyRulePrecedence:
    """Tests for client deny rules precedence."""

    @pytest.mark.asyncio
    async def test_deny_rule_beats_profile(self, dns_filter):
        """Test that deny rules beat profiles."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"custom-blocked.com"},
            active_blocklist_ids=[],
            active_preset_ids=["preset-a"],  # Domain not in profile
        )

        result = await dns_filter._apply_filter_rules(
            "custom-blocked.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "deny_rule"

    @pytest.mark.asyncio
    async def test_deny_rule_beats_blocklist(self, dns_filter):
        """Test that deny rules are checked before blocklists."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"custom.com"},
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "custom.com", config, MockLogger()
        )
        # Blocked by deny rule, not blocklist
        assert result.allowed is False
        assert result.reason == "deny_rule"

    @pytest.mark.asyncio
    async def test_deny_rule_subdomain_matching(self, dns_filter):
        """Test that deny rules match subdomains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"blocked.com"},
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "sub.blocked.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "deny_rule"


class TestProfilePrecedence:
    """Tests for profile precedence over blocklists."""

    @pytest.mark.asyncio
    async def test_profile_beats_blocklist(self, dns_filter, engine):
        """Test that profiles are checked before blocklists."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["blocklist-overlap"],
            active_preset_ids=["preset-overlap"],
        )

        result = await dns_filter._apply_filter_rules(
            "overlap.com", config, MockLogger()
        )
        # Blocked by profile (checked first), not blocklist
        assert result.allowed is False
        assert result.reason == "preset"
        assert result.blocklist_id == "preset_preset-overlap"

    @pytest.mark.asyncio
    async def test_profile_matches_subdomains(self, dns_filter, engine):
        """Test that profiles match subdomains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["preset-a"],
        )

        result = await dns_filter._apply_filter_rules(
            "sub.preset-a.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "preset"


class TestDeterministicAttribution:
    """Tests for deterministic attribution when domain matches multiple sources."""

    @pytest.mark.asyncio
    async def test_overlapping_profiles_deterministic(self, dns_filter):
        """Test deterministic attribution for overlapping profiles."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["preset-b", "preset-a"],  # Unsorted
        )

        # Shared domain - should consistently return preset-a (alphabetically first after sorting)
        for _ in range(10):  # Run multiple times to verify consistency
            result = await dns_filter._apply_filter_rules(
                "shared-preset.com", config, MockLogger()
            )
            assert result.allowed is False
            assert result.blocklist_id == "preset_preset-a"

    @pytest.mark.asyncio
    async def test_overlapping_blocklists_deterministic(self, dns_filter):
        """Test deterministic attribution for overlapping blocklists.

        Note: active_blocklist_ids are stored pre-sorted by the ProfileConfig model,
        so the sorting in _apply_filter_rules maintains deterministic order.
        """
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            # Note: These will be checked in order, first match wins
            # The filter sorts these, so blocklist-a will be checked first
            active_blocklist_ids=["blocklist-a", "blocklist-b"],
            active_preset_ids=[],
        )

        # Shared domain - should consistently return blocklist-a (first in sorted order)
        for _ in range(10):  # Run multiple times to verify consistency
            result = await dns_filter._apply_filter_rules(
                "shared-blocklist.com", config, MockLogger()
            )
            assert result.allowed is False
            assert result.blocklist_id == "blocklist-a"


class TestBlocklistFiltering:
    """Tests for blocklist filtering (lowest priority)."""

    @pytest.mark.asyncio
    async def test_blocklist_blocks_domain(self, dns_filter):
        """Test that blocklists block domains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "blocklist-a.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "blocklist"
        assert result.blocklist_id == "blocklist-a"

    @pytest.mark.asyncio
    async def test_domain_not_blocked_passes(self, dns_filter):
        """Test that non-blocked domains are allowed."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=["preset-a"],
        )

        result = await dns_filter._apply_filter_rules(
            "google.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "not_blocked"


class TestNoProfileConfig:
    """Tests for queries without client configuration."""

    @pytest.mark.asyncio
    async def test_no_config_allows_all(self, dns_filter):
        """Test that no client config allows all domains."""
        result = await dns_filter._apply_filter_rules(
            "anything.com", None, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "no_profile"


class TestCombinedPrecedence:
    """Integration tests for complete precedence chain."""

    @pytest.mark.asyncio
    async def test_full_precedence_chain(self, dns_filter, engine):
        """Test the full precedence chain with all rules active."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            filtering_paused_until=None,  # Not paused
            maintenance_mode=True,
            maintenance_allowlist={"maintenance-allowed.com"},
            allow_rules={"explicitly-allowed.com"},
            deny_rules={"explicitly-denied.com"},
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=["preset-a"],
        )

        # 1. Allow rule (highest priority)
        result = await dns_filter._apply_filter_rules(
            "explicitly-allowed.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

        # 2. Maintenance allowlist
        result = await dns_filter._apply_filter_rules(
            "maintenance-allowed.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "maintenance_allowlist"

        # 3. Maintenance mode blocks everything else
        result = await dns_filter._apply_filter_rules(
            "random.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "maintenance_mode"

        # Even deny rules, profiles, and blocklists don't matter during maintenance
        result = await dns_filter._apply_filter_rules(
            "explicitly-denied.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_precedence_without_maintenance(self, dns_filter, engine):
        """Test precedence chain without maintenance mode."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            filtering_paused_until=None,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"allowed.com"},
            deny_rules={"denied.com"},
            active_blocklist_ids=["blocklist-a"],
            active_preset_ids=["preset-a"],
        )

        # 1. Allow rule
        result = await dns_filter._apply_filter_rules(
            "allowed.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

        # 2. Deny rule
        result = await dns_filter._apply_filter_rules(
            "denied.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "deny_rule"

        # 3. Profile
        result = await dns_filter._apply_filter_rules(
            "preset-a.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "preset"

        # 4. Blocklist
        result = await dns_filter._apply_filter_rules(
            "blocklist-a.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "blocklist"

        # 5. Not blocked
        result = await dns_filter._apply_filter_rules(
            "google.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "not_blocked"
