"""Tests for maintenance mode functionality."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.cache import ProfileConfigCache
from filterdns.db.models import ProfileConfig
from filterdns.dns.filter import DNSFilter, _InternalFilterResult


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
    engine.set_blocklist("test-blocklist", {"blocked.com", "ads.example.com"})
    engine.set_blocklist("preset_windows-updates", {"windowsupdate.com"})
    return engine


@pytest.fixture
def cache():
    """Create a test cache."""
    return ProfileConfigCache(ttl_seconds=30)


@pytest.fixture
def dns_filter(engine, cache):
    """Create a DNS filter for testing."""
    return DNSFilter(engine=engine, cache=cache)


class TestMaintenanceModeFiltering:
    """Tests for maintenance mode in DNS filtering."""

    @pytest.mark.asyncio
    async def test_maintenance_mode_blocks_all(self, dns_filter):
        """Test that maintenance mode blocks all domains not in allowlist."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["test-blocklist"],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "google.com", config, MockLogger()
        )

        assert result.allowed is False
        assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_maintenance_allowlist_allows_domain(self, dns_filter):
        """Test that maintenance allowlist allows specific domains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist={"time.windows.com", "ntp.ubuntu.com"},
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["test-blocklist"],
            active_preset_ids=[],
        )

        # Allowed domain
        result = await dns_filter._apply_filter_rules(
            "time.windows.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "maintenance_allowlist"

        # Not in allowlist
        result = await dns_filter._apply_filter_rules(
            "google.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_maintenance_allowlist_subdomain_matching(self, dns_filter):
        """Test that maintenance allowlist matches subdomains."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist={"ubuntu.com"},
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        # Subdomain should be allowed
        result = await dns_filter._apply_filter_rules(
            "archive.ubuntu.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "maintenance_allowlist"

    @pytest.mark.asyncio
    async def test_allow_rule_beats_maintenance_mode(self, dns_filter):
        """Test that explicit allow rules take precedence over maintenance mode."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules={"special.com"},
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "special.com", config, MockLogger()
        )

        # Allow rule takes precedence
        assert result.allowed is True
        assert result.reason == "allow_rule"

    @pytest.mark.asyncio
    async def test_maintenance_mode_disabled(self, dns_filter):
        """Test normal filtering when maintenance mode is disabled."""
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist={"time.windows.com"},  # Should be ignored
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["test-blocklist"],
            active_preset_ids=[],
        )

        # Domain should be allowed (not in blocklist)
        result = await dns_filter._apply_filter_rules(
            "google.com", config, MockLogger()
        )
        assert result.allowed is True
        assert result.reason == "not_blocked"

        # Domain should be blocked by blocklist
        result = await dns_filter._apply_filter_rules(
            "blocked.com", config, MockLogger()
        )
        assert result.allowed is False
        assert result.blocklist_id == "test-blocklist"


class TestMaintenanceAllowlistMatching:
    """Tests for maintenance allowlist matching."""

    def test_exact_match(self):
        """Test exact domain matching."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        result = dns_filter._matches_maintenance_allowlist(
            "time.windows.com", {"time.windows.com", "ntp.ubuntu.com"}
        )
        assert result is True

    def test_subdomain_match(self):
        """Test subdomain matching."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        result = dns_filter._matches_maintenance_allowlist(
            "sub.example.com", {"example.com"}
        )
        assert result is True

    def test_deep_subdomain_match(self):
        """Test deep subdomain matching."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        result = dns_filter._matches_maintenance_allowlist(
            "deep.sub.example.com", {"example.com"}
        )
        assert result is True

    def test_no_match(self):
        """Test when domain doesn't match."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        result = dns_filter._matches_maintenance_allowlist(
            "other.com", {"example.com"}
        )
        assert result is False

    def test_partial_match_not_allowed(self):
        """Test that partial domain match doesn't allow."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        # "badexample.com" should NOT match "example.com"
        result = dns_filter._matches_maintenance_allowlist(
            "badexample.com", {"example.com"}
        )
        assert result is False

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        dns_filter = DNSFilter(engine=BlocklistEngine())

        result = dns_filter._matches_maintenance_allowlist(
            "TIME.WINDOWS.COM", {"time.windows.com"}
        )
        assert result is True


class TestMaintenanceModeWithOtherRules:
    """Tests for maintenance mode interaction with other filtering rules."""

    @pytest.mark.asyncio
    async def test_filtering_paused_bypasses_maintenance(self):
        """Test that filtering_paused_until bypasses maintenance mode."""
        engine = BlocklistEngine()
        dns_filter = DNSFilter(engine=engine)

        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            filtering_paused_until=datetime.now(timezone.utc) + timedelta(hours=1),
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "any-domain.com", config, MockLogger()
        )

        assert result.allowed is True
        assert result.reason == "filtering_paused"

    @pytest.mark.asyncio
    async def test_deny_rules_not_checked_during_maintenance(self):
        """Test that deny rules are not reached during maintenance mode."""
        engine = BlocklistEngine()
        dns_filter = DNSFilter(engine=engine)

        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules={"blocked.com"},  # Would block normally
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        result = await dns_filter._apply_filter_rules(
            "blocked.com", config, MockLogger()
        )

        # Blocked by maintenance mode, not deny rule
        assert result.allowed is False
        assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_presets_not_checked_during_maintenance(self):
        """Test that presets are not checked during maintenance mode."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"preset-blocked.com"})
        dns_filter = DNSFilter(engine=engine)

        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="test",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["test"],
        )

        result = await dns_filter._apply_filter_rules(
            "preset-blocked.com", config, MockLogger()
        )

        # Blocked by maintenance mode, not preset
        assert result.allowed is False
        assert result.reason == "maintenance_mode"
