"""Integration tests for presets and maintenance mode.

These tests demonstrate the full feature flow without requiring a database.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import dns.message
import dns.rcode

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.cache import ProfileConfigCache
from filterdns.db.models import ProfileConfig
from filterdns.dns.filter import DNSFilter


def make_query(domain: str, rdtype: str = "A") -> dns.message.Message:
    """Create a DNS query message for testing."""
    return dns.message.make_query(domain, rdtype)


class MockResolver:
    """Mock DNS resolver for testing."""

    async def resolve(self, query):
        from filterdns.dns.resolver import ResolveResult

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)
        return ResolveResult(
            response=response,
            upstream="8.8.8.8",
            response_time_ms=10,
        )


class TestFullProfileFlow:
    """Test the complete preset filtering flow."""

    @pytest.fixture
    def setup(self):
        """Set up test fixtures."""
        engine = BlocklistEngine()

        # Set up built-in presets
        engine.set_blocklist(
            "preset_windows-updates",
            {
                "windowsupdate.com",
                "update.microsoft.com",
                "download.microsoft.com",
            },
        )
        engine.set_blocklist(
            "preset_playstation-updates",
            {
                "playstation.net",
                "playstation.com",
                "dl.playstation.net",
            },
        )
        engine.set_blocklist(
            "preset_samsung-tv",
            {
                "samsungads.com",
                "samsungacr.com",
            },
        )

        # Set up regular blocklists
        engine.set_blocklist(
            "hagezi-multi-normal",
            {
                "ads.example.com",
                "tracker.example.com",
                "malware.example.com",
            },
        )

        cache = ProfileConfigCache(ttl_seconds=30)
        dns_filter = DNSFilter(engine=engine, cache=cache, resolver=MockResolver())

        return engine, cache, dns_filter

    @pytest.mark.asyncio
    async def test_profile_blocks_windows_updates(self, setup):
        """Test that enabling windows-updates preset blocks Windows Update domains."""
        engine, cache, dns_filter = setup

        # Profile with windows-updates preset enabled
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="exhibition-kiosk",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["hagezi-multi-normal"],
            active_preset_ids=["windows-updates"],
        )

        # Windows Update should be blocked
        query = make_query("windowsupdate.com")
        # Simulate cached config
        cache.set(str(config.profile_id), config, 1, 1)

        # Test that preset blocks Windows Update
        result = await dns_filter._apply_filter_rules(
            "windowsupdate.com", config, type("Logger", (), {"debug": lambda *a, **k: None})()
        )
        assert result.allowed is False
        assert result.reason == "preset"
        assert result.blocklist_id == "preset_windows-updates"

        # Subdomains should also be blocked
        result = await dns_filter._apply_filter_rules(
            "download.windowsupdate.com", config, type("Logger", (), {"debug": lambda *a, **k: None})()
        )
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_multiple_profiles(self, setup):
        """Test profile with multiple presets enabled."""
        engine, cache, dns_filter = setup

        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="smart-tv-demo",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["playstation-updates", "samsung-tv"],
        )

        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # PlayStation domains blocked
        result = await dns_filter._apply_filter_rules("playstation.com", config, logger)
        assert result.allowed is False
        assert "playstation" in result.blocklist_id

        # Samsung TV domains blocked
        result = await dns_filter._apply_filter_rules("samsungads.com", config, logger)
        assert result.allowed is False
        assert "samsung" in result.blocklist_id

        # Regular domains allowed
        result = await dns_filter._apply_filter_rules("google.com", config, logger)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_allow_rule_overrides_profile(self, setup):
        """Test that explicit allow rules override preset blocks."""
        engine, cache, dns_filter = setup

        # Exhibition that needs Windows Update for one specific machine
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="special-kiosk",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={"windowsupdate.com"},  # Explicitly allow
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["windows-updates"],
        )

        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Allow rule should win
        result = await dns_filter._apply_filter_rules("windowsupdate.com", config, logger)
        assert result.allowed is True
        assert result.reason == "allow_rule"


class TestMaintenanceModeFlow:
    """Test the complete maintenance mode flow."""

    @pytest.fixture
    def setup(self):
        """Set up test fixtures."""
        engine = BlocklistEngine()
        engine.set_blocklist("test-blocklist", {"blocked.com"})
        cache = ProfileConfigCache(ttl_seconds=30)
        dns_filter = DNSFilter(engine=engine, cache=cache, resolver=MockResolver())
        return engine, cache, dns_filter

    @pytest.mark.asyncio
    async def test_maintenance_mode_blocks_everything(self, setup):
        """Test that maintenance mode blocks all DNS except allowlist."""
        engine, cache, dns_filter = setup

        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="maintenance-profile",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist=set(),  # Empty allowlist
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["test-blocklist"],
            active_preset_ids=[],
        )

        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Everything should be blocked
        for domain in ["google.com", "microsoft.com", "apple.com", "example.org"]:
            result = await dns_filter._apply_filter_rules(domain, config, logger)
            assert result.allowed is False
            assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_maintenance_allowlist_works(self, setup):
        """Test that maintenance allowlist permits specific domains."""
        engine, cache, dns_filter = setup

        # Typical maintenance scenario - allow NTP and package repos
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="maintenance-profile",
            config_version=1,
            maintenance_mode=True,
            maintenance_allowlist={
                "time.windows.com",
                "ntp.ubuntu.com",
                "archive.ubuntu.com",
            },
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Allowed domains
        result = await dns_filter._apply_filter_rules("time.windows.com", config, logger)
        assert result.allowed is True
        assert result.reason == "maintenance_allowlist"

        result = await dns_filter._apply_filter_rules("ntp.ubuntu.com", config, logger)
        assert result.allowed is True

        # Subdomains of allowed domains
        result = await dns_filter._apply_filter_rules("de.archive.ubuntu.com", config, logger)
        assert result.allowed is True

        # Everything else blocked
        result = await dns_filter._apply_filter_rules("google.com", config, logger)
        assert result.allowed is False
        assert result.reason == "maintenance_mode"

    @pytest.mark.asyncio
    async def test_disable_maintenance_restores_filtering(self, setup):
        """Test that disabling maintenance mode restores normal filtering."""
        engine, cache, dns_filter = setup

        # Normal operation (maintenance off)
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="normal-profile",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist={"time.windows.com"},  # Should be ignored
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=["test-blocklist"],
            active_preset_ids=[],
        )

        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Google should be allowed (not in blocklist)
        result = await dns_filter._apply_filter_rules("google.com", config, logger)
        assert result.allowed is True

        # Blocked.com should be blocked (in blocklist)
        result = await dns_filter._apply_filter_rules("blocked.com", config, logger)
        assert result.allowed is False
        assert result.reason == "blocklist"


class TestExhibitionScenario:
    """Test a realistic exhibition/kiosk scenario."""

    @pytest.mark.asyncio
    async def test_full_exhibition_setup(self):
        """Test a complete exhibition setup with multiple filtering layers."""
        engine = BlocklistEngine()

        # Load presets
        engine.set_blocklist(
            "preset_windows-updates",
            {"windowsupdate.com", "update.microsoft.com"},
        )
        engine.set_blocklist(
            "preset_samsung-tv",
            {"samsungads.com", "samsungacr.com"},
        )

        # Load ad blocklist
        engine.set_blocklist(
            "ads-blocklist",
            {"ads.doubleclick.net", "googleadservices.com"},
        )

        cache = ProfileConfigCache(ttl_seconds=30)
        dns_filter = DNSFilter(engine=engine, cache=cache, resolver=MockResolver())
        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Exhibition kiosk config:
        # - Block Windows updates (don't want kiosk updating mid-exhibition)
        # - Block Samsung TV telemetry (privacy)
        # - Allow specific exhibition domains
        # - Use standard ad blocklist
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="exhibition-kiosk-1",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules={
                "internal.example.com",  # Custom internal content
                "api.internal.example.com",  # Internal API
            },
            deny_rules={
                "facebook.com",  # Specifically block social media
            },
            active_blocklist_ids=["ads-blocklist"],
            active_preset_ids=["windows-updates", "samsung-tv"],
        )

        # Test internal domain allowed
        result = await dns_filter._apply_filter_rules(
            "internal.example.com", config, logger
        )
        assert result.allowed is True
        assert result.reason == "allow_rule"

        # Test Windows Update blocked by preset
        result = await dns_filter._apply_filter_rules(
            "windowsupdate.com", config, logger
        )
        assert result.allowed is False
        assert result.reason == "preset"

        # Test Samsung telemetry blocked by preset
        result = await dns_filter._apply_filter_rules(
            "samsungads.com", config, logger
        )
        assert result.allowed is False
        assert result.reason == "preset"

        # Test ads blocked by blocklist
        result = await dns_filter._apply_filter_rules(
            "ads.doubleclick.net", config, logger
        )
        assert result.allowed is False
        assert result.reason == "blocklist"

        # Test social media blocked by deny rule
        result = await dns_filter._apply_filter_rules(
            "facebook.com", config, logger
        )
        assert result.allowed is False
        assert result.reason == "deny_rule"

        # Test regular domains allowed
        result = await dns_filter._apply_filter_rules(
            "wikipedia.org", config, logger
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_maintenance_window(self):
        """Test maintenance mode for overnight updates."""
        engine = BlocklistEngine()
        engine.set_blocklist(
            "preset_windows-updates",
            {"windowsupdate.com", "update.microsoft.com"},
        )

        cache = ProfileConfigCache(ttl_seconds=30)
        dns_filter = DNSFilter(engine=engine, cache=cache, resolver=MockResolver())
        logger = type("Logger", (), {"debug": lambda *a, **k: None})()

        # Maintenance mode config (e.g., overnight between exhibitions)
        config = ProfileConfig(
            profile_id=uuid4(),
            profile_name="exhibition-kiosk-1",
            config_version=2,  # Version bumped when entering maintenance
            maintenance_mode=True,
            maintenance_allowlist={
                "windowsupdate.com",  # Allow updates during maintenance
                "update.microsoft.com",
                "time.windows.com",  # NTP
            },
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["windows-updates"],  # Still configured but maintenance overrides
        )

        # Windows Update now allowed (in maintenance allowlist)
        result = await dns_filter._apply_filter_rules(
            "windowsupdate.com", config, logger
        )
        assert result.allowed is True
        assert result.reason == "maintenance_allowlist"

        # But random internet blocked
        result = await dns_filter._apply_filter_rules(
            "youtube.com", config, logger
        )
        assert result.allowed is False
        assert result.reason == "maintenance_mode"


class TestCacheIntegration:
    """Test cache behavior with presets and maintenance."""

    @pytest.mark.asyncio
    async def test_cache_invalidation_on_profile_change(self):
        """Test that cache properly invalidates when presets change."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"blocked.com"})

        cache = ProfileConfigCache(ttl_seconds=30)
        profile_id = uuid4()

        # Initial config without preset
        config_v1 = ProfileConfig(
            profile_id=profile_id,
            profile_name="test",
            config_version=1,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=[],
        )

        # Cache it with version 1
        cache.set(str(profile_id), config_v1, profile_version=1, global_version=1)

        # Retrieve with version 1 - should hit
        cached = cache.get(str(profile_id), 1, 1)
        assert cached is not None
        assert cached.active_preset_ids == []

        # "Preset added" - version bumped to 2
        config_v2 = ProfileConfig(
            profile_id=profile_id,
            profile_name="test",
            config_version=2,
            maintenance_mode=False,
            maintenance_allowlist=set(),
            allow_rules=set(),
            deny_rules=set(),
            active_blocklist_ids=[],
            active_preset_ids=["test"],  # Preset now added
        )

        # Old version should miss
        cached = cache.get(str(profile_id), 2, 1)
        assert cached is None  # Cache miss - version mismatch

        # Store new config
        cache.set(str(profile_id), config_v2, profile_version=2, global_version=1)

        # New version should hit
        cached = cache.get(str(profile_id), 2, 1)
        assert cached is not None
        assert cached.active_preset_ids == ["test"]
