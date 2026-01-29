"""Tests for blocklist parser and engine."""

import pytest

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.blocklist.parser import parse_blocklist, parse_line


class TestBlocklistParser:
    """Tests for blocklist parsing."""

    def test_parse_hosts_format(self):
        """Test parsing hosts file format."""
        assert parse_line("0.0.0.0 ads.example.com") == "ads.example.com"
        assert parse_line("127.0.0.1 tracker.example.com") == "tracker.example.com"

    def test_parse_domain_format(self):
        """Test parsing plain domain format."""
        assert parse_line("example.com") == "example.com"
        assert parse_line("sub.example.com") == "sub.example.com"

    def test_parse_adblock_format(self):
        """Test parsing adblock format."""
        assert parse_line("||ads.example.com^") == "ads.example.com"
        assert parse_line("||tracker.example.com") == "tracker.example.com"

    def test_skip_comments(self):
        """Test skipping comments."""
        assert parse_line("# comment") is None
        assert parse_line("! adblock comment") is None
        assert parse_line("") is None
        assert parse_line("   ") is None

    def test_skip_localhost(self):
        """Test skipping localhost entries."""
        assert parse_line("0.0.0.0 localhost") is None
        assert parse_line("127.0.0.1 localhost.localdomain") is None

    def test_parse_full_blocklist(self):
        """Test parsing a full blocklist."""
        content = """# Blocklist
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
# Another comment
127.0.0.1 malware.example.com
example.org
||adblock.example.com^
"""
        domains = parse_blocklist(content)
        assert domains == {
            "ads.example.com",
            "tracker.example.com",
            "malware.example.com",
            "example.org",
            "adblock.example.com",
        }


class TestBlocklistEngine:
    """Tests for blocklist matching engine."""

    def test_block_exact_match(self):
        """Test exact domain matching."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"ads.example.com"})

        result = engine.is_blocked("ads.example.com")
        assert result.blocked is True
        assert result.blocklist_id == "test"

    def test_allow_non_blocked(self):
        """Test allowing non-blocked domains."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"ads.example.com"})

        result = engine.is_blocked("google.com")
        assert result.blocked is False
        assert result.blocklist_id is None

    def test_block_subdomain(self):
        """Test blocking subdomains of blocked parent."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"example.com"})

        result = engine.is_blocked("sub.example.com")
        assert result.blocked is True

        result = engine.is_blocked("deep.sub.example.com")
        assert result.blocked is True

    def test_multiple_blocklists(self):
        """Test with multiple blocklists."""
        engine = BlocklistEngine()
        engine.set_blocklist("ads", {"ads.example.com"})
        engine.set_blocklist("malware", {"malware.example.com"})

        result = engine.is_blocked("ads.example.com")
        assert result.blocked is True
        assert result.blocklist_id == "ads"

        result = engine.is_blocked("malware.example.com")
        assert result.blocked is True
        assert result.blocklist_id == "malware"

    def test_filter_by_active_blocklists(self):
        """Test filtering by active blocklist IDs."""
        engine = BlocklistEngine()
        engine.set_blocklist("ads", {"ads.example.com"})
        engine.set_blocklist("malware", {"malware.example.com"})

        # Only check against "malware" blocklist
        result = engine.is_blocked("ads.example.com", active_blocklist_ids={"malware"})
        assert result.blocked is False

        result = engine.is_blocked("malware.example.com", active_blocklist_ids={"malware"})
        assert result.blocked is True

    def test_remove_blocklist(self):
        """Test removing a blocklist."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"ads.example.com"})

        assert engine.is_blocked("ads.example.com").blocked is True

        engine.remove_blocklist("test")
        assert engine.is_blocked("ads.example.com").blocked is False

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"ads.example.com"})

        result = engine.is_blocked("ADS.EXAMPLE.COM")
        assert result.blocked is True

        result = engine.is_blocked("Ads.Example.Com")
        assert result.blocked is True
