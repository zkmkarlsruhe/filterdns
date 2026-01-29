"""Tests for blocklist parser and engine."""

import pytest

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.blocklist.parser import parse_blocklist, parse_line


class TestBlocklistParserHostsFormat:
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


class TestBlocklistParserAdblockFormat:
    """Tests for adblock format parsing."""

    def test_parse_adblock_with_caret(self):
        """Test parsing adblock format with caret."""
        assert parse_line("||ads.example.com^") == "ads.example.com"
        assert parse_line("||tracker.example.com^$third-party") == "tracker.example.com"

    def test_parse_adblock_without_caret(self):
        """Test parsing adblock format without caret."""
        assert parse_line("||ads.example.com") == "ads.example.com"

    def test_parse_adblock_with_options(self):
        """Test parsing adblock format with options."""
        assert parse_line("||ads.example.com^$important") == "ads.example.com"
        assert parse_line("||tracker.com^$third-party,important") == "tracker.com"

    def test_skip_adblock_exceptions(self):
        """Test skipping adblock exception rules."""
        assert parse_line("@@||example.com^") is None  # Exception rule

    def test_skip_cosmetic_filters(self):
        """Test skipping cosmetic filters."""
        assert parse_line("##.ad-banner") is None
        assert parse_line("example.com##.ad") is None

    def test_skip_element_hiding(self):
        """Test skipping element hiding rules."""
        assert parse_line("example.com#@#.ad-banner") is None


class TestBlocklistParserDomainswildFormat:
    """Tests for domainswild format (OISD style)."""

    def test_parse_wildcard_prefix(self):
        """Test parsing wildcard prefix format."""
        # Many blocklists use *.domain.com format
        assert parse_line("*.ads.example.com") == "ads.example.com"
        assert parse_line("*.tracker.com") == "tracker.com"

    def test_parse_plain_domain(self):
        """Test parsing plain domain format."""
        assert parse_line("ads.example.com") == "ads.example.com"
        assert parse_line("tracker.com") == "tracker.com"


class TestBlocklistParserEdgeCases:
    """Tests for edge cases in blocklist parsing."""

    def test_skip_blank_lines(self):
        """Test skipping blank lines."""
        assert parse_line("") is None
        assert parse_line("   ") is None
        assert parse_line("\t") is None
        assert parse_line("\n") is None

    def test_skip_various_comments(self):
        """Test skipping various comment formats."""
        assert parse_line("# Comment") is None
        assert parse_line("! Adblock comment") is None
        assert parse_line("// Comment") is None
        assert parse_line("; DNS comment") is None

    def test_skip_ip_addresses(self):
        """Test skipping raw IP addresses."""
        assert parse_line("192.168.1.1") is None
        assert parse_line("10.0.0.1") is None

    def test_skip_special_domains(self):
        """Test skipping special domains."""
        assert parse_line("0.0.0.0 localhost") is None
        assert parse_line("127.0.0.1 localhost.localdomain") is None
        assert parse_line("::1 localhost") is None
        assert parse_line("0.0.0.0 0.0.0.0") is None

    def test_strip_inline_comments(self):
        """Test stripping inline comments from hosts format."""
        # Inline comments are stripped before parsing
        assert parse_line("0.0.0.0 ads.example.com # Ad server") == "ads.example.com"
        # Plain domain with inline comment - the space+hash is stripped first
        # Then what remains is "example.com" which is valid
        line = "example.com # Blocked domain"
        assert parse_line(line) == "example.com"

    def test_handle_tabs(self):
        """Test handling tab separators."""
        assert parse_line("0.0.0.0\tads.example.com") == "ads.example.com"
        assert parse_line("127.0.0.1\ttracker.com") == "tracker.com"

    def test_handle_multiple_spaces(self):
        """Test handling multiple spaces."""
        assert parse_line("0.0.0.0   ads.example.com") == "ads.example.com"
        assert parse_line("127.0.0.1    tracker.com") == "tracker.com"

    def test_skip_invalid_domains(self):
        """Test skipping invalid domains."""
        # These should return None or be filtered
        assert parse_line("0.0.0.0 -invalid.com") is None
        assert parse_line("0.0.0.0 .invalid.com") is None


class TestBlocklistParserFullContent:
    """Tests for parsing full blocklist content."""

    def test_parse_mixed_format_blocklist(self):
        """Test parsing blocklist with mixed formats."""
        content = """# Mixed format blocklist
# Hosts format
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com

# Plain domains
malware.example.com

# Adblock format
||adserver.example.com^
||analytics.example.com^

# Comment and empty lines

# More entries
suspicious.example.org
"""
        domains = parse_blocklist(content)
        expected = {
            "ads.example.com",
            "tracker.example.com",
            "malware.example.com",
            "adserver.example.com",
            "analytics.example.com",
            "suspicious.example.org",
        }
        assert domains == expected

    def test_parse_large_blocklist(self):
        """Test parsing a larger blocklist."""
        # Generate a list with many entries
        lines = ["0.0.0.0 domain{}.example.com".format(i) for i in range(1000)]
        content = "\n".join(lines)

        domains = parse_blocklist(content)
        assert len(domains) == 1000
        assert "domain0.example.com" in domains
        assert "domain999.example.com" in domains

    def test_parse_deduplicates(self):
        """Test that parsing deduplicates domains."""
        content = """
0.0.0.0 duplicate.com
0.0.0.0 duplicate.com
127.0.0.1 duplicate.com
||duplicate.com^
duplicate.com
"""
        domains = parse_blocklist(content)
        assert domains == {"duplicate.com"}


class TestBlocklistEngineStats:
    """Tests for blocklist engine statistics."""

    def test_get_total_domains(self):
        """Test getting total domain count."""
        engine = BlocklistEngine()
        engine.set_blocklist("list1", {"a.com", "b.com", "c.com"})
        engine.set_blocklist("list2", {"d.com", "e.com"})

        assert engine.get_total_domains() == 5

    def test_get_total_domains_deduplicated(self):
        """Test that total domains are deduplicated across lists."""
        engine = BlocklistEngine()
        engine.set_blocklist("list1", {"a.com", "b.com"})
        engine.set_blocklist("list2", {"b.com", "c.com"})  # b.com is duplicate

        # _all_domains deduplicates - only unique domains are counted
        total = engine.get_total_domains()
        assert total == 3  # a.com, b.com, c.com

    def test_get_blocklist_ids(self):
        """Test getting list of blocklist IDs."""
        engine = BlocklistEngine()
        engine.set_blocklist("ads", {"a.com"})
        engine.set_blocklist("malware", {"b.com"})
        engine.set_blocklist("tracking", {"c.com"})

        ids = engine.get_blocklist_ids()
        assert set(ids) == {"ads", "malware", "tracking"}

    def test_clear_all(self):
        """Test clearing all blocklists."""
        engine = BlocklistEngine()
        engine.set_blocklist("test1", {"a.com"})
        engine.set_blocklist("test2", {"b.com"})

        engine.clear()

        assert engine.get_total_domains() == 0
        assert engine.get_blocklist_ids() == []


class TestBlocklistEnginePerformance:
    """Tests for blocklist engine performance characteristics."""

    def test_large_blocklist_lookup(self):
        """Test lookup performance with large blocklist."""
        engine = BlocklistEngine()

        # Create a large set of domains
        domains = {"domain{}.example.com".format(i) for i in range(100000)}
        engine.set_blocklist("large", domains)

        # Lookup should be O(1)
        result = engine.is_blocked("domain50000.example.com")
        assert result.blocked is True

        result = engine.is_blocked("notblocked.example.com")
        assert result.blocked is False

    def test_many_blocklists_lookup(self):
        """Test lookup with many separate blocklists."""
        engine = BlocklistEngine()

        # Create many blocklists
        for i in range(50):
            domains = {"domain{}.list{}.com".format(j, i) for j in range(100)}
            engine.set_blocklist("list{}".format(i), domains)

        # Should still find the domain
        result = engine.is_blocked("domain50.list25.com")
        assert result.blocked is True
        assert result.blocklist_id == "list25"
