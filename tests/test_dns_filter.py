"""Tests for DNS filter logic."""

import pytest
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.dns.filter import DNSFilter


def make_query(domain: str, rdtype: str = "A") -> dns.message.Message:
    """Create a DNS query message for testing."""
    query = dns.message.make_query(domain, rdtype)
    return query


class TestDNSFilterRuleMatching:
    """Tests for rule matching logic."""

    def test_exact_match(self):
        """Test exact domain matching."""
        filter = DNSFilter(engine=BlocklistEngine())
        rules = {"example.com", "blocked.org"}

        assert filter._matches_rules("example.com", rules) is True
        assert filter._matches_rules("blocked.org", rules) is True
        assert filter._matches_rules("allowed.com", rules) is False

    def test_subdomain_match(self):
        """Test that subdomains of blocked domains are matched."""
        filter = DNSFilter(engine=BlocklistEngine())
        rules = {"example.com"}

        assert filter._matches_rules("sub.example.com", rules) is True
        assert filter._matches_rules("deep.sub.example.com", rules) is True
        assert filter._matches_rules("example.com", rules) is True

    def test_different_tld_not_matched(self):
        """Test that different TLDs are not matched."""
        filter = DNSFilter(engine=BlocklistEngine())
        rules = {"example.com"}

        assert filter._matches_rules("example.org", rules) is False
        assert filter._matches_rules("example.net", rules) is False

    def test_partial_match_not_blocked(self):
        """Test that partial domain matches don't block."""
        filter = DNSFilter(engine=BlocklistEngine())
        rules = {"ads.com"}

        # "goodads.com" should NOT be blocked just because it ends with "ads.com"
        assert filter._matches_rules("goodads.com", rules) is False
        assert filter._matches_rules("myads.com", rules) is False
        # But actual subdomains should be blocked
        assert filter._matches_rules("sub.ads.com", rules) is True

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        filter = DNSFilter(engine=BlocklistEngine())
        # Rules should be stored lowercase (normalized)
        rules = {"example.com"}

        # Domain lookup is case-insensitive
        assert filter._matches_rules("example.com", rules) is True
        assert filter._matches_rules("EXAMPLE.COM", rules) is True
        assert filter._matches_rules("Example.Com", rules) is True


class TestDNSFilterBlockedResponse:
    """Tests for blocked response generation."""

    def test_blocked_response_nxdomain(self):
        """Test that blocked responses return NXDOMAIN."""
        filter = DNSFilter(engine=BlocklistEngine())
        query = make_query("blocked.example.com")

        response = filter._make_blocked_response(query)

        assert response.rcode() == dns.rcode.NXDOMAIN
        # Response should echo the question
        assert len(response.question) == 1
        assert str(response.question[0].name) == "blocked.example.com."

    def test_error_response_formerr(self):
        """Test FORMERR response for malformed queries."""
        filter = DNSFilter(engine=BlocklistEngine())
        query = make_query("example.com")

        response = filter._make_error_response(query, dns.rcode.FORMERR)

        assert response.rcode() == dns.rcode.FORMERR

    def test_error_response_servfail(self):
        """Test SERVFAIL response."""
        filter = DNSFilter(engine=BlocklistEngine())
        query = make_query("example.com")

        response = filter._make_error_response(query, dns.rcode.SERVFAIL)

        assert response.rcode() == dns.rcode.SERVFAIL


class TestDNSFilterIntegration:
    """Integration tests for DNS filtering."""

    @pytest.mark.asyncio
    async def test_filter_blocked_domain(self):
        """Test filtering a blocked domain."""
        engine = BlocklistEngine()
        engine.set_blocklist("test-ads", {"ads.example.com", "tracker.example.com"})

        filter = DNSFilter(engine=engine)
        query = make_query("ads.example.com")

        # Mock resolver to avoid actual DNS lookups
        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                return ResolveResult(
                    response=dns.message.make_response(query),
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is True
        assert result.blocklist_id == "test-ads"
        assert result.response.rcode() == dns.rcode.NXDOMAIN

    @pytest.mark.asyncio
    async def test_filter_allowed_domain(self):
        """Test filtering an allowed domain."""
        engine = BlocklistEngine()
        engine.set_blocklist("test-ads", {"ads.example.com"})

        filter = DNSFilter(engine=engine)
        query = make_query("google.com")

        # Mock resolver
        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NOERROR)
                return ResolveResult(
                    response=response,
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is False
        assert result.blocklist_id is None
        assert result.response.rcode() == dns.rcode.NOERROR

    @pytest.mark.asyncio
    async def test_filter_subdomain_blocked(self):
        """Test that subdomains of blocked domains are also blocked."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"example.com"})

        filter = DNSFilter(engine=engine)

        # Mock resolver
        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                return ResolveResult(
                    response=dns.message.make_response(query),
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        # Test subdomain
        query = make_query("deep.sub.example.com")
        result = await filter.filter_query(query, profile=None)

        assert result.blocked is True

    @pytest.mark.asyncio
    async def test_filter_empty_query(self):
        """Test handling of empty query."""
        filter = DNSFilter(engine=BlocklistEngine())

        # Create a query with no questions
        query = dns.message.Message()
        query.id = 12345

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is False
        assert result.response.rcode() == dns.rcode.FORMERR


class TestDNSFilterQueryTypes:
    """Tests for different DNS query types."""

    @pytest.mark.asyncio
    async def test_filter_aaaa_query(self):
        """Test filtering AAAA (IPv6) queries."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"blocked.com"})

        filter = DNSFilter(engine=engine)
        query = make_query("blocked.com", "AAAA")

        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                return ResolveResult(
                    response=dns.message.make_response(query),
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is True

    @pytest.mark.asyncio
    async def test_filter_cname_query(self):
        """Test filtering CNAME queries."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"blocked.com"})

        filter = DNSFilter(engine=engine)
        query = make_query("blocked.com", "CNAME")

        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                return ResolveResult(
                    response=dns.message.make_response(query),
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is True

    @pytest.mark.asyncio
    async def test_filter_mx_query(self):
        """Test filtering MX queries."""
        engine = BlocklistEngine()
        engine.set_blocklist("test", {"blocked.com"})

        filter = DNSFilter(engine=engine)
        query = make_query("blocked.com", "MX")

        class MockResolver:
            async def resolve(self, query):
                from filterdns.dns.resolver import ResolveResult
                return ResolveResult(
                    response=dns.message.make_response(query),
                    upstream="8.8.8.8",
                    response_time_ms=10,
                )

        filter.resolver = MockResolver()

        result = await filter.filter_query(query, profile=None)

        assert result.blocked is True
