"""DNS filtering logic for FilterDNS."""

import time
from typing import NamedTuple
from uuid import UUID

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import structlog

from filterdns.blocklist.engine import BlocklistEngine, get_engine
from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import Client
from filterdns.dns.resolver import DNSResolver, get_resolver

logger = structlog.get_logger()


class FilterResult(NamedTuple):
    """Result of DNS filtering."""

    response: dns.message.Message
    blocked: bool
    blocklist_id: str | None
    response_time_ms: int


class DNSFilter:
    """DNS filter that applies per-client filtering rules."""

    def __init__(
        self,
        engine: BlocklistEngine | None = None,
        resolver: DNSResolver | None = None,
    ):
        self.engine = engine or get_engine()
        self.resolver = resolver or get_resolver()

    async def filter_query(
        self,
        query: dns.message.Message,
        client: Client | None = None,
    ) -> FilterResult:
        """Filter a DNS query based on client configuration.

        Args:
            query: DNS query message
            client: Client configuration (None for default behavior)

        Returns:
            FilterResult with response and metadata
        """
        start_time = time.monotonic()

        # Extract query info
        if not query.question:
            return FilterResult(
                response=self._make_error_response(query, dns.rcode.FORMERR),
                blocked=False,
                blocklist_id=None,
                response_time_ms=0,
            )

        question = query.question[0]
        domain = str(question.name).rstrip(".")
        query_type = dns.rdatatype.to_text(question.rdtype)

        log = logger.bind(domain=domain, query_type=query_type)

        # Check if filtering is paused for this client
        if client and client.is_filtering_paused:
            log.debug("Filtering paused for client", client_name=client.name)
            result = await self.resolver.resolve(query)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            # Log the query
            if settings.log_queries and settings.log_allowed:
                await self._log_query(client, domain, query_type, False, None, elapsed_ms)

            return FilterResult(
                response=result.response,
                blocked=False,
                blocklist_id=None,
                response_time_ms=elapsed_ms,
            )

        # Get client's custom rules and blocklists
        allow_rules: set[str] = set()
        deny_rules: set[str] = set()
        active_blocklists: set[str] | None = None

        if client:
            allow_rules = await queries.get_client_allow_rules(client.id)
            deny_rules = await queries.get_client_deny_rules(client.id)
            blocklist_ids = await queries.get_client_blocklists(client.id)
            if blocklist_ids:
                active_blocklists = set(blocklist_ids)

        # Check custom allow rules first (highest priority)
        if self._matches_rules(domain, allow_rules):
            log.debug("Domain allowed by custom rule")
            result = await self.resolver.resolve(query)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            if settings.log_queries and settings.log_allowed:
                await self._log_query(client, domain, query_type, False, None, elapsed_ms)

            return FilterResult(
                response=result.response,
                blocked=False,
                blocklist_id=None,
                response_time_ms=elapsed_ms,
            )

        # Check custom deny rules
        if self._matches_rules(domain, deny_rules):
            log.debug("Domain blocked by custom rule")
            response = self._make_blocked_response(query)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            if settings.log_queries:
                await self._log_query(client, domain, query_type, True, "custom-deny", elapsed_ms)

            return FilterResult(
                response=response,
                blocked=True,
                blocklist_id="custom-deny",
                response_time_ms=elapsed_ms,
            )

        # Check blocklists
        block_result = self.engine.is_blocked(domain, active_blocklists)
        if block_result.blocked:
            log.debug("Domain blocked by blocklist", blocklist_id=block_result.blocklist_id)
            response = self._make_blocked_response(query)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            if settings.log_queries:
                await self._log_query(
                    client, domain, query_type, True, block_result.blocklist_id, elapsed_ms
                )

            return FilterResult(
                response=response,
                blocked=True,
                blocklist_id=block_result.blocklist_id,
                response_time_ms=elapsed_ms,
            )

        # Domain not blocked, resolve normally
        result = await self.resolver.resolve(query)
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        if settings.log_queries and settings.log_allowed:
            await self._log_query(client, domain, query_type, False, None, elapsed_ms)

        return FilterResult(
            response=result.response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=elapsed_ms,
        )

    def _matches_rules(self, domain: str, rules: set[str]) -> bool:
        """Check if domain matches any rule.

        Supports exact match and wildcard subdomain matching.

        Args:
            domain: Domain to check
            rules: Set of rules to match against

        Returns:
            True if domain matches any rule
        """
        domain = domain.lower()

        # Exact match
        if domain in rules:
            return True

        # Check parent domains (for wildcard matching)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in rules:
                return True

        return False

    def _make_blocked_response(self, query: dns.message.Message) -> dns.message.Message:
        """Create a blocked response (NXDOMAIN or 0.0.0.0).

        Args:
            query: Original query message

        Returns:
            Blocked response message
        """
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    def _make_error_response(
        self,
        query: dns.message.Message,
        rcode: dns.rcode.Rcode,
    ) -> dns.message.Message:
        """Create an error response message.

        Args:
            query: Original query message
            rcode: Response code to use

        Returns:
            Error response message
        """
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        return response

    async def _log_query(
        self,
        client: Client | None,
        domain: str,
        query_type: str,
        blocked: bool,
        blocklist_id: str | None,
        response_time_ms: int,
    ) -> None:
        """Log a DNS query to the database.

        Args:
            client: Client that made the query
            domain: Queried domain
            query_type: Query type (A, AAAA, etc.)
            blocked: Whether the query was blocked
            blocklist_id: Which blocklist blocked it (if blocked)
            response_time_ms: Response time in milliseconds
        """
        try:
            await queries.log_query(
                client_id=client.id if client else None,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                blocklist_id=blocklist_id,
                response_time_ms=response_time_ms,
            )
        except Exception as e:
            logger.error("Failed to log query", error=str(e))


# Global filter instance
_filter: DNSFilter | None = None


def get_filter() -> DNSFilter:
    """Get the global DNS filter instance."""
    global _filter
    if _filter is None:
        _filter = DNSFilter()
    return _filter
