"""DNS filtering logic for FilterDNS.

Naming convention (museum-focused):
- Profile: DNS filtering configuration (e.g., "ps5-gaming-exhibition")
- Device: Individual machine using a profile (e.g., PS5 in Hall 3)
- Preset: Predefined blocking rule set (e.g., "block-social-media")
"""

import time
from datetime import datetime, timezone
from typing import NamedTuple
from uuid import UUID

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import structlog

from filterdns.blocklist.engine import BlocklistEngine, get_engine
from filterdns.cache import ProfileConfigCache, get_config_cache
from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import Profile, ProfileConfig
from filterdns.dns.resolver import DNSResolver, get_resolver
from filterdns.profiles.loader import preset_blocklist_id

logger = structlog.get_logger()


class FilterResult(NamedTuple):
    """Result of DNS filtering."""

    response: dns.message.Message
    blocked: bool
    blocklist_id: str | None
    response_time_ms: int


class DNSFilter:
    """DNS filter that applies per-profile filtering rules.

    Precedence Order (highest to lowest):
    1. Filtering paused - If filtering_paused_until > now, skip all filtering -> ALLOW
    2. Profile allow rules - Explicit allowlist always wins -> ALLOW
    3. Maintenance allowlist - If maintenance mode enabled, check allowlist -> ALLOW
    4. Maintenance mode block - If maintenance mode enabled and not in allowlist -> BLOCK
    5. Profile deny rules - Explicit profile-specific blocks -> BLOCK
    6. Active presets - Check presets SEPARATELY from global blocklists -> BLOCK
    7. Global blocklists - Standard blocklist engine (lowest priority) -> BLOCK or ALLOW
    """

    def __init__(
        self,
        engine: BlocklistEngine | None = None,
        resolver: DNSResolver | None = None,
        cache: ProfileConfigCache | None = None,
    ):
        self.engine = engine or get_engine()
        self.resolver = resolver or get_resolver()
        self.cache = cache or get_config_cache()

    async def filter_query(
        self,
        query: dns.message.Message,
        profile: Profile | None = None,
    ) -> FilterResult:
        """Filter a DNS query based on profile configuration.

        Args:
            query: DNS query message
            profile: Profile configuration (None for default behavior)

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

        # Get profile config (with caching if profile is provided)
        config: ProfileConfig | None = None
        if profile:
            config = await self._get_profile_config(profile.id)

        # Apply filtering precedence rules
        filter_result = await self._apply_filter_rules(domain, config, log)

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        if filter_result.allowed:
            # Resolve the query
            result = await self.resolver.resolve(query)

            if settings.log_queries and settings.log_allowed:
                await self._log_query(
                    profile, domain, query_type, False, filter_result.reason, elapsed_ms
                )

            return FilterResult(
                response=result.response,
                blocked=False,
                blocklist_id=None,
                response_time_ms=elapsed_ms,
            )
        else:
            # Block the query
            response = self._make_blocked_response(query)
            log.debug("Domain blocked", reason=filter_result.reason, blocklist_id=filter_result.blocklist_id)

            if settings.log_queries:
                blocklist_for_log = filter_result.blocklist_id or filter_result.reason
                await self._log_query(
                    profile, domain, query_type, True, blocklist_for_log, elapsed_ms
                )

            return FilterResult(
                response=response,
                blocked=True,
                blocklist_id=filter_result.blocklist_id or filter_result.reason,
                response_time_ms=elapsed_ms,
            )

    async def _get_profile_config(self, profile_id: UUID) -> ProfileConfig | None:
        """Get profile configuration, using cache if available.

        Args:
            profile_id: Profile UUID

        Returns:
            ProfileConfig or None if profile not found
        """
        # Check versions for cache validation
        versions = await queries.get_profile_config_versions(profile_id)
        if not versions:
            return None

        profile_version, global_version = versions

        # Try cache first
        cached = self.cache.get(str(profile_id), profile_version, global_version)
        if cached:
            return cached

        # Cache miss - fetch full config
        config = await queries.get_full_profile_config(profile_id)
        if config:
            self.cache.set(str(profile_id), config, profile_version, global_version)

        return config

    async def _apply_filter_rules(
        self,
        domain: str,
        config: ProfileConfig | None,
        log: structlog.BoundLogger,
    ) -> "_InternalFilterResult":
        """Apply filtering rules in precedence order.

        Args:
            domain: Domain being queried
            config: Profile configuration (None for no profile-specific filtering)
            log: Bound logger

        Returns:
            Internal filter result with allowed/blocked and reason
        """
        # No profile config - check all loaded blocklists (default behavior)
        if config is None:
            # Check all blocklists in the engine
            block_result = self.engine.is_blocked(domain)
            if block_result.blocked:
                log.debug("Domain blocked by blocklist (no profile)", blocklist_id=block_result.blocklist_id)
                return _InternalFilterResult(
                    allowed=False,
                    reason="blocklist",
                    blocklist_id=block_result.blocklist_id,
                )
            return _InternalFilterResult(allowed=True, reason="no_profile")

        # 1. Filtering paused (highest priority after no profile)
        if config.filtering_paused_until:
            now = datetime.now(timezone.utc)
            # Handle timezone-naive datetime
            paused_until = config.filtering_paused_until
            if paused_until.tzinfo is None:
                paused_until = paused_until.replace(tzinfo=timezone.utc)
            if paused_until > now:
                log.debug("Filtering paused for profile")
                return _InternalFilterResult(allowed=True, reason="filtering_paused")

        # 2. Profile allow rules (always win)
        if self._matches_rules(domain, config.allow_rules):
            log.debug("Domain allowed by custom rule")
            return _InternalFilterResult(allowed=True, reason="allow_rule")

        # 3. Maintenance allowlist (if maintenance mode enabled)
        if config.maintenance_mode:
            if self._matches_maintenance_allowlist(domain, config.maintenance_allowlist):
                log.debug("Domain allowed by maintenance allowlist")
                return _InternalFilterResult(allowed=True, reason="maintenance_allowlist")
            # 4. Maintenance mode block (not in allowlist)
            log.debug("Domain blocked by maintenance mode")
            return _InternalFilterResult(allowed=False, reason="maintenance_mode")

        # 5. Profile deny rules
        if self._matches_rules(domain, config.deny_rules):
            log.debug("Domain blocked by custom deny rule")
            return _InternalFilterResult(allowed=False, reason="deny_rule")

        # 6. Active presets - check SEPARATELY with SORTED preset_* IDs
        if config.active_preset_ids:
            preset_blocklist_ids = sorted(
                [preset_blocklist_id(pid) for pid in config.active_preset_ids]
            )
            result = self.engine.is_blocked_ordered(domain, preset_blocklist_ids)
            if result.blocked:
                # Extract original preset ID from blocklist ID (remove "preset_" prefix)
                original_preset_id = result.blocklist_id
                if original_preset_id and original_preset_id.startswith("preset_"):
                    original_preset_id = original_preset_id[7:]
                log.debug("Domain blocked by preset", preset_id=original_preset_id)
                return _InternalFilterResult(
                    allowed=False,
                    reason="preset",
                    blocklist_id=result.blocklist_id,
                )

        # 7. Global blocklists - check SEPARATELY with SORTED blocklist IDs
        if config.active_blocklist_ids:
            sorted_blocklist_ids = sorted(config.active_blocklist_ids)
            result = self.engine.is_blocked_ordered(domain, sorted_blocklist_ids)
            if result.blocked:
                log.debug("Domain blocked by blocklist", blocklist_id=result.blocklist_id)
                return _InternalFilterResult(
                    allowed=False,
                    reason="blocklist",
                    blocklist_id=result.blocklist_id,
                )

        # Not blocked by anything
        return _InternalFilterResult(allowed=True, reason="not_blocked")

    def _matches_rules(self, domain: str, rules: set[str]) -> bool:
        """Check if domain matches any rule.

        Supports exact match and wildcard subdomain matching.
        This preserves existing behavior for profile allow/deny rules.

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

    def _matches_maintenance_allowlist(self, domain: str, allowlist: set[str]) -> bool:
        """Check if domain matches the maintenance allowlist.

        Uses exact match only for maintenance allowlist (more restrictive).

        Args:
            domain: Domain to check
            allowlist: Set of allowed domains during maintenance

        Returns:
            True if domain is in the allowlist
        """
        domain = domain.lower()

        # Exact match
        if domain in allowlist:
            return True

        # Check parent domains (for subdomain matching)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in allowlist:
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
        profile: Profile | None,
        domain: str,
        query_type: str,
        blocked: bool,
        blocklist_id: str | None,
        response_time_ms: int,
    ) -> None:
        """Log a DNS query to the database.

        Args:
            profile: Profile that made the query
            domain: Queried domain
            query_type: Query type (A, AAAA, etc.)
            blocked: Whether the query was blocked
            blocklist_id: Which blocklist blocked it (if blocked)
            response_time_ms: Response time in milliseconds
        """
        try:
            await queries.log_query(
                profile_id=profile.id if profile else None,
                domain=domain,
                query_type=query_type,
                blocked=blocked,
                blocklist_id=blocklist_id,
                response_time_ms=response_time_ms,
            )
        except Exception as e:
            logger.error("Failed to log query", error=str(e))


class _InternalFilterResult(NamedTuple):
    """Internal result from filter rules evaluation."""

    allowed: bool
    reason: str
    blocklist_id: str | None = None


# Global filter instance
_filter: DNSFilter | None = None


def get_filter() -> DNSFilter:
    """Get the global DNS filter instance."""
    global _filter
    if _filter is None:
        _filter = DNSFilter()
    return _filter


def reset_filter() -> None:
    """Reset the global filter instance (for testing)."""
    global _filter
    _filter = None
