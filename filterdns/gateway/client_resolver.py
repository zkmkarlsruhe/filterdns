"""Profile resolution from DNS requests.

- Profile: DNS filtering configuration (e.g., "my-devices")
- Device: Individual machine using a profile

Identifies profiles by:
- DoH/DoT: Subdomain from Host header or SNI (e.g., my-devices.filterdns.example.com)
- Legacy DNS: Source IP lookup in devices table
"""

import structlog

from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import Profile
from filterdns.dns.resolver import get_resolver

logger = structlog.get_logger()


class ProfileResolver:
    """Resolves profile configuration from request context."""

    def __init__(self, domain: str | None = None):
        self.domain = domain or settings.domain

    async def resolve_from_subdomain(self, host: str) -> Profile | None:
        """Resolve profile from subdomain in Host header or SNI.

        Args:
            host: Full hostname (e.g., "my-devices.filterdns.example.com")

        Returns:
            Profile configuration or None if not found
        """
        # Extract subdomain
        profile_name = self._extract_subdomain(host)
        if not profile_name:
            return await self._get_default_profile()

        # Look up profile by name
        profile = await queries.get_profile_by_name(profile_name)
        if profile:
            logger.debug("Profile resolved from subdomain", profile_name=profile_name)
            return profile

        # Profile not found, return default
        logger.debug("Profile not found, using default", requested_name=profile_name)
        return await self._get_default_profile()

    async def resolve_from_ip(self, ip_address: str) -> Profile | None:
        """Resolve profile from source IP address.

        Args:
            ip_address: Device IP address

        Returns:
            Profile configuration or None if not found
        """
        # Check devices table
        profile = await queries.get_profile_by_device_ip(ip_address)
        if profile:
            logger.debug("Profile resolved from IP", ip=ip_address, profile_name=profile.name)
            return profile

        # Try reverse DNS if PTR server is configured
        if settings.ptr_server:
            hostname = await get_resolver().reverse_lookup(ip_address)
            if hostname:
                # Extract potential profile name from hostname
                # e.g., "lobby-display.local" -> "lobby-display"
                parts = hostname.split(".")
                if parts:
                    profile_name = parts[0]
                    profile = await queries.get_profile_by_name(profile_name)
                    if profile:
                        logger.debug(
                            "Profile resolved from PTR",
                            ip=ip_address,
                            hostname=hostname,
                            profile_name=profile_name,
                        )
                        return profile

        # Return default profile
        logger.debug("No profile for IP, using default", ip=ip_address)
        return await self._get_default_profile()

    def _extract_subdomain(self, host: str) -> str | None:
        """Extract profile name from host.

        Args:
            host: Full hostname

        Returns:
            Subdomain/profile name or None if it's the base domain
        """
        # Remove port if present
        host = host.split(":")[0].lower()

        # Check if it ends with our domain
        suffix = f".{self.domain}"
        if not host.endswith(suffix):
            # Might be the base domain itself
            if host == self.domain:
                return None
            # Unknown domain
            return None

        # Extract subdomain
        subdomain = host[: -len(suffix)]
        if not subdomain or subdomain == self.domain:
            return None

        return subdomain

    async def _get_default_profile(self) -> Profile | None:
        """Get the default profile configuration."""
        return await queries.get_profile_by_name(settings.default_client)


# Backwards compatibility alias
ClientResolver = ProfileResolver


# Global profile resolver instance
_profile_resolver: ProfileResolver | None = None


def get_profile_resolver() -> ProfileResolver:
    """Get the global profile resolver instance."""
    global _profile_resolver
    if _profile_resolver is None:
        _profile_resolver = ProfileResolver()
    return _profile_resolver


# Backwards compatibility alias
get_client_resolver = get_profile_resolver
