"""Client resolution from DNS requests.

Identifies clients by:
- DoH/DoT: Subdomain from Host header or SNI (e.g., my-devices.filterdns.zkm.de)
- Legacy DNS: Source IP lookup in linked_devices table
"""

import structlog

from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import Client
from filterdns.dns.resolver import get_resolver

logger = structlog.get_logger()


class ClientResolver:
    """Resolves client configuration from request context."""

    def __init__(self, domain: str | None = None):
        self.domain = domain or settings.domain

    async def resolve_from_subdomain(self, host: str) -> Client | None:
        """Resolve client from subdomain in Host header or SNI.

        Args:
            host: Full hostname (e.g., "my-devices.filterdns.zkm.de")

        Returns:
            Client configuration or None if not found
        """
        # Extract subdomain
        client_name = self._extract_subdomain(host)
        if not client_name:
            return await self._get_default_client()

        # Look up client by name
        client = await queries.get_client_by_name(client_name)
        if client:
            logger.debug("Client resolved from subdomain", client_name=client_name)
            return client

        # Client not found, return default
        logger.debug("Client not found, using default", requested_name=client_name)
        return await self._get_default_client()

    async def resolve_from_ip(self, ip_address: str) -> Client | None:
        """Resolve client from source IP address.

        Args:
            ip_address: Client IP address

        Returns:
            Client configuration or None if not found
        """
        # Check linked devices first
        client = await queries.get_client_by_ip(ip_address)
        if client:
            logger.debug("Client resolved from IP", ip=ip_address, client_name=client.name)
            return client

        # Try reverse DNS if PTR server is configured
        if settings.ptr_server:
            hostname = await get_resolver().reverse_lookup(ip_address)
            if hostname:
                # Extract potential client name from hostname
                # e.g., "lobby-display.zkm.local" -> "lobby-display"
                parts = hostname.split(".")
                if parts:
                    client_name = parts[0]
                    client = await queries.get_client_by_name(client_name)
                    if client:
                        logger.debug(
                            "Client resolved from PTR",
                            ip=ip_address,
                            hostname=hostname,
                            client_name=client_name,
                        )
                        return client

        # Return default client
        logger.debug("No client for IP, using default", ip=ip_address)
        return await self._get_default_client()

    def _extract_subdomain(self, host: str) -> str | None:
        """Extract client name from host.

        Args:
            host: Full hostname

        Returns:
            Subdomain/client name or None if it's the base domain
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

    async def _get_default_client(self) -> Client | None:
        """Get the default client configuration."""
        return await queries.get_client_by_name(settings.default_client)


# Global client resolver instance
_client_resolver: ClientResolver | None = None


def get_client_resolver() -> ClientResolver:
    """Get the global client resolver instance."""
    global _client_resolver
    if _client_resolver is None:
        _client_resolver = ClientResolver()
    return _client_resolver
