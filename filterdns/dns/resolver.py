"""Upstream DNS resolver using dnspython."""

import asyncio
import random
import time
from typing import NamedTuple

import dns.asyncresolver
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import structlog

from filterdns.config import settings

logger = structlog.get_logger()


class ResolveResult(NamedTuple):
    """Result of DNS resolution."""

    response: dns.message.Message
    upstream: str
    response_time_ms: int


class DNSResolver:
    """Async DNS resolver that forwards queries to upstream servers."""

    def __init__(
        self,
        upstreams: list[str] | None = None,
        timeout: float | None = None,
    ):
        self.upstreams = upstreams or settings.upstream_dns
        self.timeout = timeout or settings.upstream_timeout
        self._resolver: dns.asyncresolver.Resolver | None = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        """Get or create the async resolver."""
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.nameservers = self.upstreams
            self._resolver.timeout = self.timeout
            self._resolver.lifetime = self.timeout * 2
        return self._resolver

    async def resolve(
        self,
        query: dns.message.Message,
    ) -> ResolveResult:
        """Resolve a DNS query by forwarding to upstream.

        Args:
            query: DNS query message

        Returns:
            ResolveResult with response, upstream used, and timing
        """
        start_time = time.monotonic()
        upstream = random.choice(self.upstreams)

        try:
            # Forward the query to upstream
            response = await dns.asyncquery.udp(
                query,
                upstream,
                timeout=self.timeout,
            )

            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return ResolveResult(
                response=response,
                upstream=upstream,
                response_time_ms=elapsed_ms,
            )

        except dns.exception.Timeout:
            logger.warning("DNS query timeout", upstream=upstream)
            # Try another upstream
            for other_upstream in self.upstreams:
                if other_upstream != upstream:
                    try:
                        response = await dns.asyncquery.udp(
                            query,
                            other_upstream,
                            timeout=self.timeout,
                        )
                        elapsed_ms = int((time.monotonic() - start_time) * 1000)
                        return ResolveResult(
                            response=response,
                            upstream=other_upstream,
                            response_time_ms=elapsed_ms,
                        )
                    except dns.exception.Timeout:
                        continue

            # All upstreams timed out, return SERVFAIL
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return ResolveResult(
                response=self._make_error_response(query, dns.rcode.SERVFAIL),
                upstream=upstream,
                response_time_ms=elapsed_ms,
            )

        except Exception as e:
            logger.error("DNS resolution error", error=str(e), upstream=upstream)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return ResolveResult(
                response=self._make_error_response(query, dns.rcode.SERVFAIL),
                upstream=upstream,
                response_time_ms=elapsed_ms,
            )

    async def resolve_name(
        self,
        name: str,
        rdtype: str = "A",
    ) -> list[str]:
        """Resolve a domain name to a list of addresses.

        Simple helper for common lookups.

        Args:
            name: Domain name to resolve
            rdtype: Record type (A, AAAA, etc.)

        Returns:
            List of resolved addresses
        """
        resolver = self._get_resolver()
        try:
            answer = await resolver.resolve(name, rdtype)
            return [rdata.to_text() for rdata in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            logger.error("Name resolution error", name=name, rdtype=rdtype, error=str(e))
            return []

    async def reverse_lookup(self, ip: str) -> str | None:
        """Perform reverse DNS lookup (PTR).

        Args:
            ip: IP address to look up

        Returns:
            Hostname or None if not found
        """
        try:
            # Use custom PTR server if configured
            if settings.ptr_server:
                resolver = dns.asyncresolver.Resolver()
                resolver.nameservers = [settings.ptr_server]
                resolver.timeout = settings.ptr_timeout
            else:
                resolver = self._get_resolver()

            # Convert IP to reverse DNS name
            rev_name = dns.reversename.from_address(ip)
            answer = await resolver.resolve(rev_name, "PTR")
            if answer:
                # Remove trailing dot from hostname
                hostname = answer[0].to_text().rstrip(".")
                return hostname
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.debug("PTR lookup failed", ip=ip, error=str(e))

        return None

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


# Global resolver instance
_resolver: DNSResolver | None = None


def get_resolver() -> DNSResolver:
    """Get the global DNS resolver instance."""
    global _resolver
    if _resolver is None:
        _resolver = DNSResolver()
    return _resolver
