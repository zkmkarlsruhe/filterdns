"""Legacy DNS server (UDP/TCP on port 53)."""

import asyncio
from typing import Callable

import dns.message
import structlog

from filterdns.config import settings
from filterdns.dns.filter import DNSFilter, get_filter
from filterdns.gateway.client_resolver import ClientResolver, get_client_resolver

logger = structlog.get_logger()


class DNS53Protocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS queries."""

    def __init__(
        self,
        dns_filter: DNSFilter,
        client_resolver: ClientResolver,
        loop: asyncio.AbstractEventLoop,
    ):
        self.dns_filter = dns_filter
        self.client_resolver = client_resolver
        self.loop = loop
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle incoming UDP DNS query."""
        self.loop.create_task(self._handle_query(data, addr))

    async def _handle_query(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process DNS query and send response."""
        client_ip = addr[0]

        try:
            # Parse DNS query
            query = dns.message.from_wire(data)

            # Resolve client from IP
            client = await self.client_resolver.resolve_from_ip(client_ip)

            # Filter the query
            result = await self.dns_filter.filter_query(query, client)

            # Send response
            response_data = result.response.to_wire()
            if self.transport:
                self.transport.sendto(response_data, addr)

            # Log
            if query.question:
                domain = str(query.question[0].name).rstrip(".")
                logger.debug(
                    "DNS53 query processed",
                    domain=domain,
                    client_ip=client_ip,
                    client_name=client.name if client else None,
                    blocked=result.blocked,
                    response_time_ms=result.response_time_ms,
                )

        except Exception as e:
            logger.error("DNS53 query error", client_ip=client_ip, error=str(e))


class DNS53TCPHandler:
    """TCP connection handler for DNS queries."""

    def __init__(
        self,
        dns_filter: DNSFilter,
        client_resolver: ClientResolver,
    ):
        self.dns_filter = dns_filter
        self.client_resolver = client_resolver

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle TCP DNS connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        try:
            while True:
                # Read length prefix (2 bytes)
                length_data = await asyncio.wait_for(reader.read(2), timeout=30.0)
                if not length_data or len(length_data) < 2:
                    break

                # Read DNS message
                length = int.from_bytes(length_data, "big")
                data = await asyncio.wait_for(reader.read(length), timeout=30.0)
                if not data or len(data) < length:
                    break

                # Parse and process query
                query = dns.message.from_wire(data)
                client = await self.client_resolver.resolve_from_ip(client_ip)
                result = await self.dns_filter.filter_query(query, client)

                # Send response with length prefix
                response_data = result.response.to_wire()
                writer.write(len(response_data).to_bytes(2, "big") + response_data)
                await writer.drain()

                if query.question:
                    domain = str(query.question[0].name).rstrip(".")
                    logger.debug(
                        "DNS53/TCP query processed",
                        domain=domain,
                        client_ip=client_ip,
                        blocked=result.blocked,
                    )

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error("DNS53/TCP error", client_ip=client_ip, error=str(e))
        finally:
            writer.close()
            await writer.wait_closed()


class DNS53Server:
    """DNS server supporting both UDP and TCP on port 53."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int | None = None,
        dns_filter: DNSFilter | None = None,
        client_resolver: ClientResolver | None = None,
    ):
        self.host = host
        self.port = port or settings.dns_port
        self.dns_filter = dns_filter or get_filter()
        self.client_resolver = client_resolver or get_client_resolver()
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the DNS server (UDP and TCP)."""
        loop = asyncio.get_event_loop()

        # Start UDP server
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: DNS53Protocol(self.dns_filter, self.client_resolver, loop),
            local_addr=(self.host, self.port),
        )
        logger.info("DNS53/UDP server started", host=self.host, port=self.port)

        # Start TCP server
        tcp_handler = DNS53TCPHandler(self.dns_filter, self.client_resolver)
        self._tcp_server = await asyncio.start_server(
            tcp_handler.handle_connection,
            self.host,
            self.port,
        )
        logger.info("DNS53/TCP server started", host=self.host, port=self.port)

    async def stop(self) -> None:
        """Stop the DNS server."""
        if self._udp_transport:
            self._udp_transport.close()
            logger.info("DNS53/UDP server stopped")

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            logger.info("DNS53/TCP server stopped")
