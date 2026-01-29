"""DNS-over-TLS (DoT) server (RFC 7858)."""

import asyncio
import ssl
from pathlib import Path

import dns.message
import structlog

from filterdns.config import settings
from filterdns.dns.filter import DNSFilter, get_filter
from filterdns.gateway.client_resolver import ClientResolver, get_client_resolver

logger = structlog.get_logger()


class DoTServer:
    """DNS-over-TLS server on port 853."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int | None = None,
        cert_path: Path | None = None,
        key_path: Path | None = None,
        dns_filter: DNSFilter | None = None,
        client_resolver: ClientResolver | None = None,
    ):
        self.host = host
        self.port = port or settings.dot_port
        self.cert_path = cert_path or settings.tls_cert
        self.key_path = key_path or settings.tls_key
        self.dns_filter = dns_filter or get_filter()
        self.client_resolver = client_resolver or get_client_resolver()
        self._server: asyncio.Server | None = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for TLS connections."""
        if not self.cert_path or not self.key_path:
            raise ValueError("TLS certificate and key paths required for DoT")

        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(self.cert_path, self.key_path)

        # Enable SNI callback to extract client name
        def sni_callback(
            ssl_socket: ssl.SSLSocket,
            server_name: str | None,
            original_context: ssl.SSLContext,
        ) -> None:
            # Store SNI in ssl_socket for later use
            if server_name:
                ssl_socket.server_name = server_name  # type: ignore

        ctx.sni_callback = sni_callback  # type: ignore
        return ctx

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a DoT connection."""
        # Get peer info and SNI
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        # Try to get SNI from the SSL object
        ssl_object = writer.get_extra_info("ssl_object")
        sni_hostname = None
        if ssl_object:
            sni_hostname = getattr(ssl_object, "server_name", None)

        log = logger.bind(client_ip=client_ip, sni=sni_hostname)
        log.debug("DoT connection established")

        try:
            while True:
                # Read length prefix (2 bytes, big-endian)
                length_data = await asyncio.wait_for(reader.read(2), timeout=30.0)
                if not length_data or len(length_data) < 2:
                    break

                # Read DNS message
                length = int.from_bytes(length_data, "big")
                if length > 65535:
                    log.warning("DoT message too large", length=length)
                    break

                data = await asyncio.wait_for(reader.read(length), timeout=30.0)
                if not data or len(data) < length:
                    break

                # Parse DNS query
                query = dns.message.from_wire(data)

                # Resolve client from SNI or IP
                if sni_hostname:
                    client = await self.client_resolver.resolve_from_subdomain(sni_hostname)
                else:
                    client = await self.client_resolver.resolve_from_ip(client_ip)

                # Filter the query
                result = await self.dns_filter.filter_query(query, client)

                # Send response with length prefix
                response_data = result.response.to_wire()
                writer.write(len(response_data).to_bytes(2, "big") + response_data)
                await writer.drain()

                if query.question:
                    domain = str(query.question[0].name).rstrip(".")
                    log.debug(
                        "DoT query processed",
                        domain=domain,
                        client_name=client.name if client else None,
                        blocked=result.blocked,
                        response_time_ms=result.response_time_ms,
                    )

        except asyncio.TimeoutError:
            log.debug("DoT connection timeout")
        except Exception as e:
            log.error("DoT connection error", error=str(e))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        """Start the DoT server."""
        if not self.cert_path or not self.key_path:
            logger.warning("DoT server not started: TLS certificates not configured")
            return

        if not self.cert_path.exists() or not self.key_path.exists():
            logger.warning(
                "DoT server not started: TLS certificate files not found",
                cert=str(self.cert_path),
                key=str(self.key_path),
            )
            return

        ssl_context = self._create_ssl_context()

        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
            ssl=ssl_context,
        )

        logger.info("DoT server started", host=self.host, port=self.port)

    async def stop(self) -> None:
        """Stop the DoT server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("DoT server stopped")
