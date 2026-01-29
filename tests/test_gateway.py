"""Tests for DNS gateway protocols (DoH, DoT, DNS53)."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime, timezone

import pytest
import dns.message
import dns.rcode

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.dns.filter import DNSFilter, FilterResult
from filterdns.gateway.client_resolver import ClientResolver
from filterdns.gateway.doh import create_doh_blueprint
from filterdns.gateway.dns53 import DNS53Protocol, DNS53TCPHandler
from filterdns.app import create_app


def make_dns_query(domain: str, rdtype: str = "A") -> bytes:
    """Create a wire-format DNS query."""
    query = dns.message.make_query(domain, rdtype)
    return query.to_wire()


def make_dns_query_base64url(domain: str, rdtype: str = "A") -> str:
    """Create a base64url-encoded DNS query for DoH GET requests."""
    wire = make_dns_query(domain, rdtype)
    # Base64url encoding without padding
    encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
    return encoded


class TestClientResolver:
    """Tests for client resolution from requests."""

    def test_extract_subdomain(self):
        """Test extracting client name from hostname."""
        resolver = ClientResolver(domain="filterdns.example.com")

        # Valid subdomain
        assert resolver._extract_subdomain("mydevices.filterdns.example.com") == "mydevices"
        assert resolver._extract_subdomain("test-client.filterdns.example.com") == "test-client"

        # With port
        assert resolver._extract_subdomain("mydevices.filterdns.example.com:443") == "mydevices"

        # Base domain (no subdomain)
        assert resolver._extract_subdomain("filterdns.example.com") is None

        # Unknown domain
        assert resolver._extract_subdomain("other.example.com") is None

    def test_extract_subdomain_case_insensitive(self):
        """Test that subdomain extraction is case-insensitive."""
        resolver = ClientResolver(domain="filterdns.example.com")

        assert resolver._extract_subdomain("MyDevices.FilterDNS.Example.COM") == "mydevices"
        assert resolver._extract_subdomain("TEST.FILTERDNS.EXAMPLE.COM") == "test"

    @pytest.mark.asyncio
    async def test_resolve_from_subdomain(self):
        """Test resolving client from subdomain."""
        from filterdns.db.models import Client

        resolver = ClientResolver(domain="filterdns.example.com")

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="mydevices",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.gateway.client_resolver.queries") as mock_queries:
            mock_queries.get_client_by_name = AsyncMock(return_value=mock_client)

            client = await resolver.resolve_from_subdomain("mydevices.filterdns.example.com")

            assert client is not None
            assert client.name == "mydevices"
            mock_queries.get_client_by_name.assert_called_with("mydevices")

    @pytest.mark.asyncio
    async def test_resolve_from_subdomain_not_found(self):
        """Test resolving unknown client falls back to default."""
        from filterdns.db.models import Client

        resolver = ClientResolver(domain="filterdns.example.com")

        now = datetime.now(timezone.utc)
        default_client = Client(
            id=uuid4(),
            name="default",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.gateway.client_resolver.queries") as mock_queries:
            # First call (lookup) returns None, second call (default) returns default
            mock_queries.get_client_by_name = AsyncMock(
                side_effect=[None, default_client]
            )

            client = await resolver.resolve_from_subdomain("unknown.filterdns.example.com")

            # Should fall back to default client
            assert client is not None
            assert client.name == "default"

    @pytest.mark.asyncio
    async def test_resolve_from_ip(self):
        """Test resolving client from IP address."""
        from filterdns.db.models import Client

        resolver = ClientResolver(domain="filterdns.example.com")

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="lobby-display",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.gateway.client_resolver.queries") as mock_queries:
            mock_queries.get_client_by_ip = AsyncMock(return_value=mock_client)

            client = await resolver.resolve_from_ip("192.168.1.100")

            assert client is not None
            assert client.name == "lobby-display"
            mock_queries.get_client_by_ip.assert_called_with("192.168.1.100")


class TestDoHEndpoint:
    """Tests for DNS-over-HTTPS endpoint."""

    @pytest.fixture
    def mock_filter(self):
        """Create a mock DNS filter."""
        mock = MagicMock()
        return mock

    @pytest.fixture
    def mock_client_resolver(self):
        """Create a mock client resolver."""
        mock = MagicMock()
        mock.resolve_from_subdomain = AsyncMock(return_value=None)
        return mock

    @pytest.fixture
    def doh_app(self, mock_filter, mock_client_resolver):
        """Create test app with injected mock dependencies."""
        from quart import Quart

        app = Quart(__name__)
        # Create blueprint with injected mocks
        bp = create_doh_blueprint(
            dns_filter=mock_filter,
            client_resolver=mock_client_resolver,
        )
        app.register_blueprint(bp)
        return app, mock_filter, mock_client_resolver

    @pytest.mark.asyncio
    async def test_doh_get_request(self, doh_app):
        """Test DoH GET request with base64url encoded query."""
        app, mock_filter, _ = doh_app
        client = app.test_client()

        # Setup mock filter response
        query = dns.message.make_query("google.com", "A")
        response = dns.message.make_response(query)
        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=10,
        ))

        dns_param = make_dns_query_base64url("google.com", "A")
        resp = await client.get(f"/dns-query?dns={dns_param}")

        assert resp.status_code == 200
        assert resp.content_type == "application/dns-message"

        # Parse response
        data = await resp.get_data()
        dns_response = dns.message.from_wire(data)
        assert dns_response.rcode() == dns.rcode.NOERROR

    @pytest.mark.asyncio
    async def test_doh_post_request(self, doh_app):
        """Test DoH POST request with binary DNS message."""
        app, mock_filter, _ = doh_app
        client = app.test_client()

        # Setup mock filter response
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)
        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=10,
        ))

        dns_wire = make_dns_query("example.com", "A")
        resp = await client.post(
            "/dns-query",
            data=dns_wire,
            headers={"Content-Type": "application/dns-message"},
        )

        assert resp.status_code == 200
        assert resp.content_type == "application/dns-message"

    @pytest.mark.asyncio
    async def test_doh_missing_dns_param(self, doh_app):
        """Test DoH GET without dns parameter returns 400."""
        app, _, _ = doh_app
        client = app.test_client()

        response = await client.get("/dns-query")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_doh_wrong_content_type(self, doh_app):
        """Test DoH POST with wrong content type returns 415."""
        app, _, _ = doh_app
        client = app.test_client()

        dns_wire = make_dns_query("example.com", "A")
        response = await client.post(
            "/dns-query",
            data=dns_wire,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 415

    @pytest.mark.asyncio
    async def test_doh_blocked_domain(self, doh_app):
        """Test DoH request for blocked domain returns NXDOMAIN."""
        app, mock_filter, _ = doh_app
        client = app.test_client()

        # Setup mock filter to return blocked response
        query = dns.message.make_query("blocked.example.com", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=True,
            blocklist_id="test-ads",
            response_time_ms=1,
        ))

        dns_param = make_dns_query_base64url("blocked.example.com", "A")
        resp = await client.get(f"/dns-query?dns={dns_param}")

        assert resp.status_code == 200

        # Parse response - should be NXDOMAIN
        data = await resp.get_data()
        dns_response = dns.message.from_wire(data)
        assert dns_response.rcode() == dns.rcode.NXDOMAIN


class TestDoHJsonResolve:
    """Tests for JSON resolve API (Google-style)."""

    @pytest.fixture
    def doh_app(self):
        """Create test app with injected mock dependencies."""
        from quart import Quart

        mock_filter = MagicMock()
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_subdomain = AsyncMock(return_value=None)

        app = Quart(__name__)
        bp = create_doh_blueprint(
            dns_filter=mock_filter,
            client_resolver=mock_resolver,
        )
        app.register_blueprint(bp)
        return app, mock_filter

    @pytest.mark.asyncio
    async def test_json_resolve(self, doh_app):
        """Test JSON resolve endpoint."""
        app, mock_filter = doh_app
        client = app.test_client()

        # Setup mock filter
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)
        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=10,
        ))

        resp = await client.get("/resolve?name=example.com&type=A")

        assert resp.status_code == 200
        data = await resp.get_json()
        assert "Status" in data
        assert "Question" in data

    @pytest.mark.asyncio
    async def test_json_resolve_missing_name(self, doh_app):
        """Test JSON resolve without name parameter."""
        app, _ = doh_app
        client = app.test_client()

        response = await client.get("/resolve")

        assert response.status_code == 200
        data = await response.get_json()
        assert data["Status"] == 400
        assert "Missing name" in data["Comment"]


class TestDNS53Protocol:
    """Tests for legacy DNS (UDP) protocol."""

    @pytest.mark.asyncio
    async def test_udp_query_processing(self):
        """Test UDP DNS query processing."""
        # Create mock filter
        mock_filter = MagicMock()
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)

        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=10,
        ))

        # Create mock client resolver
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        # Create protocol instance
        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        # Create mock transport
        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # Simulate receiving a DNS query
        dns_wire = make_dns_query("example.com", "A")
        addr = ("192.168.1.100", 12345)

        # Process the query
        await protocol._handle_query(dns_wire, addr)

        # Verify filter was called
        mock_filter.filter_query.assert_called_once()

        # Verify response was sent
        mock_transport.sendto.assert_called_once()
        sent_data, sent_addr = mock_transport.sendto.call_args[0]
        assert sent_addr == addr

        # Verify response is valid DNS
        dns_response = dns.message.from_wire(sent_data)
        assert dns_response.rcode() == dns.rcode.NOERROR

    @pytest.mark.asyncio
    async def test_udp_blocked_query(self):
        """Test UDP DNS query for blocked domain."""
        # Create mock filter that blocks
        mock_filter = MagicMock()
        query = dns.message.make_query("blocked.com", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=True,
            blocklist_id="ads",
            response_time_ms=1,
        ))

        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        dns_wire = make_dns_query("blocked.com", "A")
        await protocol._handle_query(dns_wire, ("192.168.1.100", 12345))

        # Verify NXDOMAIN response
        sent_data = mock_transport.sendto.call_args[0][0]
        dns_response = dns.message.from_wire(sent_data)
        assert dns_response.rcode() == dns.rcode.NXDOMAIN


class TestDNS53TCPHandler:
    """Tests for legacy DNS (TCP) protocol."""

    @pytest.mark.asyncio
    async def test_tcp_length_prefixed_message(self):
        """Test TCP DNS with length-prefixed messages."""
        # Create mock filter
        mock_filter = MagicMock()
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)

        mock_filter.filter_query = AsyncMock(return_value=FilterResult(
            response=response,
            blocked=False,
            blocklist_id=None,
            response_time_ms=10,
        ))

        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        handler = DNS53TCPHandler(mock_filter, mock_resolver)

        # Create DNS query with length prefix
        dns_wire = make_dns_query("example.com", "A")
        length_prefix = len(dns_wire).to_bytes(2, "big")
        full_message = length_prefix + dns_wire

        # Create mock reader/writer
        mock_reader = AsyncMock()
        # First read returns length, second returns message, third returns empty (connection closed)
        mock_reader.read = AsyncMock(side_effect=[
            length_prefix,
            dns_wire,
            b"",  # Connection closed
        ])

        mock_writer = MagicMock()
        mock_writer.get_extra_info = MagicMock(return_value=("192.168.1.100", 12345))
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        # Handle connection
        await handler.handle_connection(mock_reader, mock_writer)

        # Verify response was written with length prefix
        mock_writer.write.assert_called_once()
        written_data = mock_writer.write.call_args[0][0]

        # First 2 bytes are length
        resp_length = int.from_bytes(written_data[:2], "big")
        resp_data = written_data[2:]
        assert len(resp_data) == resp_length

        # Verify it's valid DNS response
        dns_response = dns.message.from_wire(resp_data)
        assert dns_response.rcode() == dns.rcode.NOERROR


class TestDoTServer:
    """Tests for DNS-over-TLS server logic (without actual TLS)."""

    def test_ssl_context_requires_certs(self):
        """Test that DoT server requires TLS certificates."""
        from filterdns.gateway.dot import DoTServer

        server = DoTServer(cert_path=None, key_path=None)

        with pytest.raises(ValueError, match="TLS certificate"):
            server._create_ssl_context()


class TestDNSQueryTypes:
    """Tests for handling different DNS query types across protocols."""

    @pytest.fixture
    def mock_filter(self):
        """Create a mock filter that returns appropriate responses."""
        mock = MagicMock()

        def filter_query(query, client):
            response = dns.message.make_response(query)
            return FilterResult(
                response=response,
                blocked=False,
                blocklist_id=None,
                response_time_ms=5,
            )

        mock.filter_query = AsyncMock(side_effect=filter_query)
        return mock

    @pytest.mark.asyncio
    async def test_aaaa_query(self, mock_filter):
        """Test AAAA (IPv6) query handling."""
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        dns_wire = make_dns_query("example.com", "AAAA")
        await protocol._handle_query(dns_wire, ("192.168.1.100", 12345))

        # Verify query was processed
        mock_filter.filter_query.assert_called_once()
        call_args = mock_filter.filter_query.call_args
        query = call_args[0][0]
        assert query.question[0].rdtype == dns.rdatatype.AAAA

    @pytest.mark.asyncio
    async def test_mx_query(self, mock_filter):
        """Test MX query handling."""
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        dns_wire = make_dns_query("example.com", "MX")
        await protocol._handle_query(dns_wire, ("192.168.1.100", 12345))

        call_args = mock_filter.filter_query.call_args
        query = call_args[0][0]
        assert query.question[0].rdtype == dns.rdatatype.MX

    @pytest.mark.asyncio
    async def test_txt_query(self, mock_filter):
        """Test TXT query handling."""
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        dns_wire = make_dns_query("example.com", "TXT")
        await protocol._handle_query(dns_wire, ("192.168.1.100", 12345))

        call_args = mock_filter.filter_query.call_args
        query = call_args[0][0]
        assert query.question[0].rdtype == dns.rdatatype.TXT

    @pytest.mark.asyncio
    async def test_ptr_query(self, mock_filter):
        """Test PTR (reverse DNS) query handling."""
        mock_resolver = MagicMock()
        mock_resolver.resolve_from_ip = AsyncMock(return_value=None)

        loop = asyncio.get_event_loop()
        protocol = DNS53Protocol(mock_filter, mock_resolver, loop)

        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # PTR query for 1.168.192.in-addr.arpa
        dns_wire = make_dns_query("1.168.192.in-addr.arpa", "PTR")
        await protocol._handle_query(dns_wire, ("192.168.1.100", 12345))

        call_args = mock_filter.filter_query.call_args
        query = call_args[0][0]
        assert query.question[0].rdtype == dns.rdatatype.PTR
