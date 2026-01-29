"""Tests for the REST API."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timezone

from filterdns.app import create_app
from filterdns.db.models import Blocklist


@pytest.fixture
def app():
    """Create application for testing."""
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test health endpoint returns OK."""
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "healthy"
        assert "blocklists_loaded" in data
        assert "total_blocked_domains" in data


class TestBlocklistsEndpoint:
    """Tests for blocklists endpoint."""

    @pytest.mark.asyncio
    async def test_list_blocklists(self, client):
        """Test listing available blocklists."""
        mock_blocklists = [
            Blocklist(
                id="test-blocklist",
                name="Test Blocklist",
                url="https://example.com/blocklist.txt",
                description="A test blocklist",
                category="ads",
                domain_count=1000,
                enabled=True,
                last_updated=datetime.now(timezone.utc),
            ),
            Blocklist(
                id="malware-list",
                name="Malware List",
                url="https://example.com/malware.txt",
                description="A malware blocklist",
                category="malware",
                domain_count=500,
                enabled=True,
                last_updated=datetime.now(timezone.utc),
            ),
        ]

        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.list_blocklists = AsyncMock(return_value=mock_blocklists)

            response = await client.get("/api/blocklists")
            assert response.status_code == 200

            data = await response.get_json()
            assert "blocklists" in data
            assert len(data["blocklists"]) == 2

            bl = data["blocklists"][0]
            assert bl["id"] == "test-blocklist"
            assert bl["name"] == "Test Blocklist"
            assert bl["category"] == "ads"
            assert bl["domain_count"] == 1000

    @pytest.mark.asyncio
    async def test_list_blocklists_empty(self, client):
        """Test listing blocklists when none exist."""
        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.list_blocklists = AsyncMock(return_value=[])

            response = await client.get("/api/blocklists")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["blocklists"] == []


class TestClientCreation:
    """Tests for client creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_client_success(self, client):
        """Test successful client creation."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.get_client_by_name = AsyncMock(return_value=None)
            mock_queries.create_client = AsyncMock(return_value=mock_client)
            mock_queries.add_client_blocklist = AsyncMock()

            response = await client.post(
                "/api/clients",
                json={"name": "testclient"},
            )

            assert response.status_code == 201
            data = await response.get_json()
            assert data["name"] == "testclient"
            assert "dns_endpoint" in data
            assert "doh_url" in data
            assert "dot_hostname" in data

    @pytest.mark.asyncio
    async def test_create_client_missing_name(self, client):
        """Test client creation with missing name."""
        response = await client.post("/api/clients", json={})
        assert response.status_code == 400

        data = await response.get_json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_create_client_invalid_name(self, client):
        """Test client creation with invalid name."""
        response = await client.post("/api/clients", json={"name": "Invalid Name!"})
        assert response.status_code == 400

        data = await response.get_json()
        assert "error" in data
        assert "Invalid name" in data["error"]

    @pytest.mark.asyncio
    async def test_create_client_duplicate_name(self, client):
        """Test client creation with duplicate name."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        existing = Client(
            id=uuid4(),
            name="existingclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.get_client_by_name = AsyncMock(return_value=existing)

            response = await client.post(
                "/api/clients",
                json={"name": "existingclient"},
            )

            assert response.status_code == 409
            data = await response.get_json()
            assert "already taken" in data["error"]

    @pytest.mark.asyncio
    async def test_create_client_name_too_long(self, client):
        """Test client creation with name too long."""
        response = await client.post(
            "/api/clients",
            json={"name": "a" * 64},
        )
        assert response.status_code == 400

        data = await response.get_json()
        assert "too long" in data["error"]


class TestWhoamiEndpoint:
    """Tests for whoami endpoint."""

    @pytest.mark.asyncio
    async def test_whoami(self, client):
        """Test whoami endpoint."""
        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.get_client_by_ip = AsyncMock(return_value=None)

            # The get_resolver is imported inside the function, so we patch where it's used
            with patch("filterdns.dns.resolver.get_resolver") as mock_get_resolver:
                resolver_instance = MagicMock()
                resolver_instance.reverse_lookup = AsyncMock(return_value="hostname.local")
                mock_get_resolver.return_value = resolver_instance

                response = await client.get("/api/whoami")
                assert response.status_code == 200

                data = await response.get_json()
                assert "ip_address" in data
                assert "hostname" in data
                assert "linked_to" in data


class TestClientRulesEndpoint:
    """Tests for client rules endpoint."""

    @pytest.mark.asyncio
    async def test_create_rule_invalid_type(self, client):
        """Test creating a rule with invalid type."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        # Patch queries in both routes and auth modules
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_client_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_client_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/clients/testclient/rules",
                json={"domain": "example.com", "rule_type": "invalid"},
            )

            assert response.status_code == 400
            data = await response.get_json()
            assert "allow" in data["error"] or "deny" in data["error"]

    @pytest.mark.asyncio
    async def test_create_rule_missing_domain(self, client):
        """Test creating a rule with missing domain."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        # Patch queries in both routes and auth modules
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_client_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_client_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/clients/testclient/rules",
                json={"rule_type": "allow"},
            )

            assert response.status_code == 400
            data = await response.get_json()
            assert "Domain required" in data["error"]


class TestPauseFiltering:
    """Tests for pause/resume filtering endpoints."""

    @pytest.mark.asyncio
    async def test_pause_invalid_minutes(self, client):
        """Test pausing with invalid minutes value."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        # Patch queries in both routes and auth modules
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_client_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_client_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/clients/testclient/pause",
                json={"minutes": 10},  # Invalid - must be 5, 15, 30, or 60
            )

            assert response.status_code == 400
            data = await response.get_json()
            assert "5, 15, 30, or 60" in data["error"]

    @pytest.mark.asyncio
    async def test_pause_valid_minutes(self, client):
        """Test pausing with valid minutes value."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        paused_client = Client(
            id=mock_client.id,
            name="testclient",
            password_hash=None,
            filtering_paused_until=now,
            created_at=mock_client.created_at,
            updated_at=now,
        )

        # Patch queries in both routes and auth modules
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_client_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.pause_client_filtering = AsyncMock(return_value=paused_client)
            mock_auth_queries.get_client_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/clients/testclient/pause",
                json={"minutes": 15},
            )

            assert response.status_code == 200
            data = await response.get_json()
            assert "paused for 15 minutes" in data["message"]
