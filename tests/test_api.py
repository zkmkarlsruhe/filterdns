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


class TestProfileCreation:
    """Tests for client creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_profile_success(self, client):
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
            mock_queries.get_profile_by_name = AsyncMock(return_value=None)
            mock_queries.create_profile = AsyncMock(return_value=mock_client)
            mock_queries.add_profile_blocklist = AsyncMock()

            response = await client.post(
                "/api/profiles",
                json={"name": "testclient"},
            )

            assert response.status_code == 201
            data = await response.get_json()
            assert data["name"] == "testclient"
            assert "dns_endpoint" in data
            assert "doh_url" in data
            assert "dot_hostname" in data

    @pytest.mark.asyncio
    async def test_create_profile_missing_name(self, client):
        """Test client creation with missing name."""
        response = await client.post("/api/profiles", json={})
        assert response.status_code == 400

        data = await response.get_json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_create_profile_invalid_name(self, client):
        """Test client creation with invalid name."""
        response = await client.post("/api/profiles", json={"name": "Invalid Name!"})
        assert response.status_code == 400

        data = await response.get_json()
        assert "error" in data
        assert "Invalid name" in data["error"]

    @pytest.mark.asyncio
    async def test_create_profile_duplicate_name(self, client):
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
            mock_queries.get_profile_by_name = AsyncMock(return_value=existing)

            response = await client.post(
                "/api/profiles",
                json={"name": "existingclient"},
            )

            assert response.status_code == 409
            data = await response.get_json()
            assert "already taken" in data["error"]

    @pytest.mark.asyncio
    async def test_create_profile_name_too_long(self, client):
        """Test client creation with name too long."""
        response = await client.post(
            "/api/profiles",
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
            mock_queries.get_profile_by_device_ip = AsyncMock(return_value=None)

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
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/rules",
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
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/rules",
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
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/pause",
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
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.pause_profile_filtering = AsyncMock(return_value=paused_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/pause",
                json={"minutes": 15},
            )

            assert response.status_code == 200
            data = await response.get_json()
            assert "paused for 15 minutes" in data["message"]


class TestGetClient:
    """Tests for get client endpoint."""

    @pytest.mark.asyncio
    async def test_get_client_success(self, client):
        """Test getting a client by name."""
        from filterdns.db.models import Client, ClientStats

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            maintenance_mode=False,
            maintenance_allowlist=[],
            created_at=now,
            updated_at=now,
        )
        mock_stats = ClientStats(
            total_queries=100,
            blocked_queries=25,
            allowed_queries=75,
            blocked_percentage=25.0,
            top_blocked_domains=[("ads.example.com", 10)],
            queries_by_hour=[],
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_profile_blocklists = AsyncMock(return_value=["hagezi-multi-normal"])
            mock_routes_queries.get_profile_rules = AsyncMock(return_value=[])
            mock_routes_queries.get_profile_stats = AsyncMock(return_value=mock_stats)
            mock_routes_queries.get_profile_presets = AsyncMock(return_value=[])
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["name"] == "testclient"
            assert "dns_endpoint" in data
            assert "doh_url" in data
            assert data["blocklists"] == ["hagezi-multi-normal"]
            assert data["stats"]["total_queries"] == 100

    @pytest.mark.asyncio
    async def test_get_client_not_found(self, client):
        """Test getting a non-existent client."""
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=None)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=None)

            response = await client.get("/api/profiles/nonexistent")
            assert response.status_code == 404


class TestUpdateClient:
    """Tests for update client endpoint."""

    @pytest.mark.asyncio
    async def test_update_client_blocklists(self, client):
        """Test updating client blocklists."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.set_profile_blocklists = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.put(
                "/api/profiles/testclient",
                json={"blocklists": ["hagezi-multi-normal", "malware-list"]},
            )

            assert response.status_code == 200
            mock_routes_queries.set_profile_blocklists.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_client_not_found(self, client):
        """Test updating non-existent client."""
        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=None)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=None)

            response = await client.put(
                "/api/profiles/nonexistent",
                json={"blocklists": []},
            )
            assert response.status_code == 404


class TestDeleteClient:
    """Tests for delete client endpoint."""

    @pytest.mark.asyncio
    async def test_delete_client_success(self, client):
        """Test deleting a client."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries, \
             patch("filterdns.api.routes.settings") as mock_settings:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.delete_profile = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_settings.default_client = "default"

            response = await client.delete("/api/profiles/testclient")
            assert response.status_code == 200
            mock_routes_queries.delete_profile.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_default_client_forbidden(self, client):
        """Test that deleting the default client is forbidden."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="default",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries, \
             patch("filterdns.api.routes.settings") as mock_settings:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_settings.default_client = "default"

            response = await client.delete("/api/profiles/default")
            assert response.status_code == 403


class TestResumeFiltering:
    """Tests for resume filtering endpoint."""

    @pytest.mark.asyncio
    async def test_resume_filtering(self, client):
        """Test resuming filtering."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=now,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.resume_profile_filtering = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post("/api/profiles/testclient/resume")
            assert response.status_code == 200

            data = await response.get_json()
            assert "resumed" in data["message"]


class TestClientLogs:
    """Tests for client logs endpoint."""

    @pytest.mark.asyncio
    async def test_get_client_logs(self, client):
        """Test getting client logs."""
        from filterdns.db.models import Client, QueryLog

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_logs = [
            QueryLog(
                id=1,
                timestamp=now,
                profile_id=mock_client.id,
                domain="example.com",
                query_type="A",
                blocked=False,
                blocklist_id=None,
                response_time_ms=5,
            ),
            QueryLog(
                id=2,
                timestamp=now,
                profile_id=mock_client.id,
                domain="ads.example.com",
                query_type="A",
                blocked=True,
                blocklist_id="hagezi-multi-normal",
                response_time_ms=2,
            ),
        ]

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_query_logs = AsyncMock(return_value=mock_logs)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/logs")
            assert response.status_code == 200

            data = await response.get_json()
            assert "logs" in data
            assert len(data["logs"]) == 2
            assert data["logs"][0]["domain"] == "example.com"
            assert data["logs"][1]["blocked"] is True

    @pytest.mark.asyncio
    async def test_get_client_logs_with_filters(self, client):
        """Test getting client logs with filters."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_query_logs = AsyncMock(return_value=[])
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get(
                "/api/profiles/testclient/logs?limit=50&offset=10&blocked=true&domain=ads"
            )
            assert response.status_code == 200

            # Verify the correct filters were passed
            mock_routes_queries.get_query_logs.assert_called_once_with(
                profile_id=mock_client.id,
                limit=50,
                offset=10,
                blocked_only=True,
                domain_filter="ads",
            )


class TestClientStats:
    """Tests for client stats endpoint."""

    @pytest.mark.asyncio
    async def test_get_client_stats(self, client):
        """Test getting client statistics."""
        from filterdns.db.models import Client, ClientStats

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_stats = ClientStats(
            total_queries=1000,
            blocked_queries=250,
            allowed_queries=750,
            blocked_percentage=25.0,
            top_blocked_domains=[("ads.example.com", 100), ("tracker.example.com", 50)],
            queries_by_hour=[(0, 10), (1, 15), (2, 20)],
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_profile_stats = AsyncMock(return_value=mock_stats)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/stats")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["total_queries"] == 1000
            assert data["blocked_queries"] == 250
            assert data["blocked_percentage"] == 25.0
            assert len(data["top_blocked_domains"]) == 2


class TestListClientRules:
    """Tests for listing client rules."""

    @pytest.mark.asyncio
    async def test_list_rules(self, client):
        """Test listing client rules."""
        from filterdns.db.models import Client, ClientRule, RuleType

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_rules = [
            ClientRule(
                id=uuid4(),
                profile_id=mock_client.id,
                domain="allowed.example.com",
                rule_type=RuleType.ALLOW,
                created_at=now,
            ),
            ClientRule(
                id=uuid4(),
                profile_id=mock_client.id,
                domain="blocked.example.com",
                rule_type=RuleType.DENY,
                created_at=now,
            ),
        ]

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_profile_rules = AsyncMock(return_value=mock_rules)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/rules")
            assert response.status_code == 200

            data = await response.get_json()
            assert len(data["rules"]) == 2
            assert data["rules"][0]["domain"] == "allowed.example.com"
            assert data["rules"][0]["rule_type"] == "allow"


class TestCreateClientRule:
    """Tests for creating client rules."""

    @pytest.mark.asyncio
    async def test_create_rule_success(self, client):
        """Test creating a client rule successfully."""
        from filterdns.db.models import Client, ClientRule, RuleType

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_rule = ClientRule(
            id=uuid4(),
            profile_id=mock_client.id,
            domain="example.com",
            rule_type=RuleType.ALLOW,
            created_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.create_profile_rule = AsyncMock(return_value=mock_rule)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/rules",
                json={"domain": "example.com", "rule_type": "allow"},
            )

            assert response.status_code == 201
            data = await response.get_json()
            assert data["domain"] == "example.com"
            assert data["rule_type"] == "allow"


class TestDeleteClientRule:
    """Tests for deleting client rules."""

    @pytest.mark.asyncio
    async def test_delete_rule_success(self, client):
        """Test deleting a client rule."""
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
        rule_id = uuid4()

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.delete_profile_rule = AsyncMock(return_value=True)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete(f"/api/profiles/testclient/rules/{rule_id}")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_rule_not_found(self, client):
        """Test deleting a non-existent rule."""
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
        rule_id = uuid4()

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.delete_profile_rule = AsyncMock(return_value=False)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete(f"/api/profiles/testclient/rules/{rule_id}")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rule_invalid_id(self, client):
        """Test deleting with invalid rule ID."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete("/api/profiles/testclient/rules/not-a-uuid")
            assert response.status_code == 400


class TestLinkedDevices:
    """Tests for linked devices endpoints."""

    @pytest.mark.asyncio
    async def test_list_devices(self, client):
        """Test listing linked devices."""
        from filterdns.db.models import Client, LinkedDevice

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_devices = [
            LinkedDevice(
                id=uuid4(),
                profile_id=mock_client.id,
                ip_address="192.168.1.100",
                hostname="desktop.local",
                label="Desktop",
                created_at=now,
            ),
        ]

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.list_devices = AsyncMock(return_value=mock_devices)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/devices")
            assert response.status_code == 200

            data = await response.get_json()
            assert len(data["devices"]) == 1
            assert data["devices"][0]["ip_address"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_link_device(self, client):
        """Test linking a device."""
        from filterdns.db.models import Client, Device

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_device = Device(
            id=uuid4(),
            profile_id=mock_client.id,
            ip_address="192.168.1.100",
            name="PS5 Hall 3",
            location="Hall 3",
            created_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_device_by_ip = AsyncMock(return_value=None)
            mock_routes_queries.add_device = AsyncMock(return_value=mock_device)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/devices",
                json={"ip_address": "192.168.1.100", "name": "PS5 Hall 3", "location": "Hall 3"},
            )

            assert response.status_code == 201
            data = await response.get_json()
            assert data["ip_address"] == "192.168.1.100"
            assert data["name"] == "PS5 Hall 3"

    @pytest.mark.asyncio
    async def test_link_device_auto_ip(self, client):
        """Test linking device with auto-detected IP address."""
        from filterdns.db.models import Client, Device

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        # Device will be created with auto-detected IP
        mock_device = Device(
            id=uuid4(),
            profile_id=mock_client.id,
            ip_address="127.0.0.1",  # Auto-detected from request
            name="Kiosk 1",
            location=None,
            created_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_device_by_ip = AsyncMock(return_value=None)
            mock_routes_queries.add_device = AsyncMock(return_value=mock_device)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/devices",
                json={"name": "Kiosk 1"},  # No IP - will be auto-detected
            )

            assert response.status_code == 201
            data = await response.get_json()
            assert data["name"] == "Kiosk 1"

    @pytest.mark.asyncio
    async def test_unlink_device(self, client):
        """Test unlinking a device."""
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
        device_id = uuid4()

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.remove_device = AsyncMock(return_value=True)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete(f"/api/profiles/testclient/devices/{device_id}")
            assert response.status_code == 200


class TestProfilesAPI:
    """Tests for profiles endpoints."""

    @pytest.mark.asyncio
    async def test_list_profiles(self, client):
        """Test listing available profiles."""
        from filterdns.db.models import RestrictionProfile

        now = datetime.now(timezone.utc)
        mock_profiles = [
            RestrictionProfile(
                id="no-social",
                name="No Social Media",
                description="Blocks social media sites",
                category="productivity",
                is_builtin=True,
                created_at=now,
            ),
            RestrictionProfile(
                id="safe-search",
                name="Safe Search",
                description="Enforces safe search",
                category="family",
                is_builtin=True,
                created_at=now,
            ),
        ]

        with patch("filterdns.api.routes.queries") as mock_queries:
            mock_queries.list_presets = AsyncMock(return_value=mock_profiles)
            mock_queries.get_preset_domain_count = AsyncMock(return_value=100)

            response = await client.get("/api/presets")
            assert response.status_code == 200

            data = await response.get_json()
            assert len(data["presets"]) == 2
            assert data["presets"][0]["id"] == "no-social"

    @pytest.mark.asyncio
    async def test_get_client_profiles(self, client):
        """Test getting client's enabled profiles."""
        from filterdns.db.models import Client, RestrictionProfile

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            created_at=now,
            updated_at=now,
        )
        mock_profile = RestrictionProfile(
            id="no-social",
            name="No Social Media",
            description="Blocks social media",
            category="productivity",
            is_builtin=True,
            created_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_profile_presets = AsyncMock(return_value=["no-social"])
            mock_routes_queries.get_preset = AsyncMock(return_value=mock_profile)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/presets")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["preset_ids"] == ["no-social"]

    @pytest.mark.asyncio
    async def test_set_client_profiles(self, client):
        """Test setting client profiles."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.preset_exists = AsyncMock(return_value=True)
            mock_routes_queries.set_profile_presets = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.put(
                "/api/profiles/testclient/presets",
                json={"preset_ids": ["no-social", "safe-search"]},
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_set_client_profiles_invalid_profile(self, client):
        """Test setting client profiles with invalid profile ID."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.preset_exists = AsyncMock(return_value=False)
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.put(
                "/api/profiles/testclient/presets",
                json={"preset_ids": ["nonexistent-profile"]},
            )

            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_add_client_profile(self, client):
        """Test adding a profile to a client."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.preset_exists = AsyncMock(return_value=True)
            mock_routes_queries.add_profile_preset = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post("/api/profiles/testclient/presets/no-social")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_remove_client_profile(self, client):
        """Test removing a profile from a client."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.remove_profile_preset = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete("/api/profiles/testclient/presets/no-social")
            assert response.status_code == 200


class TestMaintenanceMode:
    """Tests for maintenance mode endpoints."""

    @pytest.mark.asyncio
    async def test_get_maintenance_status(self, client):
        """Test getting maintenance mode status."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            maintenance_mode=True,
            maintenance_allowlist=["example.com"],
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.get_maintenance_allowlist = AsyncMock(return_value=["example.com"])
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.get("/api/profiles/testclient/maintenance")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["maintenance_mode"] is True
            assert "example.com" in data["allowlist"]

    @pytest.mark.asyncio
    async def test_enable_maintenance_mode(self, client):
        """Test enabling maintenance mode."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            maintenance_mode=False,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.set_maintenance_mode = AsyncMock(return_value=mock_client)
            mock_routes_queries.set_maintenance_allowlist = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/maintenance",
                json={"allowlist": ["essential.com"]},
            )

            assert response.status_code == 200
            data = await response.get_json()
            assert data["maintenance_mode"] is True

    @pytest.mark.asyncio
    async def test_disable_maintenance_mode(self, client):
        """Test disabling maintenance mode."""
        from filterdns.db.models import Client

        now = datetime.now(timezone.utc)
        mock_client = Client(
            id=uuid4(),
            name="testclient",
            password_hash=None,
            filtering_paused_until=None,
            maintenance_mode=True,
            created_at=now,
            updated_at=now,
        )

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.set_maintenance_mode = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.delete("/api/profiles/testclient/maintenance")
            assert response.status_code == 200

            data = await response.get_json()
            assert data["maintenance_mode"] is False

    @pytest.mark.asyncio
    async def test_set_maintenance_allowlist(self, client):
        """Test setting maintenance allowlist."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.set_maintenance_allowlist = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.put(
                "/api/profiles/testclient/maintenance/allowlist",
                json={"allowlist": ["example.com", "important.org"]},
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_add_maintenance_allowlist_domain(self, client):
        """Test adding a domain to maintenance allowlist."""
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

        with patch("filterdns.api.routes.queries") as mock_routes_queries, \
             patch("filterdns.api.auth.queries") as mock_auth_queries:
            mock_routes_queries.get_profile_by_name = AsyncMock(return_value=mock_client)
            mock_routes_queries.add_maintenance_allowlist_domain = AsyncMock()
            mock_auth_queries.get_profile_by_name = AsyncMock(return_value=mock_client)

            response = await client.post(
                "/api/profiles/testclient/maintenance/allowlist",
                json={"domain": "newdomain.com"},
            )

            assert response.status_code == 200


class TestAdminLogin:
    """Tests for admin login/logout."""

    @pytest.mark.asyncio
    async def test_admin_login_success(self, client):
        """Test successful admin login."""
        with patch("filterdns.api.routes.verify_admin_password") as mock_verify:
            mock_verify.return_value = True

            response = await client.post(
                "/api/admin/login",
                json={"password": "correct-password"},
            )

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_login_failure(self, client):
        """Test failed admin login."""
        with patch("filterdns.api.routes.verify_admin_password") as mock_verify:
            mock_verify.return_value = False

            response = await client.post(
                "/api/admin/login",
                json={"password": "wrong-password"},
            )

            assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_admin_logout(self, client):
        """Test admin logout."""
        response = await client.post("/api/admin/logout")
        assert response.status_code == 200
