"""Tests for the REST API."""

import pytest
from filterdns.app import create_app


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


class TestBlocklistsEndpoint:
    """Tests for blocklists endpoint."""

    @pytest.mark.asyncio
    async def test_list_blocklists(self, client):
        """Test listing available blocklists."""
        response = await client.get("/api/blocklists")
        assert response.status_code == 200
        data = await response.get_json()
        assert "blocklists" in data
