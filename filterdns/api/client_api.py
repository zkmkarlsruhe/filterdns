"""Client API for desktop app onboarding and sync.

This module provides endpoints for the FilterDNS desktop client to:
1. Complete web-based onboarding (receive profile info via callback)
2. Sync settings from the server
3. Report client status
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from quart import Blueprint, jsonify, request
import structlog

from filterdns.db import queries
from filterdns.config import settings

logger = structlog.get_logger()

# In-memory store for pending onboarding tokens
# In production, this should be Redis or similar
_pending_tokens: dict[str, dict[str, Any]] = {}

# Token expiry time
TOKEN_EXPIRY_MINUTES = 10


def create_client_api_blueprint() -> Blueprint:
    """Create the client API Blueprint."""
    bp = Blueprint("client_api", __name__, url_prefix="/api/client")

    @bp.route("/onboard/start", methods=["POST"])
    async def start_onboarding() -> tuple[dict[str, Any], int]:
        """Start the onboarding process.

        The desktop client calls this to get a unique token, then opens
        the browser to the onboarding page with this token.

        Returns:
            token: Unique token for this onboarding session
            onboard_url: URL to open in browser
            expires_at: When the token expires
        """
        # Generate secure token
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

        # Store pending token
        _pending_tokens[token] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "completed": False,
            "profile": None,
            "client_info": await request.get_json() or {},
        }

        # Clean up expired tokens
        _cleanup_expired_tokens()

        # Build onboard URL
        base_url = settings.public_url or f"http://localhost:{settings.port}"
        onboard_url = f"{base_url}/onboard?token={token}"

        return jsonify({
            "token": token,
            "onboard_url": onboard_url,
            "expires_at": expires_at.isoformat(),
        }), 200

    @bp.route("/onboard/complete", methods=["POST"])
    async def complete_onboarding() -> tuple[dict[str, Any], int]:
        """Complete the onboarding process.

        Called by the web UI when the user has selected/created a profile.
        This stores the profile info for the client to retrieve.

        Request body:
            token: The onboarding token
            profile_name: The selected profile name
            password: Optional password for the profile
        """
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        token = data.get("token")
        profile_name = data.get("profile_name")

        if not token:
            return jsonify({"error": "Token required"}), 400
        if not profile_name:
            return jsonify({"error": "Profile name required"}), 400

        # Validate token
        if token not in _pending_tokens:
            return jsonify({"error": "Invalid or expired token"}), 400

        token_data = _pending_tokens[token]
        expires_at = datetime.fromisoformat(token_data["expires_at"])

        if datetime.now(timezone.utc) > expires_at:
            del _pending_tokens[token]
            return jsonify({"error": "Token expired"}), 400

        # Verify profile exists
        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        # Mark as completed with profile info
        _pending_tokens[token]["completed"] = True
        _pending_tokens[token]["profile"] = {
            "id": str(profile.id),
            "name": profile.name,
            "has_password": profile.password_hash is not None,
            "dns_endpoint": f"{profile.name}.{settings.domain}",
            "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
        }
        # Store password hash for client auth (optional)
        if data.get("password"):
            _pending_tokens[token]["password"] = data.get("password")

        logger.info("Onboarding completed", profile=profile_name, token=token[:8] + "...")

        return jsonify({
            "message": "Onboarding completed",
            "profile": _pending_tokens[token]["profile"],
        }), 200

    @bp.route("/onboard/poll", methods=["GET"])
    async def poll_onboarding() -> tuple[dict[str, Any], int]:
        """Poll for onboarding completion.

        The desktop client calls this to check if the user has completed
        the web-based onboarding flow.

        Query params:
            token: The onboarding token
        """
        token = request.args.get("token")
        if not token:
            return jsonify({"error": "Token required"}), 400

        if token not in _pending_tokens:
            return jsonify({"error": "Invalid or expired token"}), 400

        token_data = _pending_tokens[token]
        expires_at = datetime.fromisoformat(token_data["expires_at"])

        if datetime.now(timezone.utc) > expires_at:
            del _pending_tokens[token]
            return jsonify({"error": "Token expired"}), 400

        if not token_data["completed"]:
            return jsonify({
                "completed": False,
                "expires_at": token_data["expires_at"],
            }), 200

        # Onboarding completed - return profile info and clean up
        result = {
            "completed": True,
            "profile": token_data["profile"],
        }
        if token_data.get("password"):
            result["password"] = token_data["password"]

        # Clean up token after successful retrieval
        del _pending_tokens[token]

        return jsonify(result), 200

    @bp.route("/sync/<profile_name>", methods=["GET"])
    async def sync_profile(profile_name: str) -> tuple[dict[str, Any], int]:
        """Get current profile state for client sync.

        The desktop client polls this endpoint to get the current
        profile configuration and state.

        Returns:
            - filtering_enabled: Whether filtering is active
            - paused_until: If paused, when it resumes
            - blocklists: List of enabled blocklist IDs
            - server_url: Current server URL
        """
        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        blocklist_ids = await queries.get_profile_blocklists(profile.id)

        return jsonify({
            "profile": {
                "id": str(profile.id),
                "name": profile.name,
                "filtering_enabled": not profile.is_filtering_paused,
                "paused_until": (
                    profile.filtering_paused_until.isoformat() + "Z"
                    if profile.filtering_paused_until
                    else None
                ),
                "maintenance_mode": profile.maintenance_mode,
                "blocklist_count": len(blocklist_ids),
            },
            "dns": {
                "endpoint": f"{profile.name}.{settings.domain}",
                "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
                "dot_hostname": f"{profile.name}.{settings.domain}",
            },
            "server_version": "1.0.0",
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }), 200

    @bp.route("/status", methods=["POST"])
    async def report_status() -> tuple[dict[str, Any], int]:
        """Report client status to server.

        The desktop client periodically reports its status.
        This can be used for diagnostics and to track active clients.

        Request body:
            profile_name: Current profile
            enabled: Whether DNS filtering is active locally
            version: Client version
            os: Operating system
        """
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Log client status (could store in DB for diagnostics)
        logger.info(
            "Client status report",
            profile=data.get("profile_name"),
            enabled=data.get("enabled"),
            version=data.get("version"),
            os=data.get("os"),
        )

        return jsonify({"message": "Status received"}), 200

    return bp


def _cleanup_expired_tokens() -> None:
    """Remove expired onboarding tokens."""
    now = datetime.now(timezone.utc)
    expired = [
        token for token, data in _pending_tokens.items()
        if datetime.fromisoformat(data["expires_at"]) < now
    ]
    for token in expired:
        del _pending_tokens[token]
