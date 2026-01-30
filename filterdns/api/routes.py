"""REST API routes for FilterDNS.

Naming convention (museum-focused):
- Profile: DNS filtering configuration (e.g., "ps5-gaming-exhibition")
- Device: Individual machine using a profile (e.g., PS5 in Hall 3)
- Preset: Predefined blocking rule set (e.g., "block-social-media")
"""

import asyncio
import ipaddress
import json
from datetime import datetime
from typing import Any, AsyncGenerator
from uuid import UUID

from quart import Blueprint, Response, jsonify, make_response, request, session
import structlog

logger = structlog.get_logger()


def get_client_ip() -> str | None:
    """Extract and validate client IP address from request.

    Returns None if IP cannot be determined or is invalid.
    """
    # Try X-Forwarded-For first (for proxied requests)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain (original client)
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.remote_addr

    if not ip:
        return None

    # Validate IP address format
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        logger.warning("Invalid IP address in request", ip=ip)
        return None


def parse_int_param(value: str | None, default: int, min_val: int = 0, max_val: int | None = None) -> int:
    """Safely parse integer parameter with bounds checking."""
    if value is None:
        return default
    try:
        result = int(value)
        result = max(result, min_val)
        if max_val is not None:
            result = min(result, max_val)
        return result
    except (ValueError, TypeError):
        return default

from filterdns.api.auth import (
    admin_required,
    generate_profile_token,
    profile_auth_optional,
    revoke_profile_token,
    verify_admin_password,
)
from filterdns.blocklist.engine import get_engine
from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import (
    BlocklistCreate,
    DeviceCreate,
    Profile,
    ProfileCreate,
    ProfileRuleCreate,
    RuleType,
)
from filterdns.profiles.loader import reload_preset_in_engine, remove_preset_from_engine


def create_api_blueprint() -> Blueprint:
    """Create the API Blueprint."""
    bp = Blueprint("api", __name__, url_prefix="/api")

    # =========================================================================
    # Public API
    # =========================================================================

    @bp.route("/blocklists", methods=["GET"])
    async def list_blocklists() -> tuple[dict[str, Any], int]:
        """List available blocklists."""
        blocklists = await queries.list_blocklists()
        return jsonify(
            {
                "blocklists": [
                    {
                        "id": bl.id,
                        "name": bl.name,
                        "url": bl.url,
                        "description": bl.description,
                        "category": bl.category,
                        "domain_count": bl.domain_count,
                        "last_updated": bl.last_updated.isoformat() if bl.last_updated else None,
                        "enabled": bl.enabled,
                    }
                    for bl in blocklists
                ]
            }
        ), 200

    @bp.route("/profiles", methods=["POST"])
    async def create_profile() -> tuple[dict[str, Any], int]:
        """Create a new profile (self-service)."""
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        name = data.get("name", "").strip().lower()
        if not name:
            return jsonify({"error": "Profile name required"}), 400

        # Validate name format (DNS subdomain rules)
        if not name.replace("-", "").isalnum() or name.startswith("-") or name.endswith("-"):
            return jsonify(
                {"error": "Invalid name. Use lowercase letters, numbers, and hyphens."}
            ), 400

        if len(name) > 63:
            return jsonify({"error": "Name too long (max 63 characters)"}), 400

        # Check if name already exists
        existing = await queries.get_profile_by_name(name)
        if existing:
            return jsonify({"error": "Profile name already taken"}), 409

        try:
            profile = await queries.create_profile(
                ProfileCreate(name=name, password=data.get("password"), description=data.get("description"))
            )

            # Set default blocklists from admin settings
            default_blocklists = await queries.get_default_blocklists()
            for blocklist_id in default_blocklists:
                await queries.add_profile_blocklist(profile.id, blocklist_id)

            return jsonify(
                {
                    "id": str(profile.id),
                    "name": profile.name,
                    "description": profile.description,
                    "dns_endpoint": f"{profile.name}.{settings.domain}",
                    "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
                    "dot_hostname": f"{profile.name}.{settings.domain}",
                    "has_password": profile.password_hash is not None,
                    "created_at": profile.created_at.isoformat(),
                }
            ), 201
        except Exception as e:
            logger.error("Profile creation failed", error=str(e), exc_info=True)
            return jsonify({"error": "Failed to create profile"}), 500

    @bp.route("/profiles/<profile_name>/login", methods=["POST"])
    async def profile_login(profile_name: str) -> tuple[dict[str, Any], int]:
        """Authenticate to a profile and receive an access token.

        This endpoint verifies the password and returns a secure token
        that can be used for subsequent API requests.
        """
        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        # If profile has no password, return error (use direct access)
        if not profile.password_hash:
            return jsonify({"error": "Profile has no password set"}), 400

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        password = data.get("password", "")
        if not password:
            return jsonify({"error": "Password required"}), 400

        # Verify password
        import bcrypt
        if not bcrypt.checkpw(password.encode(), profile.password_hash.encode()):
            return jsonify({"error": "Invalid password"}), 401

        # Generate secure token
        token = generate_profile_token(profile.id)

        return jsonify({
            "token": token,
            "expires_in": 3600,  # 1 hour
            "profile_id": str(profile.id),
        }), 200

    @bp.route("/profiles/<profile_name>/logout", methods=["POST"])
    async def profile_logout(profile_name: str) -> tuple[dict[str, Any], int]:
        """Revoke the current access token."""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            revoke_profile_token(token)

        # Also clear session
        profile = await queries.get_profile_by_name(profile_name)
        if profile:
            session.pop(f"profile_{profile.id}", None)

        return jsonify({"message": "Logged out"}), 200

    # =========================================================================
    # Device Onboarding API
    # =========================================================================

    @bp.route("/join/<profile_name>", methods=["GET"])
    async def get_join_info(profile_name: str) -> tuple[dict[str, Any], int]:
        """Get profile info for device onboarding.

        This endpoint is used when a device visits the profile page
        to see profile details before joining.
        """
        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        # Get current device IP
        device_ip = get_client_ip()

        # Check if this device is already linked to this profile
        existing_device = None
        if device_ip:
            existing_device = await queries.get_device_by_ip(profile.id, device_ip)

        # Get device count for this profile
        devices = await queries.list_devices(profile.id)

        return jsonify(
            {
                "profile": {
                    "id": str(profile.id),
                    "name": profile.name,
                    "description": profile.description,
                    "dns_endpoint": f"{profile.name}.{settings.domain}",
                    "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
                    "dot_hostname": f"{profile.name}.{settings.domain}",
                    "device_count": len(devices),
                },
                "current_device": {
                    "ip_address": device_ip,
                    "already_joined": existing_device is not None,
                    "device_id": str(existing_device.id) if existing_device else None,
                    "device_name": existing_device.name if existing_device else None,
                },
            }
        ), 200

    @bp.route("/join/<profile_name>", methods=["POST"])
    async def join_profile(profile_name: str) -> tuple[dict[str, Any], int]:
        """Add current device to a profile.

        This is the main onboarding endpoint. A device visits a profile page
        and clicks "Add this device" to join.
        """
        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        # Get current device IP
        device_ip = get_client_ip()
        if not device_ip:
            return jsonify({"error": "Cannot determine device IP address"}), 400

        # Check for duplicate
        existing_device = await queries.get_device_by_ip(profile.id, device_ip)
        if existing_device:
            return jsonify({
                "error": "Device already joined",
                "device": {
                    "id": str(existing_device.id),
                    "name": existing_device.name,
                    "ip_address": existing_device.ip_address,
                    "location": existing_device.location,
                }
            }), 409

        # Get optional device info from request body
        data = await request.get_json() or {}
        device_name = data.get("name")
        location = data.get("location")

        # Add device to profile
        device = await queries.add_device(
            profile.id,
            DeviceCreate(
                name=device_name,
                ip_address=device_ip,
                location=location,
            ),
        )

        return jsonify(
            {
                "message": "Device added to profile",
                "device": {
                    "id": str(device.id),
                    "name": device.name,
                    "ip_address": device.ip_address,
                    "location": device.location,
                    "created_at": device.created_at.isoformat(),
                },
                "profile": {
                    "name": profile.name,
                    "dns_endpoint": f"{profile.name}.{settings.domain}",
                    "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
                    "dot_hostname": f"{profile.name}.{settings.domain}",
                },
                "next_steps": [
                    f"Configure your DNS to use {profile.name}.{settings.domain}",
                    "Or use DNS-over-HTTPS (DoH) for encrypted DNS",
                ],
            }
        ), 201

    # =========================================================================
    # Profile API (per-profile, optional password auth)
    # =========================================================================

    @bp.route("/profiles/<profile_name>", methods=["GET"])
    @profile_auth_optional
    async def get_profile(profile_name: str, profile: Profile = None) -> tuple[dict[str, Any], int]:
        """Get profile configuration and stats."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        blocklist_ids = await queries.get_profile_blocklists(profile.id)
        rules = await queries.get_profile_rules(profile.id)
        stats = await queries.get_profile_stats(profile.id)
        preset_ids = await queries.get_profile_presets(profile.id)

        return jsonify(
            {
                "id": str(profile.id),
                "name": profile.name,
                "description": profile.description,
                "dns_endpoint": f"{profile.name}.{settings.domain}",
                "doh_url": f"https://{profile.name}.{settings.domain}/dns-query",
                "dot_hostname": f"{profile.name}.{settings.domain}",
                "has_password": profile.password_hash is not None,
                "filtering_paused_until": (
                    profile.filtering_paused_until.isoformat() + "Z"
                    if profile.filtering_paused_until
                    else None
                ),
                "is_filtering_paused": profile.is_filtering_paused,
                "maintenance_mode": profile.maintenance_mode,
                "maintenance_allowlist": list(profile.maintenance_allowlist) if profile.maintenance_allowlist else [],
                "blocklists": blocklist_ids,
                "presets": preset_ids,
                "rules": [
                    {
                        "id": str(r.id),
                        "domain": r.domain,
                        "rule_type": r.rule_type.value,
                    }
                    for r in rules
                ],
                "stats": {
                    "total_queries": stats.total_queries,
                    "blocked_queries": stats.blocked_queries,
                    "blocked_percentage": round(stats.blocked_percentage, 1),
                    "top_blocked_domains": [
                        {"domain": d, "count": c, "blocklist_id": bl_id}
                        for d, c, bl_id in stats.top_blocked_domains[:5]
                    ],
                },
                "created_at": profile.created_at.isoformat(),
            }
        ), 200

    @bp.route("/profiles/<profile_name>", methods=["PUT"])
    @profile_auth_optional
    async def update_profile(profile_name: str, profile: Profile = None) -> tuple[dict[str, Any], int]:
        """Update profile settings."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Update password
        if "password" in data:
            await queries.update_profile_password(profile.id, data.get("password"))

        # Update blocklists
        if "blocklists" in data:
            await queries.set_profile_blocklists(profile.id, data["blocklists"])

        # Update description
        if "description" in data:
            await queries.update_profile_description(profile.id, data["description"])

        return jsonify({"message": "Profile updated"}), 200

    @bp.route("/profiles/<profile_name>", methods=["DELETE"])
    @profile_auth_optional
    async def delete_profile(profile_name: str, profile: Profile = None) -> tuple[dict[str, Any], int]:
        """Delete a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        # Don't allow deleting the default profile
        if profile.name == settings.default_client:
            return jsonify({"error": "Cannot delete the default profile"}), 403

        await queries.delete_profile(profile.id)
        return jsonify({"message": "Profile deleted"}), 200

    @bp.route("/profiles/<profile_name>/pause", methods=["POST"])
    @profile_auth_optional
    async def pause_filtering(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Pause filtering for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json() or {}
        minutes = data.get("minutes", 5)

        if minutes not in [5, 15, 30, 60]:
            return jsonify({"error": "Minutes must be 5, 15, 30, or 60"}), 400

        updated = await queries.pause_profile_filtering(profile.id, minutes)
        return jsonify(
            {
                "message": f"Filtering paused for {minutes} minutes",
                "paused_until": (
                    updated.filtering_paused_until.isoformat() + "Z" if updated else None
                ),
            }
        ), 200

    @bp.route("/profiles/<profile_name>/resume", methods=["POST"])
    @profile_auth_optional
    async def resume_filtering(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Resume filtering for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        await queries.resume_profile_filtering(profile.id)
        return jsonify({"message": "Filtering resumed"}), 200

    @bp.route("/profiles/<profile_name>/logs", methods=["GET"])
    @profile_auth_optional
    async def get_profile_logs(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Get query logs for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        limit = parse_int_param(request.args.get("limit"), default=100, min_val=1, max_val=1000)
        offset = parse_int_param(request.args.get("offset"), default=0, min_val=0)
        blocked_only = request.args.get("blocked", "").lower() == "true"
        domain_filter = request.args.get("domain")

        logs = await queries.get_query_logs(
            profile_id=profile.id,
            limit=limit,
            offset=offset,
            blocked_only=blocked_only,
            domain_filter=domain_filter,
        )

        return jsonify(
            {
                "logs": [
                    {
                        "timestamp": log.timestamp.isoformat(),
                        "domain": log.domain,
                        "query_type": log.query_type,
                        "blocked": log.blocked,
                        "blocklist_id": log.blocklist_id,
                        "response_time_ms": log.response_time_ms,
                    }
                    for log in logs
                ],
                "limit": limit,
                "offset": offset,
            }
        ), 200

    @bp.route("/profiles/<profile_name>/logs/stream", methods=["GET"])
    @profile_auth_optional
    async def stream_profile_logs(
        profile_name: str, profile: Profile = None
    ) -> Response:
        """Stream query logs for a profile via Server-Sent Events (SSE).

        Query parameters:
        - blocked_only: Only stream blocked queries (default: false)
        """
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        blocked_only = request.args.get("blocked", "").lower() == "true"

        async def generate_sse() -> AsyncGenerator[str, None]:
            """Generate SSE events for new log entries."""
            last_timestamp: datetime | None = None

            while True:
                try:
                    # Check if client disconnected to avoid infinite polling
                    # This is more reliable than relying solely on CancelledError
                    if await request.is_disconnected:
                        logger.debug("SSE client disconnected", profile_id=str(profile.id))
                        break

                    # Get recent logs since last check
                    logs = await queries.get_query_logs(
                        profile_id=profile.id,
                        limit=50,
                        offset=0,
                        blocked_only=blocked_only,
                    )

                    # Filter to only new logs
                    new_logs = []
                    for log in reversed(logs):  # Process oldest first
                        if last_timestamp is None or log.timestamp > last_timestamp:
                            new_logs.append(log)
                            last_timestamp = log.timestamp

                    # Send new log events
                    for log in new_logs:
                        event_data = {
                            "timestamp": log.timestamp.isoformat(),
                            "domain": log.domain,
                            "query_type": log.query_type,
                            "blocked": log.blocked,
                            "blocklist_id": log.blocklist_id,
                            "response_time_ms": log.response_time_ms,
                        }
                        yield f"event: log\ndata: {json.dumps(event_data)}\n\n"

                    # Send keepalive comment every iteration
                    yield ": keepalive\n\n"

                    # Wait before next check
                    await asyncio.sleep(1)

                except asyncio.CancelledError:
                    logger.debug("SSE stream cancelled", profile_id=str(profile.id))
                    break
                except Exception as e:
                    # Log error but send generic message to client
                    logger.error("SSE stream error", error=str(e), exc_info=True)
                    yield f"event: error\ndata: {json.dumps({'error': 'Stream error'})}\n\n"
                    await asyncio.sleep(5)  # Wait longer on error

        response = await make_response(generate_sse())
        response.headers["Content-Type"] = "text/event-stream"
        response.headers["Cache-Control"] = "no-cache"
        response.headers["Connection"] = "keep-alive"
        response.headers["X-Accel-Buffering"] = "no"  # Disable nginx/traefik buffering
        return response

    @bp.route("/profiles/<profile_name>/stats", methods=["GET"])
    @profile_auth_optional
    async def get_profile_stats(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Get statistics for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        hours = parse_int_param(request.args.get("hours"), default=24, min_val=1, max_val=168)  # Max 7 days
        stats = await queries.get_profile_stats(profile.id, hours)

        # Get blocklist info for displaying names/categories
        all_blocklists = await queries.list_blocklists()
        blocklist_map = {bl.id: {"name": bl.name, "category": bl.category} for bl in all_blocklists}

        return jsonify(
            {
                "hours": hours,
                "total_queries": stats.total_queries,
                "blocked_queries": stats.blocked_queries,
                "allowed_queries": stats.allowed_queries,
                "blocked_percentage": round(stats.blocked_percentage, 1),
                "avg_response_time_ms": stats.avg_response_time_ms,
                "top_blocked_domains": [
                    {
                        "domain": d,
                        "count": c,
                        "blocklist_id": bl_id,
                        "blocklist_name": blocklist_map.get(bl_id, {}).get("name") if bl_id else None,
                        "blocklist_category": blocklist_map.get(bl_id, {}).get("category") if bl_id else None,
                    }
                    for d, c, bl_id in stats.top_blocked_domains
                ],
                "top_allowed_domains": [
                    {"domain": d, "count": c} for d, c in stats.top_allowed_domains
                ],
                "queries_by_hour": [{"hour": h, "count": c} for h, c in stats.queries_by_hour],
                "top_blocklists": [
                    {
                        "blocklist_id": b,
                        "name": blocklist_map.get(b, {}).get("name", b),
                        "category": blocklist_map.get(b, {}).get("category"),
                        "count": c,
                    }
                    for b, c in stats.top_blocklists
                ],
            }
        ), 200

    # =========================================================================
    # Profile Rules API
    # =========================================================================

    @bp.route("/profiles/<profile_name>/rules", methods=["GET"])
    @profile_auth_optional
    async def list_profile_rules(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """List custom rules for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        rules = await queries.get_profile_rules(profile.id)
        return jsonify(
            {
                "rules": [
                    {
                        "id": str(r.id),
                        "domain": r.domain,
                        "rule_type": r.rule_type.value,
                        "created_at": r.created_at.isoformat(),
                    }
                    for r in rules
                ]
            }
        ), 200

    @bp.route("/profiles/<profile_name>/rules", methods=["POST"])
    @profile_auth_optional
    async def create_profile_rule(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Create a custom rule for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        domain = data.get("domain", "").strip().lower()
        rule_type = data.get("rule_type", "").lower()

        if not domain:
            return jsonify({"error": "Domain required"}), 400
        if rule_type not in ["allow", "deny"]:
            return jsonify({"error": "rule_type must be 'allow' or 'deny'"}), 400

        rule = await queries.create_profile_rule(
            profile.id,
            ProfileRuleCreate(
                domain=domain,
                rule_type=RuleType.ALLOW if rule_type == "allow" else RuleType.DENY,
            ),
        )

        return jsonify(
            {
                "id": str(rule.id),
                "domain": rule.domain,
                "rule_type": rule.rule_type.value,
                "created_at": rule.created_at.isoformat(),
            }
        ), 201

    @bp.route("/profiles/<profile_name>/rules/<rule_id>", methods=["DELETE"])
    @profile_auth_optional
    async def delete_profile_rule(
        profile_name: str, rule_id: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Delete a custom rule."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        try:
            rule_uuid = UUID(rule_id)
        except ValueError:
            return jsonify({"error": "Invalid rule ID"}), 400

        deleted = await queries.delete_profile_rule(rule_uuid)
        if not deleted:
            return jsonify({"error": "Rule not found"}), 404

        return jsonify({"message": "Rule deleted"}), 200

    # =========================================================================
    # Devices API (devices linked to profiles)
    # =========================================================================

    @bp.route("/profiles/<profile_name>/devices", methods=["GET"])
    @profile_auth_optional
    async def list_devices(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """List devices linked to a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        devices = await queries.list_devices(profile.id)
        return jsonify(
            {
                "devices": [
                    {
                        "id": str(d.id),
                        "name": d.name,
                        "ip_address": d.ip_address,
                        "hostname": d.hostname,
                        "location": d.location,
                        "created_at": d.created_at.isoformat(),
                    }
                    for d in devices
                ]
            }
        ), 200

    @bp.route("/profiles/<profile_name>/devices", methods=["POST"])
    @profile_auth_optional
    async def add_device(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Add a device to a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json() or {}

        # Get IP from request body or auto-detect
        ip_address = data.get("ip_address", "").strip()
        if not ip_address:
            ip_address = get_client_ip()

        # Validate IP address
        if not ip_address:
            return jsonify({"error": "Cannot determine device IP address"}), 400
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({"error": "Invalid IP address format"}), 400

        # Check for duplicate
        existing = await queries.get_device_by_ip(profile.id, ip_address)
        if existing:
            return jsonify({"error": "Device with this IP already exists in profile"}), 409

        device = await queries.add_device(
            profile.id,
            DeviceCreate(
                name=data.get("name"),
                ip_address=ip_address,
                location=data.get("location"),
            ),
        )

        return jsonify(
            {
                "id": str(device.id),
                "name": device.name,
                "ip_address": device.ip_address,
                "location": device.location,
                "created_at": device.created_at.isoformat(),
            }
        ), 201

    @bp.route("/profiles/<profile_name>/devices/<device_id>", methods=["PUT"])
    @profile_auth_optional
    async def update_device(
        profile_name: str, device_id: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Update a device's name or location."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        try:
            device_uuid = UUID(device_id)
        except ValueError:
            return jsonify({"error": "Invalid device ID"}), 400

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        device = await queries.update_device(
            device_uuid,
            name=data.get("name"),
            location=data.get("location"),
        )
        if not device:
            return jsonify({"error": "Device not found"}), 404

        return jsonify(
            {
                "id": str(device.id),
                "name": device.name,
                "ip_address": device.ip_address,
                "location": device.location,
            }
        ), 200

    @bp.route("/profiles/<profile_name>/devices/<device_id>", methods=["DELETE"])
    @profile_auth_optional
    async def remove_device(
        profile_name: str, device_id: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Remove a device from a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        try:
            device_uuid = UUID(device_id)
        except ValueError:
            return jsonify({"error": "Invalid device ID"}), 400

        deleted = await queries.remove_device(device_uuid)
        if not deleted:
            return jsonify({"error": "Device not found"}), 404

        return jsonify({"message": "Device removed"}), 200

    @bp.route("/whoami", methods=["GET"])
    async def whoami() -> tuple[dict[str, Any], int]:
        """Detect current device (IP and PTR hostname)."""
        device_ip = get_client_ip()
        if not device_ip:
            return jsonify({"error": "Cannot determine device IP address"}), 400

        # Try to get hostname via PTR
        from filterdns.dns.resolver import get_resolver

        hostname = await get_resolver().reverse_lookup(device_ip)

        # Check if IP is already linked to any profile
        linked_profile = await queries.get_profile_by_device_ip(device_ip)

        return jsonify(
            {
                "ip_address": device_ip,
                "hostname": hostname,
                "linked_to": linked_profile.name if linked_profile else None,
                "profile_id": str(linked_profile.id) if linked_profile else None,
            }
        ), 200

    # =========================================================================
    # Presets API (Public - list all presets, formerly restriction profiles)
    # =========================================================================

    @bp.route("/presets", methods=["GET"])
    async def list_presets() -> tuple[dict[str, Any], int]:
        """List all available presets (predefined blocking rule sets)."""
        presets = await queries.list_presets()
        result = []

        for p in presets:
            domain_count = await queries.get_preset_domain_count(p.id)
            result.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "category": p.category,
                    "is_builtin": p.is_builtin,
                    "domain_count": domain_count,
                }
            )

        return jsonify({"presets": result}), 200

    # =========================================================================
    # Profile Presets API (presets enabled for a profile)
    # =========================================================================

    @bp.route("/profiles/<profile_name>/presets", methods=["GET"])
    @profile_auth_optional
    async def get_profile_presets(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Get presets enabled for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        preset_ids = await queries.get_profile_presets(profile.id)

        # Get preset details
        presets = []
        for pid in preset_ids:
            preset = await queries.get_preset(pid)
            if preset:
                presets.append(
                    {
                        "id": preset.id,
                        "name": preset.name,
                        "category": preset.category,
                    }
                )

        return jsonify({"presets": presets, "preset_ids": preset_ids}), 200

    @bp.route("/profiles/<profile_name>/presets", methods=["PUT"])
    @profile_auth_optional
    async def set_profile_presets(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Set presets for a profile (replaces existing)."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        preset_ids = data.get("preset_ids", [])
        if not isinstance(preset_ids, list):
            return jsonify({"error": "preset_ids must be a list"}), 400

        # Validate all preset IDs exist
        for pid in preset_ids:
            if not await queries.preset_exists(pid):
                return jsonify({"error": f"Preset not found: {pid}"}), 404

        await queries.set_profile_presets(profile.id, preset_ids)
        return jsonify({"message": "Presets updated", "preset_ids": preset_ids}), 200

    @bp.route("/profiles/<profile_name>/presets/<preset_id>", methods=["POST"])
    @profile_auth_optional
    async def add_profile_preset(
        profile_name: str, preset_id: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Add a preset to a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        if not await queries.preset_exists(preset_id):
            return jsonify({"error": "Preset not found"}), 404

        await queries.add_profile_preset(profile.id, preset_id)
        return jsonify({"message": f"Preset {preset_id} added"}), 200

    @bp.route("/profiles/<profile_name>/presets/<preset_id>", methods=["DELETE"])
    @profile_auth_optional
    async def remove_profile_preset(
        profile_name: str, preset_id: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Remove a preset from a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        await queries.remove_profile_preset(profile.id, preset_id)
        return jsonify({"message": f"Preset {preset_id} removed"}), 200

    # =========================================================================
    # Maintenance Mode API
    # =========================================================================

    @bp.route("/profiles/<profile_name>/maintenance", methods=["GET"])
    @profile_auth_optional
    async def get_maintenance_status(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Get maintenance mode status for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        allowlist = await queries.get_maintenance_allowlist(profile.id)

        return jsonify(
            {
                "maintenance_mode": profile.maintenance_mode,
                "allowlist": allowlist,
            }
        ), 200

    @bp.route("/profiles/<profile_name>/maintenance", methods=["POST"])
    @profile_auth_optional
    async def enable_maintenance_mode(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Enable maintenance mode for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json() or {}
        initial_allowlist = data.get("allowlist", [])

        # Enable maintenance mode
        await queries.set_maintenance_mode(profile.id, True)

        # Set initial allowlist if provided
        if initial_allowlist:
            await queries.set_maintenance_allowlist(profile.id, initial_allowlist)

        return jsonify(
            {
                "message": "Maintenance mode enabled",
                "maintenance_mode": True,
                "allowlist": initial_allowlist,
            }
        ), 200

    @bp.route("/profiles/<profile_name>/maintenance", methods=["DELETE"])
    @profile_auth_optional
    async def disable_maintenance_mode(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Disable maintenance mode for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        await queries.set_maintenance_mode(profile.id, False)

        return jsonify(
            {
                "message": "Maintenance mode disabled",
                "maintenance_mode": False,
            }
        ), 200

    @bp.route("/profiles/<profile_name>/maintenance/allowlist", methods=["GET"])
    @profile_auth_optional
    async def get_maintenance_allowlist(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Get the maintenance mode allowlist for a profile."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        allowlist = await queries.get_maintenance_allowlist(profile.id)

        return jsonify({"allowlist": allowlist}), 200

    @bp.route("/profiles/<profile_name>/maintenance/allowlist", methods=["PUT"])
    @profile_auth_optional
    async def set_maintenance_allowlist(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Set the maintenance mode allowlist for a profile (replaces existing)."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        allowlist = data.get("allowlist", [])
        if not isinstance(allowlist, list):
            return jsonify({"error": "allowlist must be a list of domains"}), 400

        await queries.set_maintenance_allowlist(profile.id, allowlist)

        return jsonify({"message": "Allowlist updated", "allowlist": allowlist}), 200

    @bp.route("/profiles/<profile_name>/maintenance/allowlist", methods=["POST"])
    @profile_auth_optional
    async def add_maintenance_allowlist_domain(
        profile_name: str, profile: Profile = None
    ) -> tuple[dict[str, Any], int]:
        """Add a domain to the maintenance mode allowlist."""
        if not profile:
            profile = await queries.get_profile_by_name(profile_name)
            if not profile:
                return jsonify({"error": "Profile not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"error": "domain required"}), 400

        await queries.add_maintenance_allowlist_domain(profile.id, domain)

        return jsonify({"message": f"Domain {domain} added to allowlist"}), 200

    # =========================================================================
    # Admin API
    # =========================================================================

    @bp.route("/admin/login", methods=["POST"])
    async def admin_login() -> tuple[dict[str, Any], int]:
        """Admin login."""
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        password = data.get("password", "")
        if await verify_admin_password(password):
            session["is_admin"] = True
            return jsonify({"message": "Logged in"}), 200

        return jsonify({"error": "Invalid password"}), 401

    @bp.route("/admin/logout", methods=["POST"])
    async def admin_logout() -> tuple[dict[str, Any], int]:
        """Admin logout."""
        session.pop("is_admin", None)
        return jsonify({"message": "Logged out"}), 200

    @bp.route("/admin/profiles", methods=["GET"])
    @admin_required
    async def admin_list_profiles() -> tuple[dict[str, Any], int]:
        """List all profiles (admin only)."""
        profiles = await queries.list_profiles()
        result = []

        for p in profiles:
            stats = await queries.get_profile_stats(p.id)
            devices = await queries.list_devices(p.id)
            result.append(
                {
                    "id": str(p.id),
                    "name": p.name,
                    "description": p.description,
                    "has_password": p.password_hash is not None,
                    "is_filtering_paused": p.is_filtering_paused,
                    "maintenance_mode": p.maintenance_mode,
                    "device_count": len(devices),
                    "total_queries_24h": stats.total_queries,
                    "blocked_percentage": round(stats.blocked_percentage, 1),
                    "created_at": p.created_at.isoformat(),
                }
            )

        return jsonify({"profiles": result}), 200

    @bp.route("/admin/stats", methods=["GET"])
    @admin_required
    async def admin_stats() -> tuple[dict[str, Any], int]:
        """Get global statistics (admin only)."""
        stats = await queries.get_global_stats()
        engine = get_engine()

        return jsonify(
            {
                "total_profiles": stats.total_profiles,
                "total_devices": stats.total_devices,
                "total_queries_today": stats.total_queries_today,
                "total_blocked_today": stats.total_blocked_today,
                "blocked_percentage": (
                    round(stats.total_blocked_today / stats.total_queries_today * 100, 1)
                    if stats.total_queries_today > 0
                    else 0
                ),
                "active_blocklists": stats.active_blocklists,
                "total_blocked_domains": engine.get_total_domains(),
                "loaded_blocklists": engine.get_blocklist_ids(),
            }
        ), 200

    @bp.route("/admin/blocklists", methods=["POST"])
    @admin_required
    async def admin_add_blocklist() -> tuple[dict[str, Any], int]:
        """Add a new blocklist source (admin only)."""
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        try:
            blocklist = await queries.create_blocklist(
                BlocklistCreate(
                    id=data["id"],
                    name=data["name"],
                    url=data["url"],
                    description=data.get("description"),
                    category=data.get("category"),
                )
            )

            return jsonify(
                {
                    "id": blocklist.id,
                    "name": blocklist.name,
                    "url": blocklist.url,
                }
            ), 201
        except Exception as e:
            logger.warning("Blocklist creation failed", error=str(e))
            # Check for common errors
            error_msg = str(e).lower()
            if "duplicate" in error_msg or "unique" in error_msg:
                return jsonify({"error": "A blocklist with this ID already exists"}), 400
            return jsonify({"error": "Failed to create blocklist"}), 400

    @bp.route("/admin/blocklists/<blocklist_id>", methods=["DELETE"])
    @admin_required
    async def admin_delete_blocklist(blocklist_id: str) -> tuple[dict[str, Any], int]:
        """Delete a blocklist source (admin only)."""
        deleted = await queries.delete_blocklist(blocklist_id)
        if not deleted:
            return jsonify({"error": "Blocklist not found"}), 404

        # Remove from engine
        get_engine().remove_blocklist(blocklist_id)

        return jsonify({"message": "Blocklist deleted"}), 200

    @bp.route("/admin/blocklists/<blocklist_id>/enable", methods=["POST"])
    @admin_required
    async def admin_enable_blocklist(blocklist_id: str) -> tuple[dict[str, Any], int]:
        """Enable a blocklist (admin only)."""
        result = await queries.set_blocklist_enabled(blocklist_id, True)
        if not result:
            return jsonify({"error": "Blocklist not found"}), 404
        return jsonify({"message": "Blocklist enabled"}), 200

    @bp.route("/admin/blocklists/<blocklist_id>/disable", methods=["POST"])
    @admin_required
    async def admin_disable_blocklist(blocklist_id: str) -> tuple[dict[str, Any], int]:
        """Disable a blocklist (admin only)."""
        result = await queries.set_blocklist_enabled(blocklist_id, False)
        if not result:
            return jsonify({"error": "Blocklist not found"}), 404
        return jsonify({"message": "Blocklist disabled"}), 200

    # =========================================================================
    # Admin Preset Management
    # =========================================================================

    @bp.route("/admin/presets", methods=["POST"])
    @admin_required
    async def admin_create_preset() -> tuple[dict[str, Any], int]:
        """Create a custom preset (admin only)."""
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        preset_id = data.get("id", "").strip().lower()
        name = data.get("name", "").strip()
        category = data.get("category", "").strip()
        description = data.get("description")
        domains = data.get("domains", [])

        if not preset_id:
            return jsonify({"error": "Preset ID required"}), 400
        if not name:
            return jsonify({"error": "Preset name required"}), 400
        if not category:
            return jsonify({"error": "Preset category required"}), 400

        # Validate preset_id format
        if not preset_id.replace("-", "").isalnum():
            return jsonify({"error": "Invalid preset ID. Use letters, numbers, and hyphens."}), 400

        # Check if preset already exists
        if await queries.preset_exists(preset_id):
            return jsonify({"error": "Preset ID already exists"}), 409

        try:
            # Create preset
            preset = await queries.create_preset(
                preset_id=preset_id,
                name=name,
                category=category,
                description=description,
                is_builtin=False,
            )

            # Set domains
            if domains:
                await queries.set_preset_domains(preset_id, domains)

            # Load into engine
            engine = get_engine()
            await reload_preset_in_engine(engine, preset_id)

            return jsonify(
                {
                    "id": preset.id,
                    "name": preset.name,
                    "category": preset.category,
                    "description": preset.description,
                    "domain_count": len(domains),
                }
            ), 201
        except Exception as e:
            logger.error("Preset creation failed", error=str(e), exc_info=True)
            error_msg = str(e).lower()
            if "duplicate" in error_msg or "unique" in error_msg:
                return jsonify({"error": "A preset with this ID already exists"}), 400
            return jsonify({"error": "Failed to create preset"}), 500

    @bp.route("/admin/presets/<preset_id>", methods=["GET"])
    @admin_required
    async def admin_get_preset(preset_id: str) -> tuple[dict[str, Any], int]:
        """Get a preset with its domains (admin only)."""
        preset = await queries.get_preset(preset_id)
        if not preset:
            return jsonify({"error": "Preset not found"}), 404

        domains = await queries.get_preset_domains(preset_id)

        return jsonify(
            {
                "id": preset.id,
                "name": preset.name,
                "description": preset.description,
                "category": preset.category,
                "is_builtin": preset.is_builtin,
                "domains": domains,
                "domain_count": len(domains),
            }
        ), 200

    @bp.route("/admin/presets/<preset_id>", methods=["PUT"])
    @admin_required
    async def admin_update_preset(preset_id: str) -> tuple[dict[str, Any], int]:
        """Update a preset's domains (admin only)."""
        preset = await queries.get_preset(preset_id)
        if not preset:
            return jsonify({"error": "Preset not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        domains = data.get("domains", [])
        if not isinstance(domains, list):
            return jsonify({"error": "domains must be a list"}), 400

        # Update domains
        await queries.set_preset_domains(preset_id, domains)

        # Reload in engine
        engine = get_engine()
        await reload_preset_in_engine(engine, preset_id)

        return jsonify(
            {
                "message": "Preset updated",
                "domain_count": len(domains),
            }
        ), 200

    @bp.route("/admin/presets/<preset_id>", methods=["DELETE"])
    @admin_required
    async def admin_delete_preset(preset_id: str) -> tuple[dict[str, Any], int]:
        """Delete a custom preset (admin only).

        Built-in presets cannot be deleted.
        """
        preset = await queries.get_preset(preset_id)
        if not preset:
            return jsonify({"error": "Preset not found"}), 404

        if preset.is_builtin:
            return jsonify({"error": "Cannot delete built-in presets"}), 403

        # Delete from DB
        deleted = await queries.delete_preset(preset_id)
        if not deleted:
            return jsonify({"error": "Failed to delete preset"}), 500

        # Remove from engine
        engine = get_engine()
        remove_preset_from_engine(engine, preset_id)

        return jsonify({"message": "Preset deleted"}), 200

    # =========================================================================
    # Admin Settings
    # =========================================================================

    @bp.route("/admin/settings", methods=["GET"])
    @admin_required
    async def admin_get_settings() -> tuple[dict[str, Any], int]:
        """Get all admin settings (admin only)."""
        settings_data = await queries.get_all_admin_settings()

        # Parse JSON values for known settings
        import json
        default_blocklists = []
        if "default_blocklists" in settings_data:
            try:
                default_blocklists = json.loads(settings_data["default_blocklists"])
            except json.JSONDecodeError:
                pass

        return jsonify({
            "default_blocklists": default_blocklists,
        }), 200

    @bp.route("/admin/settings", methods=["PUT"])
    @admin_required
    async def admin_update_settings() -> tuple[dict[str, Any], int]:
        """Update admin settings (admin only)."""
        data = await request.get_json()

        if "default_blocklists" in data:
            blocklist_ids = data["default_blocklists"]
            if not isinstance(blocklist_ids, list):
                return jsonify({"error": "default_blocklists must be a list"}), 400

            # Validate that all blocklists exist
            all_blocklists = await queries.list_blocklists()
            valid_ids = {bl.id for bl in all_blocklists}
            invalid = [bid for bid in blocklist_ids if bid not in valid_ids]
            if invalid:
                return jsonify({"error": f"Invalid blocklist IDs: {invalid}"}), 400

            await queries.set_default_blocklists(blocklist_ids)

        # Get updated settings
        default_blocklists = await queries.get_default_blocklists()

        return jsonify({
            "default_blocklists": default_blocklists,
            "message": "Settings updated",
        }), 200

    # =========================================================================
    # Health Check
    # =========================================================================

    @bp.route("/health", methods=["GET"])
    async def health() -> tuple[dict[str, Any], int]:
        """Health check endpoint."""
        engine = get_engine()
        return jsonify(
            {
                "status": "healthy",
                "blocklists_loaded": len(engine.get_blocklist_ids()),
                "total_blocked_domains": engine.get_total_domains(),
            }
        ), 200

    return bp
