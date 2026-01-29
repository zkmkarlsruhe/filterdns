"""REST API routes for FilterDNS."""

from typing import Any
from uuid import UUID

from quart import Blueprint, jsonify, request, session

from filterdns.api.auth import admin_required, client_auth_optional, verify_admin_password
from filterdns.blocklist.engine import get_engine
from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import (
    BlocklistCreate,
    Client,
    ClientCreate,
    ClientRuleCreate,
    LinkedDeviceCreate,
    RuleType,
)


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
                        "description": bl.description,
                        "category": bl.category,
                        "domain_count": bl.domain_count,
                        "enabled": bl.enabled,
                    }
                    for bl in blocklists
                ]
            }
        ), 200

    @bp.route("/clients", methods=["POST"])
    async def create_client() -> tuple[dict[str, Any], int]:
        """Create a new client (self-service)."""
        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        name = data.get("name", "").strip().lower()
        if not name:
            return jsonify({"error": "Client name required"}), 400

        # Validate name format (DNS subdomain rules)
        if not name.replace("-", "").isalnum() or name.startswith("-") or name.endswith("-"):
            return jsonify(
                {"error": "Invalid name. Use lowercase letters, numbers, and hyphens."}
            ), 400

        if len(name) > 63:
            return jsonify({"error": "Name too long (max 63 characters)"}), 400

        # Check if name already exists
        existing = await queries.get_client_by_name(name)
        if existing:
            return jsonify({"error": "Client name already taken"}), 409

        try:
            client = await queries.create_client(
                ClientCreate(name=name, password=data.get("password"))
            )

            # Set default blocklists (Hagezi Multi Normal)
            await queries.add_client_blocklist(client.id, "hagezi-multi-normal")

            return jsonify(
                {
                    "id": str(client.id),
                    "name": client.name,
                    "dns_endpoint": f"{client.name}.{settings.domain}",
                    "doh_url": f"https://{client.name}.{settings.domain}/dns-query",
                    "dot_hostname": f"{client.name}.{settings.domain}",
                    "has_password": client.password_hash is not None,
                    "created_at": client.created_at.isoformat(),
                }
            ), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # =========================================================================
    # Client API (per-client, optional password auth)
    # =========================================================================

    @bp.route("/clients/<client_name>", methods=["GET"])
    @client_auth_optional
    async def get_client(client_name: str, client: Client = None) -> tuple[dict[str, Any], int]:
        """Get client configuration and stats."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        blocklist_ids = await queries.get_client_blocklists(client.id)
        rules = await queries.get_client_rules(client.id)
        stats = await queries.get_client_stats(client.id)

        return jsonify(
            {
                "id": str(client.id),
                "name": client.name,
                "dns_endpoint": f"{client.name}.{settings.domain}",
                "doh_url": f"https://{client.name}.{settings.domain}/dns-query",
                "dot_hostname": f"{client.name}.{settings.domain}",
                "has_password": client.password_hash is not None,
                "filtering_paused_until": (
                    client.filtering_paused_until.isoformat()
                    if client.filtering_paused_until
                    else None
                ),
                "is_filtering_paused": client.is_filtering_paused,
                "blocklists": blocklist_ids,
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
                        {"domain": d, "count": c} for d, c in stats.top_blocked_domains[:5]
                    ],
                },
                "created_at": client.created_at.isoformat(),
            }
        ), 200

    @bp.route("/clients/<client_name>", methods=["PUT"])
    @client_auth_optional
    async def update_client(client_name: str, client: Client = None) -> tuple[dict[str, Any], int]:
        """Update client settings."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        # Update password
        if "password" in data:
            await queries.update_client_password(client.id, data.get("password"))

        # Update blocklists
        if "blocklists" in data:
            await queries.set_client_blocklists(client.id, data["blocklists"])

        return jsonify({"message": "Client updated"}), 200

    @bp.route("/clients/<client_name>", methods=["DELETE"])
    @client_auth_optional
    async def delete_client(client_name: str, client: Client = None) -> tuple[dict[str, Any], int]:
        """Delete a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        # Don't allow deleting the default client
        if client.name == settings.default_client:
            return jsonify({"error": "Cannot delete the default client"}), 403

        await queries.delete_client(client.id)
        return jsonify({"message": "Client deleted"}), 200

    @bp.route("/clients/<client_name>/pause", methods=["POST"])
    @client_auth_optional
    async def pause_filtering(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Pause filtering for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        data = await request.get_json() or {}
        minutes = data.get("minutes", 5)

        if minutes not in [5, 15, 30, 60]:
            return jsonify({"error": "Minutes must be 5, 15, 30, or 60"}), 400

        updated = await queries.pause_client_filtering(client.id, minutes)
        return jsonify(
            {
                "message": f"Filtering paused for {minutes} minutes",
                "paused_until": (
                    updated.filtering_paused_until.isoformat() if updated else None
                ),
            }
        ), 200

    @bp.route("/clients/<client_name>/resume", methods=["POST"])
    @client_auth_optional
    async def resume_filtering(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Resume filtering for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        await queries.resume_client_filtering(client.id)
        return jsonify({"message": "Filtering resumed"}), 200

    @bp.route("/clients/<client_name>/logs", methods=["GET"])
    @client_auth_optional
    async def get_client_logs(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Get query logs for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        limit = min(int(request.args.get("limit", 100)), 1000)
        offset = int(request.args.get("offset", 0))
        blocked_only = request.args.get("blocked", "").lower() == "true"
        domain_filter = request.args.get("domain")

        logs = await queries.get_query_logs(
            client_id=client.id,
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

    @bp.route("/clients/<client_name>/stats", methods=["GET"])
    @client_auth_optional
    async def get_client_stats(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Get statistics for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        hours = min(int(request.args.get("hours", 24)), 168)  # Max 7 days
        stats = await queries.get_client_stats(client.id, hours)

        return jsonify(
            {
                "hours": hours,
                "total_queries": stats.total_queries,
                "blocked_queries": stats.blocked_queries,
                "allowed_queries": stats.allowed_queries,
                "blocked_percentage": round(stats.blocked_percentage, 1),
                "top_blocked_domains": [
                    {"domain": d, "count": c} for d, c in stats.top_blocked_domains
                ],
                "queries_by_hour": [{"hour": h, "count": c} for h, c in stats.queries_by_hour],
            }
        ), 200

    # =========================================================================
    # Client Rules API
    # =========================================================================

    @bp.route("/clients/<client_name>/rules", methods=["GET"])
    @client_auth_optional
    async def list_client_rules(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """List custom rules for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        rules = await queries.get_client_rules(client.id)
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

    @bp.route("/clients/<client_name>/rules", methods=["POST"])
    @client_auth_optional
    async def create_client_rule(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Create a custom rule for a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        domain = data.get("domain", "").strip().lower()
        rule_type = data.get("rule_type", "").lower()

        if not domain:
            return jsonify({"error": "Domain required"}), 400
        if rule_type not in ["allow", "deny"]:
            return jsonify({"error": "rule_type must be 'allow' or 'deny'"}), 400

        rule = await queries.create_client_rule(
            client.id,
            ClientRuleCreate(
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

    @bp.route("/clients/<client_name>/rules/<rule_id>", methods=["DELETE"])
    @client_auth_optional
    async def delete_client_rule(
        client_name: str, rule_id: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Delete a custom rule."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        try:
            rule_uuid = UUID(rule_id)
        except ValueError:
            return jsonify({"error": "Invalid rule ID"}), 400

        deleted = await queries.delete_client_rule(rule_uuid)
        if not deleted:
            return jsonify({"error": "Rule not found"}), 404

        return jsonify({"message": "Rule deleted"}), 200

    # =========================================================================
    # Linked Devices API
    # =========================================================================

    @bp.route("/clients/<client_name>/devices", methods=["GET"])
    @client_auth_optional
    async def list_linked_devices(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """List devices linked to a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        devices = await queries.list_linked_devices(client.id)
        return jsonify(
            {
                "devices": [
                    {
                        "id": str(d.id),
                        "ip_address": d.ip_address,
                        "hostname": d.hostname,
                        "label": d.label,
                        "created_at": d.created_at.isoformat(),
                    }
                    for d in devices
                ]
            }
        ), 200

    @bp.route("/clients/<client_name>/devices", methods=["POST"])
    @client_auth_optional
    async def link_device(
        client_name: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Link a device to a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        data = await request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400

        ip_address = data.get("ip_address", "").strip()
        if not ip_address:
            return jsonify({"error": "IP address required"}), 400

        device = await queries.link_device(
            client.id,
            LinkedDeviceCreate(ip_address=ip_address, label=data.get("label")),
        )

        return jsonify(
            {
                "id": str(device.id),
                "ip_address": device.ip_address,
                "label": device.label,
                "created_at": device.created_at.isoformat(),
            }
        ), 201

    @bp.route("/clients/<client_name>/devices/<device_id>", methods=["DELETE"])
    @client_auth_optional
    async def unlink_device(
        client_name: str, device_id: str, client: Client = None
    ) -> tuple[dict[str, Any], int]:
        """Unlink a device from a client."""
        if not client:
            client = await queries.get_client_by_name(client_name)
            if not client:
                return jsonify({"error": "Client not found"}), 404

        try:
            device_uuid = UUID(device_id)
        except ValueError:
            return jsonify({"error": "Invalid device ID"}), 400

        deleted = await queries.unlink_device(device_uuid)
        if not deleted:
            return jsonify({"error": "Device not found"}), 404

        return jsonify({"message": "Device unlinked"}), 200

    @bp.route("/whoami", methods=["GET"])
    async def whoami() -> tuple[dict[str, Any], int]:
        """Detect current device (IP and PTR hostname)."""
        client_ip = request.remote_addr or "unknown"

        # Try to get hostname via PTR
        from filterdns.dns.resolver import get_resolver

        hostname = await get_resolver().reverse_lookup(client_ip)

        # Check if IP is already linked
        linked_client = await queries.get_client_by_ip(client_ip)

        return jsonify(
            {
                "ip_address": client_ip,
                "hostname": hostname,
                "linked_to": linked_client.name if linked_client else None,
            }
        ), 200

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

    @bp.route("/admin/clients", methods=["GET"])
    @admin_required
    async def admin_list_clients() -> tuple[dict[str, Any], int]:
        """List all clients (admin only)."""
        clients = await queries.list_clients()
        result = []

        for c in clients:
            stats = await queries.get_client_stats(c.id)
            result.append(
                {
                    "id": str(c.id),
                    "name": c.name,
                    "has_password": c.password_hash is not None,
                    "is_filtering_paused": c.is_filtering_paused,
                    "total_queries_24h": stats.total_queries,
                    "blocked_percentage": round(stats.blocked_percentage, 1),
                    "created_at": c.created_at.isoformat(),
                }
            )

        return jsonify({"clients": result}), 200

    @bp.route("/admin/stats", methods=["GET"])
    @admin_required
    async def admin_stats() -> tuple[dict[str, Any], int]:
        """Get global statistics (admin only)."""
        stats = await queries.get_global_stats()
        engine = get_engine()

        return jsonify(
            {
                "total_clients": stats.total_clients,
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
            return jsonify({"error": str(e)}), 400

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
