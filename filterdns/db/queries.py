"""Database queries for FilterDNS."""

from datetime import datetime, timedelta
from uuid import UUID

import asyncpg
import bcrypt
import structlog

from filterdns.db.database import get_db
from filterdns.db.models import (
    Blocklist,
    BlocklistCreate,
    Client,
    ClientCreate,
    ClientRule,
    ClientRuleCreate,
    ClientStats,
    GlobalStats,
    LinkedDevice,
    LinkedDeviceCreate,
    QueryLog,
    RuleType,
)

logger = structlog.get_logger()


# ============================================================================
# Client Operations
# ============================================================================


async def create_client(data: ClientCreate) -> Client:
    """Create a new client."""
    db = get_db()
    password_hash = None
    if data.password:
        password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    row = await db.fetchrow(
        """
        INSERT INTO clients (name, password_hash)
        VALUES ($1, $2)
        RETURNING *
        """,
        data.name,
        password_hash,
    )
    return Client(**dict(row))


async def get_client(client_id: UUID) -> Client | None:
    """Get a client by ID."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM clients WHERE id = $1", client_id)
    return Client(**dict(row)) if row else None


async def get_client_by_name(name: str) -> Client | None:
    """Get a client by name (subdomain)."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM clients WHERE name = $1", name)
    return Client(**dict(row)) if row else None


async def list_clients() -> list[Client]:
    """List all clients."""
    db = get_db()
    rows = await db.fetch("SELECT * FROM clients ORDER BY created_at DESC")
    return [Client(**dict(row)) for row in rows]


async def update_client_password(client_id: UUID, password: str | None) -> Client | None:
    """Update client password."""
    db = get_db()
    password_hash = None
    if password:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    row = await db.fetchrow(
        """
        UPDATE clients
        SET password_hash = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        client_id,
        password_hash,
    )
    return Client(**dict(row)) if row else None


async def delete_client(client_id: UUID) -> bool:
    """Delete a client."""
    db = get_db()
    result = await db.execute("DELETE FROM clients WHERE id = $1", client_id)
    return result == "DELETE 1"


async def pause_client_filtering(client_id: UUID, minutes: int) -> Client | None:
    """Pause filtering for a client."""
    db = get_db()
    pause_until = datetime.utcnow() + timedelta(minutes=minutes)
    row = await db.fetchrow(
        """
        UPDATE clients
        SET filtering_paused_until = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        client_id,
        pause_until,
    )
    return Client(**dict(row)) if row else None


async def resume_client_filtering(client_id: UUID) -> Client | None:
    """Resume filtering for a client."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE clients
        SET filtering_paused_until = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        client_id,
    )
    return Client(**dict(row)) if row else None


async def verify_client_password(client_id: UUID, password: str) -> bool:
    """Verify a client's password."""
    db = get_db()
    row = await db.fetchrow("SELECT password_hash FROM clients WHERE id = $1", client_id)
    if not row or not row["password_hash"]:
        return False
    return bcrypt.checkpw(password.encode(), row["password_hash"].encode())


# ============================================================================
# Linked Devices Operations
# ============================================================================


async def link_device(client_id: UUID, data: LinkedDeviceCreate) -> LinkedDevice:
    """Link a device to a client."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO linked_devices (client_id, ip_address, label)
        VALUES ($1, $2, $3)
        ON CONFLICT (ip_address) DO UPDATE
        SET client_id = $1, label = $3
        RETURNING *
        """,
        client_id,
        data.ip_address,
        data.label,
    )
    return LinkedDevice(**dict(row))


async def get_client_by_ip(ip_address: str) -> Client | None:
    """Get client by linked device IP."""
    db = get_db()
    row = await db.fetchrow(
        """
        SELECT c.* FROM clients c
        JOIN linked_devices d ON c.id = d.client_id
        WHERE d.ip_address = $1
        """,
        ip_address,
    )
    return Client(**dict(row)) if row else None


async def list_linked_devices(client_id: UUID) -> list[LinkedDevice]:
    """List devices linked to a client."""
    db = get_db()
    rows = await db.fetch(
        "SELECT * FROM linked_devices WHERE client_id = $1 ORDER BY created_at DESC",
        client_id,
    )
    return [LinkedDevice(**dict(row)) for row in rows]


async def unlink_device(device_id: UUID) -> bool:
    """Unlink a device."""
    db = get_db()
    result = await db.execute("DELETE FROM linked_devices WHERE id = $1", device_id)
    return result == "DELETE 1"


async def update_device_hostname(ip_address: str, hostname: str) -> None:
    """Update device hostname from PTR lookup."""
    db = get_db()
    await db.execute(
        "UPDATE linked_devices SET hostname = $2 WHERE ip_address = $1",
        ip_address,
        hostname,
    )


# ============================================================================
# Blocklist Operations
# ============================================================================


async def create_blocklist(data: BlocklistCreate) -> Blocklist:
    """Create a new blocklist."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO blocklists (id, name, url, description, category)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """,
        data.id,
        data.name,
        data.url,
        data.description,
        data.category,
    )
    return Blocklist(**dict(row))


async def get_blocklist(blocklist_id: str) -> Blocklist | None:
    """Get a blocklist by ID."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM blocklists WHERE id = $1", blocklist_id)
    return Blocklist(**dict(row)) if row else None


async def list_blocklists(enabled_only: bool = False) -> list[Blocklist]:
    """List all blocklists."""
    db = get_db()
    query = "SELECT * FROM blocklists"
    if enabled_only:
        query += " WHERE enabled = TRUE"
    query += " ORDER BY category, name"
    rows = await db.fetch(query)
    return [Blocklist(**dict(row)) for row in rows]


async def update_blocklist_stats(blocklist_id: str, domain_count: int) -> None:
    """Update blocklist domain count and last updated timestamp."""
    db = get_db()
    await db.execute(
        """
        UPDATE blocklists
        SET domain_count = $2, last_updated = CURRENT_TIMESTAMP
        WHERE id = $1
        """,
        blocklist_id,
        domain_count,
    )


async def delete_blocklist(blocklist_id: str) -> bool:
    """Delete a blocklist."""
    db = get_db()
    result = await db.execute("DELETE FROM blocklists WHERE id = $1", blocklist_id)
    return result == "DELETE 1"


async def set_blocklist_enabled(blocklist_id: str, enabled: bool) -> Blocklist | None:
    """Enable or disable a blocklist."""
    db = get_db()
    row = await db.fetchrow(
        "UPDATE blocklists SET enabled = $2 WHERE id = $1 RETURNING *",
        blocklist_id,
        enabled,
    )
    return Blocklist(**dict(row)) if row else None


# ============================================================================
# Client Blocklist Assignments
# ============================================================================


async def get_client_blocklists(client_id: UUID) -> list[str]:
    """Get blocklist IDs assigned to a client."""
    db = get_db()
    rows = await db.fetch(
        "SELECT blocklist_id FROM client_blocklists WHERE client_id = $1",
        client_id,
    )
    return [row["blocklist_id"] for row in rows]


async def set_client_blocklists(client_id: UUID, blocklist_ids: list[str]) -> None:
    """Set blocklists for a client (replaces existing)."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM client_blocklists WHERE client_id = $1", client_id)
        if blocklist_ids:
            await conn.executemany(
                "INSERT INTO client_blocklists (client_id, blocklist_id) VALUES ($1, $2)",
                [(client_id, bid) for bid in blocklist_ids],
            )


async def add_client_blocklist(client_id: UUID, blocklist_id: str) -> None:
    """Add a blocklist to a client."""
    db = get_db()
    await db.execute(
        """
        INSERT INTO client_blocklists (client_id, blocklist_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        """,
        client_id,
        blocklist_id,
    )


async def remove_client_blocklist(client_id: UUID, blocklist_id: str) -> None:
    """Remove a blocklist from a client."""
    db = get_db()
    await db.execute(
        "DELETE FROM client_blocklists WHERE client_id = $1 AND blocklist_id = $2",
        client_id,
        blocklist_id,
    )


# ============================================================================
# Client Rules Operations
# ============================================================================


async def create_client_rule(client_id: UUID, data: ClientRuleCreate) -> ClientRule:
    """Create a custom rule for a client."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO client_rules (client_id, domain, rule_type)
        VALUES ($1, $2, $3)
        RETURNING *
        """,
        client_id,
        data.domain.lower(),
        data.rule_type.value,
    )
    return ClientRule(**dict(row))


async def get_client_rules(client_id: UUID) -> list[ClientRule]:
    """Get all custom rules for a client."""
    db = get_db()
    rows = await db.fetch(
        "SELECT * FROM client_rules WHERE client_id = $1 ORDER BY created_at DESC",
        client_id,
    )
    return [ClientRule(**dict(row)) for row in rows]


async def get_client_allow_rules(client_id: UUID) -> set[str]:
    """Get allow rules for a client as a set of domains."""
    db = get_db()
    rows = await db.fetch(
        "SELECT domain FROM client_rules WHERE client_id = $1 AND rule_type = 'allow'",
        client_id,
    )
    return {row["domain"] for row in rows}


async def get_client_deny_rules(client_id: UUID) -> set[str]:
    """Get deny rules for a client as a set of domains."""
    db = get_db()
    rows = await db.fetch(
        "SELECT domain FROM client_rules WHERE client_id = $1 AND rule_type = 'deny'",
        client_id,
    )
    return {row["domain"] for row in rows}


async def delete_client_rule(rule_id: UUID) -> bool:
    """Delete a custom rule."""
    db = get_db()
    result = await db.execute("DELETE FROM client_rules WHERE id = $1", rule_id)
    return result == "DELETE 1"


# ============================================================================
# Query Logging
# ============================================================================


async def log_query(
    client_id: UUID | None,
    domain: str,
    query_type: str,
    blocked: bool,
    blocklist_id: str | None = None,
    response_time_ms: int | None = None,
) -> None:
    """Log a DNS query."""
    db = get_db()
    await db.execute(
        """
        INSERT INTO query_logs (client_id, domain, query_type, blocked, blocklist_id, response_time_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        client_id,
        domain,
        query_type,
        blocked,
        blocklist_id,
        response_time_ms,
    )


async def get_query_logs(
    client_id: UUID | None = None,
    limit: int = 100,
    offset: int = 0,
    blocked_only: bool = False,
    domain_filter: str | None = None,
) -> list[QueryLog]:
    """Get query logs with optional filtering."""
    db = get_db()
    conditions = []
    params = []
    param_idx = 1

    if client_id:
        conditions.append(f"q.client_id = ${param_idx}")
        params.append(client_id)
        param_idx += 1

    if blocked_only:
        conditions.append("q.blocked = TRUE")

    if domain_filter:
        conditions.append(f"q.domain LIKE ${param_idx}")
        params.append(f"%{domain_filter}%")
        param_idx += 1

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    query = f"""
        SELECT q.*, c.name as client_name
        FROM query_logs q
        LEFT JOIN clients c ON q.client_id = c.id
        WHERE {where_clause}
        ORDER BY q.timestamp DESC
        LIMIT ${param_idx} OFFSET ${param_idx + 1}
    """
    params.extend([limit, offset])

    rows = await db.fetch(query, *params)
    return [QueryLog(**dict(row)) for row in rows]


async def get_client_stats(client_id: UUID, hours: int = 24) -> ClientStats:
    """Get statistics for a client."""
    db = get_db()
    since = datetime.utcnow() - timedelta(hours=hours)

    # Total and blocked counts
    counts = await db.fetchrow(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM query_logs
        WHERE client_id = $1 AND timestamp > $2
        """,
        client_id,
        since,
    )

    total = counts["total"] or 0
    blocked = counts["blocked"] or 0
    allowed = total - blocked

    # Top blocked domains
    top_blocked = await db.fetch(
        """
        SELECT domain, COUNT(*) as count
        FROM query_logs
        WHERE client_id = $1 AND timestamp > $2 AND blocked = TRUE
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
        """,
        client_id,
        since,
    )

    # Queries by hour
    by_hour = await db.fetch(
        """
        SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as count
        FROM query_logs
        WHERE client_id = $1 AND timestamp > $2
        GROUP BY hour
        ORDER BY hour
        """,
        client_id,
        since,
    )

    return ClientStats(
        total_queries=total,
        blocked_queries=blocked,
        allowed_queries=allowed,
        blocked_percentage=(blocked / total * 100) if total > 0 else 0,
        top_blocked_domains=[(row["domain"], row["count"]) for row in top_blocked],
        queries_by_hour=[(row["hour"], row["count"]) for row in by_hour],
    )


async def get_global_stats() -> GlobalStats:
    """Get global statistics for admin."""
    db = get_db()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Client count
    client_count = await db.fetchval("SELECT COUNT(*) FROM clients")

    # Today's query stats
    query_stats = await db.fetchrow(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM query_logs
        WHERE timestamp > $1
        """,
        today_start,
    )

    # Active blocklists and domain count
    blocklist_stats = await db.fetchrow(
        """
        SELECT COUNT(*) as count, COALESCE(SUM(domain_count), 0) as domains
        FROM blocklists
        WHERE enabled = TRUE
        """
    )

    return GlobalStats(
        total_clients=client_count or 0,
        total_queries_today=query_stats["total"] or 0,
        total_blocked_today=query_stats["blocked"] or 0,
        active_blocklists=blocklist_stats["count"] or 0,
        total_blocked_domains=blocklist_stats["domains"] or 0,
    )


async def cleanup_old_logs(days: int) -> int:
    """Delete logs older than specified days."""
    db = get_db()
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = await db.execute("DELETE FROM query_logs WHERE timestamp < $1", cutoff)
    count = int(result.split()[-1]) if result else 0
    logger.info("Cleaned up old query logs", deleted=count, older_than_days=days)
    return count
