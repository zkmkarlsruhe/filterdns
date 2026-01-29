"""Database queries for FilterDNS.

Uses new naming convention:
- profiles (formerly clients)
- devices (formerly linked_devices)
- presets (formerly restriction_profiles)
"""

from datetime import datetime, timedelta
from uuid import UUID

import asyncpg
import bcrypt
import structlog

from filterdns.db.database import get_db
from filterdns.db.models import (
    Blocklist,
    BlocklistCreate,
    Device,
    DeviceCreate,
    GlobalStats,
    Preset,
    PresetDomain,
    Profile,
    ProfileConfig,
    ProfileCreate,
    ProfilePreset,
    ProfileRule,
    ProfileRuleCreate,
    ProfileStats,
    QueryLog,
    RuleType,
)

logger = structlog.get_logger()


# ============================================================================
# Profile Operations (formerly Client)
# ============================================================================


async def create_profile(data: ProfileCreate) -> Profile:
    """Create a new profile."""
    db = get_db()
    password_hash = None
    if data.password:
        password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    row = await db.fetchrow(
        """
        INSERT INTO profiles (name, password_hash)
        VALUES ($1, $2)
        RETURNING *
        """,
        data.name,
        password_hash,
    )
    return Profile(**dict(row))


async def get_profile(profile_id: UUID) -> Profile | None:
    """Get a profile by ID."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM profiles WHERE id = $1", profile_id)
    return Profile(**dict(row)) if row else None


async def get_profile_by_name(name: str) -> Profile | None:
    """Get a profile by name (subdomain)."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM profiles WHERE name = $1", name)
    return Profile(**dict(row)) if row else None


async def list_profiles() -> list[Profile]:
    """List all profiles."""
    db = get_db()
    rows = await db.fetch("SELECT * FROM profiles ORDER BY created_at DESC")
    return [Profile(**dict(row)) for row in rows]


async def update_profile_password(profile_id: UUID, password: str | None) -> Profile | None:
    """Update profile password."""
    db = get_db()
    password_hash = None
    if password:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    row = await db.fetchrow(
        """
        UPDATE profiles
        SET password_hash = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        password_hash,
    )
    return Profile(**dict(row)) if row else None


async def delete_profile(profile_id: UUID) -> bool:
    """Delete a profile."""
    db = get_db()
    result = await db.execute("DELETE FROM profiles WHERE id = $1", profile_id)
    return result == "DELETE 1"


async def pause_profile_filtering(profile_id: UUID, minutes: int) -> Profile | None:
    """Pause filtering for a profile."""
    db = get_db()
    pause_until = datetime.utcnow() + timedelta(minutes=minutes)
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET filtering_paused_until = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        pause_until,
    )
    return Profile(**dict(row)) if row else None


async def resume_profile_filtering(profile_id: UUID) -> Profile | None:
    """Resume filtering for a profile."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET filtering_paused_until = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
    )
    return Profile(**dict(row)) if row else None


async def verify_profile_password(profile_id: UUID, password: str) -> bool:
    """Verify a profile's password."""
    db = get_db()
    row = await db.fetchrow("SELECT password_hash FROM profiles WHERE id = $1", profile_id)
    if not row or not row["password_hash"]:
        return False
    return bcrypt.checkpw(password.encode(), row["password_hash"].encode())


# ============================================================================
# Device Operations (formerly LinkedDevice)
# ============================================================================


async def add_device(profile_id: UUID, data: DeviceCreate) -> Device:
    """Add a device to a profile."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO devices (profile_id, ip_address, name, location)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (ip_address) DO UPDATE
        SET profile_id = $1, name = $3, location = $4
        RETURNING *
        """,
        profile_id,
        data.ip_address,
        data.name,
        data.location,
    )
    return Device(**dict(row))


async def get_profile_by_device_ip(ip_address: str) -> Profile | None:
    """Get profile by device IP."""
    db = get_db()
    row = await db.fetchrow(
        """
        SELECT p.* FROM profiles p
        JOIN devices d ON p.id = d.profile_id
        WHERE d.ip_address = $1
        """,
        ip_address,
    )
    return Profile(**dict(row)) if row else None


async def list_devices(profile_id: UUID) -> list[Device]:
    """List devices for a profile."""
    db = get_db()
    rows = await db.fetch(
        "SELECT * FROM devices WHERE profile_id = $1 ORDER BY created_at DESC",
        profile_id,
    )
    return [Device(**dict(row)) for row in rows]


async def remove_device(device_id: UUID) -> bool:
    """Remove a device."""
    db = get_db()
    result = await db.execute("DELETE FROM devices WHERE id = $1", device_id)
    return result == "DELETE 1"


async def update_device_hostname(ip_address: str, hostname: str) -> None:
    """Update device hostname from PTR lookup."""
    db = get_db()
    await db.execute(
        "UPDATE devices SET hostname = $2 WHERE ip_address = $1",
        ip_address,
        hostname,
    )


async def get_device_by_ip(profile_id: UUID, ip_address: str) -> Device | None:
    """Get a device by IP address for a specific profile."""
    db = get_db()
    row = await db.fetchrow(
        "SELECT * FROM devices WHERE profile_id = $1 AND ip_address = $2",
        profile_id,
        ip_address,
    )
    return Device(**dict(row)) if row else None


async def update_device(
    device_id: UUID, name: str | None = None, location: str | None = None
) -> Device | None:
    """Update device name or location."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE devices
        SET name = COALESCE($2, name), location = COALESCE($3, location)
        WHERE id = $1
        RETURNING *
        """,
        device_id,
        name,
        location,
    )
    return Device(**dict(row)) if row else None


async def update_profile_description(profile_id: UUID, description: str | None) -> bool:
    """Update profile description."""
    db = get_db()
    result = await db.execute(
        """
        UPDATE profiles
        SET description = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        """,
        profile_id,
        description,
    )
    return result == "UPDATE 1"


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
# Profile Blocklist Assignments
# ============================================================================


async def get_profile_blocklists(profile_id: UUID) -> list[str]:
    """Get blocklist IDs assigned to a profile."""
    db = get_db()
    rows = await db.fetch(
        "SELECT blocklist_id FROM profile_blocklists WHERE profile_id = $1",
        profile_id,
    )
    return [row["blocklist_id"] for row in rows]


async def set_profile_blocklists(profile_id: UUID, blocklist_ids: list[str]) -> None:
    """Set blocklists for a profile (replaces existing)."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM profile_blocklists WHERE profile_id = $1", profile_id)
        if blocklist_ids:
            await conn.executemany(
                "INSERT INTO profile_blocklists (profile_id, blocklist_id) VALUES ($1, $2)",
                [(profile_id, bid) for bid in blocklist_ids],
            )


async def add_profile_blocklist(profile_id: UUID, blocklist_id: str) -> None:
    """Add a blocklist to a profile."""
    db = get_db()
    await db.execute(
        """
        INSERT INTO profile_blocklists (profile_id, blocklist_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        """,
        profile_id,
        blocklist_id,
    )


async def remove_profile_blocklist(profile_id: UUID, blocklist_id: str) -> None:
    """Remove a blocklist from a profile."""
    db = get_db()
    await db.execute(
        "DELETE FROM profile_blocklists WHERE profile_id = $1 AND blocklist_id = $2",
        profile_id,
        blocklist_id,
    )


# ============================================================================
# Profile Rules Operations
# ============================================================================


async def create_profile_rule(profile_id: UUID, data: ProfileRuleCreate) -> ProfileRule:
    """Create a custom rule for a profile."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO profile_rules (profile_id, domain, rule_type)
        VALUES ($1, $2, $3)
        RETURNING *
        """,
        profile_id,
        data.domain.lower(),
        data.rule_type.value,
    )
    return ProfileRule(**dict(row))


async def get_profile_rules(profile_id: UUID) -> list[ProfileRule]:
    """Get all custom rules for a profile."""
    db = get_db()
    rows = await db.fetch(
        "SELECT * FROM profile_rules WHERE profile_id = $1 ORDER BY created_at DESC",
        profile_id,
    )
    return [ProfileRule(**dict(row)) for row in rows]


async def get_profile_allow_rules(profile_id: UUID) -> set[str]:
    """Get allow rules for a profile as a set of domains."""
    db = get_db()
    rows = await db.fetch(
        "SELECT domain FROM profile_rules WHERE profile_id = $1 AND rule_type = 'allow'",
        profile_id,
    )
    return {row["domain"] for row in rows}


async def get_profile_deny_rules(profile_id: UUID) -> set[str]:
    """Get deny rules for a profile as a set of domains."""
    db = get_db()
    rows = await db.fetch(
        "SELECT domain FROM profile_rules WHERE profile_id = $1 AND rule_type = 'deny'",
        profile_id,
    )
    return {row["domain"] for row in rows}


async def delete_profile_rule(rule_id: UUID) -> bool:
    """Delete a custom rule."""
    db = get_db()
    result = await db.execute("DELETE FROM profile_rules WHERE id = $1", rule_id)
    return result == "DELETE 1"


# ============================================================================
# Query Logging
# ============================================================================


async def log_query(
    profile_id: UUID | None,
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
        INSERT INTO query_logs (profile_id, domain, query_type, blocked, blocklist_id, response_time_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        profile_id,
        domain,
        query_type,
        blocked,
        blocklist_id,
        response_time_ms,
    )


async def get_query_logs(
    profile_id: UUID | None = None,
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

    if profile_id:
        conditions.append(f"q.profile_id = ${param_idx}")
        params.append(profile_id)
        param_idx += 1

    if blocked_only:
        conditions.append("q.blocked = TRUE")

    if domain_filter:
        conditions.append(f"q.domain LIKE ${param_idx}")
        params.append(f"%{domain_filter}%")
        param_idx += 1

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    query = f"""
        SELECT q.*, p.name as profile_name
        FROM query_logs q
        LEFT JOIN profiles p ON q.profile_id = p.id
        WHERE {where_clause}
        ORDER BY q.timestamp DESC
        LIMIT ${param_idx} OFFSET ${param_idx + 1}
    """
    params.extend([limit, offset])

    rows = await db.fetch(query, *params)
    return [QueryLog(**dict(row)) for row in rows]


async def get_profile_stats(profile_id: UUID, hours: int = 24) -> ProfileStats:
    """Get statistics for a profile."""
    db = get_db()
    since = datetime.utcnow() - timedelta(hours=hours)

    # Total, blocked counts, and avg response time
    counts = await db.fetchrow(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked,
            AVG(response_time_ms) as avg_response_time
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2
        """,
        profile_id,
        since,
    )

    total = counts["total"] or 0
    blocked = counts["blocked"] or 0
    allowed = total - blocked
    avg_response_time = counts["avg_response_time"]

    # Top blocked domains with blocklist info
    top_blocked = await db.fetch(
        """
        SELECT domain, blocklist_id, COUNT(*) as count
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2 AND blocked = TRUE
        GROUP BY domain, blocklist_id
        ORDER BY count DESC
        LIMIT 10
        """,
        profile_id,
        since,
    )

    # Top allowed domains
    top_allowed = await db.fetch(
        """
        SELECT domain, COUNT(*) as count
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2 AND blocked = FALSE
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
        """,
        profile_id,
        since,
    )

    # Queries by hour
    by_hour = await db.fetch(
        """
        SELECT EXTRACT(HOUR FROM timestamp)::int as hour, COUNT(*) as count
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2
        GROUP BY hour
        ORDER BY hour
        """,
        profile_id,
        since,
    )

    # Query type distribution
    query_types = await db.fetch(
        """
        SELECT query_type, COUNT(*) as count
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2
        GROUP BY query_type
        ORDER BY count DESC
        """,
        profile_id,
        since,
    )

    # Top blocklists (which blocklists are blocking the most)
    top_blocklists = await db.fetch(
        """
        SELECT blocklist_id, COUNT(*) as count
        FROM query_logs
        WHERE profile_id = $1 AND timestamp > $2 AND blocked = TRUE AND blocklist_id IS NOT NULL
        GROUP BY blocklist_id
        ORDER BY count DESC
        LIMIT 10
        """,
        profile_id,
        since,
    )

    return ProfileStats(
        total_queries=total,
        blocked_queries=blocked,
        allowed_queries=allowed,
        blocked_percentage=(blocked / total * 100) if total > 0 else 0,
        top_blocked_domains=[(row["domain"], row["count"], row["blocklist_id"]) for row in top_blocked],
        top_allowed_domains=[(row["domain"], row["count"]) for row in top_allowed],
        queries_by_hour=[(row["hour"], row["count"]) for row in by_hour],
        query_types=[(row["query_type"], row["count"]) for row in query_types],
        avg_response_time_ms=round(avg_response_time, 2) if avg_response_time else None,
        top_blocklists=[(row["blocklist_id"], row["count"]) for row in top_blocklists],
    )


async def get_global_stats() -> GlobalStats:
    """Get global statistics for admin."""
    db = get_db()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Profile and device counts
    profile_count = await db.fetchval("SELECT COUNT(*) FROM profiles")
    device_count = await db.fetchval("SELECT COUNT(*) FROM devices")

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
        total_profiles=profile_count or 0,
        total_devices=device_count or 0,
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


# ============================================================================
# Config Version Operations
# ============================================================================


async def get_global_version() -> int:
    """Get the global config version for cache invalidation."""
    db = get_db()
    row = await db.fetchrow("SELECT value FROM config WHERE key = 'global_version'")
    return int(row["value"]) if row else 1


async def increment_global_version() -> int:
    """Increment the global config version."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE config SET value = (value::INTEGER + 1)::TEXT, updated_at = NOW()
        WHERE key = 'global_version'
        RETURNING value
        """
    )
    return int(row["value"]) if row else 1


async def increment_profile_config_version(profile_id: UUID) -> int:
    """Increment profile's config version. Call this when profile config changes."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING config_version
        """,
        profile_id,
    )
    return row["config_version"] if row else 1


async def get_profile_config_versions(profile_id: UUID) -> tuple[int, int] | None:
    """Get profile config version and global version for cache check.

    Returns (profile_version, global_version) or None if profile not found.
    """
    db = get_db()
    row = await db.fetchrow(
        """
        SELECT p.config_version, g.value::INTEGER as global_version
        FROM profiles p, config g
        WHERE p.id = $1 AND g.key = 'global_version'
        """,
        profile_id,
    )
    return (row["config_version"], row["global_version"]) if row else None


# ============================================================================
# Preset Operations (formerly RestrictionProfile)
# ============================================================================


async def create_preset(
    preset_id: str,
    name: str,
    category: str,
    description: str | None = None,
    is_builtin: bool = False,
) -> Preset:
    """Create a new preset."""
    db = get_db()
    row = await db.fetchrow(
        """
        INSERT INTO presets (id, name, description, category, is_builtin)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """,
        preset_id,
        name,
        description,
        category,
        is_builtin,
    )
    return Preset(**dict(row))


async def get_preset(preset_id: str) -> Preset | None:
    """Get a preset by ID."""
    db = get_db()
    row = await db.fetchrow("SELECT * FROM presets WHERE id = $1", preset_id)
    return Preset(**dict(row)) if row else None


async def list_presets() -> list[Preset]:
    """List all presets."""
    db = get_db()
    rows = await db.fetch("SELECT * FROM presets ORDER BY category, name")
    return [Preset(**dict(row)) for row in rows]


async def delete_preset(preset_id: str) -> bool:
    """Delete a preset. Returns False if builtin or not found."""
    db = get_db()
    result = await db.execute(
        "DELETE FROM presets WHERE id = $1 AND is_builtin = FALSE",
        preset_id,
    )
    return result == "DELETE 1"


async def preset_exists(preset_id: str) -> bool:
    """Check if a preset exists."""
    db = get_db()
    row = await db.fetchrow("SELECT 1 FROM presets WHERE id = $1", preset_id)
    return row is not None


# ============================================================================
# Preset Domains Operations
# ============================================================================


async def get_preset_domains(preset_id: str) -> list[str]:
    """Get domains for a preset."""
    db = get_db()
    rows = await db.fetch(
        "SELECT domain FROM preset_domains WHERE preset_id = $1",
        preset_id,
    )
    return [row["domain"] for row in rows]


async def set_preset_domains(preset_id: str, domains: list[str]) -> None:
    """Set domains for a preset (replaces existing)."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM preset_domains WHERE preset_id = $1", preset_id)
        if domains:
            # Normalize domains to lowercase
            normalized = [(preset_id, d.lower()) for d in domains]
            await conn.executemany(
                "INSERT INTO preset_domains (preset_id, domain) VALUES ($1, $2)",
                normalized,
            )


async def get_preset_domain_count(preset_id: str) -> int:
    """Get the number of domains in a preset."""
    db = get_db()
    count = await db.fetchval(
        "SELECT COUNT(*) FROM preset_domains WHERE preset_id = $1",
        preset_id,
    )
    return count or 0


async def get_all_preset_domains() -> dict[str, set[str]]:
    """Get all preset domains, grouped by preset_id."""
    db = get_db()
    rows = await db.fetch("SELECT preset_id, domain FROM preset_domains")
    result: dict[str, set[str]] = {}
    for row in rows:
        preset_id = row["preset_id"]
        if preset_id not in result:
            result[preset_id] = set()
        result[preset_id].add(row["domain"])
    return result


# ============================================================================
# Profile Presets Operations
# ============================================================================


async def get_profile_presets(profile_id: UUID) -> list[str]:
    """Get preset IDs enabled for a profile."""
    db = get_db()
    rows = await db.fetch(
        "SELECT preset_id FROM profile_presets WHERE profile_id = $1",
        profile_id,
    )
    return [row["preset_id"] for row in rows]


async def set_profile_presets(profile_id: UUID, preset_ids: list[str]) -> None:
    """Set presets for a profile (replaces existing). Also bumps config_version."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM profile_presets WHERE profile_id = $1", profile_id)
        if preset_ids:
            await conn.executemany(
                "INSERT INTO profile_presets (profile_id, preset_id) VALUES ($1, $2)",
                [(profile_id, pid) for pid in preset_ids],
            )
        # Bump profile config version
        await conn.execute(
            "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            profile_id,
        )


async def add_profile_preset(profile_id: UUID, preset_id: str) -> None:
    """Add a preset to a profile. Also bumps config_version."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO profile_presets (profile_id, preset_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            """,
            profile_id,
            preset_id,
        )
        await conn.execute(
            "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            profile_id,
        )


async def remove_profile_preset(profile_id: UUID, preset_id: str) -> None:
    """Remove a preset from a profile. Also bumps config_version."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute(
            "DELETE FROM profile_presets WHERE profile_id = $1 AND preset_id = $2",
            profile_id,
            preset_id,
        )
        await conn.execute(
            "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            profile_id,
        )


# ============================================================================
# Maintenance Mode Operations
# ============================================================================


async def set_maintenance_mode(profile_id: UUID, enabled: bool) -> Profile | None:
    """Enable or disable maintenance mode for a profile. Also bumps config_version."""
    db = get_db()
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET maintenance_mode = $2, config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        enabled,
    )
    return Profile(**dict(row)) if row else None


async def get_maintenance_allowlist(profile_id: UUID) -> list[str]:
    """Get the maintenance mode allowlist for a profile."""
    db = get_db()
    row = await db.fetchrow(
        "SELECT maintenance_allowlist FROM profiles WHERE id = $1",
        profile_id,
    )
    return list(row["maintenance_allowlist"]) if row and row["maintenance_allowlist"] else []


async def set_maintenance_allowlist(profile_id: UUID, domains: list[str]) -> Profile | None:
    """Set the maintenance mode allowlist for a profile. Also bumps config_version."""
    db = get_db()
    # Normalize domains to lowercase
    normalized = [d.lower() for d in domains]
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET maintenance_allowlist = $2, config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        normalized,
    )
    return Profile(**dict(row)) if row else None


async def add_maintenance_allowlist_domain(profile_id: UUID, domain: str) -> Profile | None:
    """Add a domain to the maintenance allowlist. Also bumps config_version."""
    db = get_db()
    normalized = domain.lower()
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET maintenance_allowlist = array_append(
            array_remove(maintenance_allowlist, $2), $2
        ),
        config_version = config_version + 1,
        updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        normalized,
    )
    return Profile(**dict(row)) if row else None


async def remove_maintenance_allowlist_domain(profile_id: UUID, domain: str) -> Profile | None:
    """Remove a domain from the maintenance allowlist. Also bumps config_version."""
    db = get_db()
    normalized = domain.lower()
    row = await db.fetchrow(
        """
        UPDATE profiles
        SET maintenance_allowlist = array_remove(maintenance_allowlist, $2),
        config_version = config_version + 1,
        updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        """,
        profile_id,
        normalized,
    )
    return Profile(**dict(row)) if row else None


# ============================================================================
# Profile Config (for caching)
# ============================================================================


async def get_full_profile_config(profile_id: UUID) -> ProfileConfig | None:
    """Get full profile configuration for DNS filtering.

    This fetches all data needed for filtering in a single call.
    Use with caching for performance.
    """
    db = get_db()

    # Get profile base data
    profile_row = await db.fetchrow("SELECT * FROM profiles WHERE id = $1", profile_id)
    if not profile_row:
        return None

    # Get rules, blocklists, and presets
    allow_rows = await db.fetch(
        "SELECT domain FROM profile_rules WHERE profile_id = $1 AND rule_type = 'allow'",
        profile_id,
    )
    deny_rows = await db.fetch(
        "SELECT domain FROM profile_rules WHERE profile_id = $1 AND rule_type = 'deny'",
        profile_id,
    )
    blocklist_rows = await db.fetch(
        "SELECT blocklist_id FROM profile_blocklists WHERE profile_id = $1",
        profile_id,
    )
    preset_rows = await db.fetch(
        "SELECT preset_id FROM profile_presets WHERE profile_id = $1",
        profile_id,
    )

    return ProfileConfig(
        profile_id=profile_row["id"],
        profile_name=profile_row["name"],
        config_version=profile_row["config_version"],
        filtering_paused_until=profile_row["filtering_paused_until"],
        maintenance_mode=profile_row["maintenance_mode"],
        maintenance_allowlist=set(profile_row["maintenance_allowlist"] or []),
        allow_rules={row["domain"] for row in allow_rows},
        deny_rules={row["domain"] for row in deny_rows},
        active_blocklist_ids=sorted([row["blocklist_id"] for row in blocklist_rows]),
        active_preset_ids=sorted([row["preset_id"] for row in preset_rows]),
    )


# ============================================================================
# Version-aware Profile Rule Operations
# ============================================================================


async def create_profile_rule_versioned(profile_id: UUID, data: ProfileRuleCreate) -> ProfileRule:
    """Create a custom rule for a profile and bump config_version."""
    db = get_db()
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO profile_rules (profile_id, domain, rule_type)
            VALUES ($1, $2, $3)
            RETURNING *
            """,
            profile_id,
            data.domain.lower(),
            data.rule_type.value,
        )
        await conn.execute(
            "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            profile_id,
        )
    return ProfileRule(**dict(row))


async def delete_profile_rule_versioned(profile_id: UUID, rule_id: UUID) -> bool:
    """Delete a custom rule and bump config_version."""
    db = get_db()
    async with db.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM profile_rules WHERE id = $1 AND profile_id = $2",
            rule_id,
            profile_id,
        )
        if result == "DELETE 1":
            await conn.execute(
                "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                profile_id,
            )
            return True
        return False


async def set_profile_blocklists_versioned(profile_id: UUID, blocklist_ids: list[str]) -> None:
    """Set blocklists for a profile (replaces existing) and bump config_version."""
    db = get_db()
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM profile_blocklists WHERE profile_id = $1", profile_id)
        if blocklist_ids:
            await conn.executemany(
                "INSERT INTO profile_blocklists (profile_id, blocklist_id) VALUES ($1, $2)",
                [(profile_id, bid) for bid in blocklist_ids],
            )
        await conn.execute(
            "UPDATE profiles SET config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
            profile_id,
        )


# ============================================================================
# Admin Settings
# ============================================================================


async def get_admin_setting(key: str) -> str | None:
    """Get an admin setting by key."""
    db = get_db()
    row = await db.fetchrow(
        "SELECT value FROM admin_settings WHERE key = $1",
        key,
    )
    return row["value"] if row else None


async def set_admin_setting(key: str, value: str) -> None:
    """Set an admin setting."""
    db = get_db()
    await db.execute(
        """
        INSERT INTO admin_settings (key, value, updated_at)
        VALUES ($1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT (key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = CURRENT_TIMESTAMP
        """,
        key,
        value,
    )


async def get_all_admin_settings() -> dict[str, str]:
    """Get all admin settings."""
    db = get_db()
    rows = await db.fetch("SELECT key, value FROM admin_settings")
    return {row["key"]: row["value"] for row in rows}


async def get_default_blocklists() -> list[str]:
    """Get the list of default blocklists for new profiles."""
    import json
    value = await get_admin_setting("default_blocklists")
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return []
    return []


async def set_default_blocklists(blocklist_ids: list[str]) -> None:
    """Set the list of default blocklists for new profiles."""
    import json
    await set_admin_setting("default_blocklists", json.dumps(blocklist_ids))


# ============================================================================
# Backwards Compatibility Aliases
# ============================================================================

# Client -> Profile aliases
create_client = create_profile
get_client = get_profile
get_client_by_name = get_profile_by_name
list_clients = list_profiles
update_client_password = update_profile_password
delete_client = delete_profile
pause_client_filtering = pause_profile_filtering
resume_client_filtering = resume_profile_filtering
verify_client_password = verify_profile_password
get_client_blocklists = get_profile_blocklists
set_client_blocklists = set_profile_blocklists
add_client_blocklist = add_profile_blocklist
remove_client_blocklist = remove_profile_blocklist
get_client_stats = get_profile_stats
increment_client_config_version = increment_profile_config_version
get_client_config_versions = get_profile_config_versions
get_full_client_config = get_full_profile_config

# LinkedDevice -> Device aliases
link_device = add_device
get_client_by_ip = get_profile_by_device_ip
list_linked_devices = list_devices
unlink_device = remove_device

# ClientRule -> ProfileRule aliases
create_client_rule = create_profile_rule
get_client_rules = get_profile_rules
get_client_allow_rules = get_profile_allow_rules
get_client_deny_rules = get_profile_deny_rules
delete_client_rule = delete_profile_rule
create_client_rule_versioned = create_profile_rule_versioned
delete_client_rule_versioned = delete_profile_rule_versioned
set_client_blocklists_versioned = set_profile_blocklists_versioned

# RestrictionProfile -> Preset aliases
create_restriction_profile = create_preset
get_restriction_profile = get_preset
list_restriction_profiles = list_presets
delete_restriction_profile = delete_preset
profile_exists = preset_exists
get_profile_domains = get_preset_domains
set_profile_domains = set_preset_domains
get_profile_domain_count = get_preset_domain_count
get_all_profile_domains = get_all_preset_domains

# ClientProfile -> ProfilePreset aliases
get_client_profiles = get_profile_presets
set_client_profiles = set_profile_presets
add_client_profile = add_profile_preset
remove_client_profile = remove_profile_preset
