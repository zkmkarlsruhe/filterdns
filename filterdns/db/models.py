"""Pydantic models for database entities."""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class RuleType(str, Enum):
    """Type of custom rule."""

    ALLOW = "allow"
    DENY = "deny"


class Client(BaseModel):
    """Client configuration (user-created, name = DNS subdomain)."""

    id: UUID
    name: str  # e.g., "my-devices" → my-devices.filterdns.zkm.de
    password_hash: str | None = None
    filtering_paused_until: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def is_filtering_paused(self) -> bool:
        """Check if filtering is currently paused."""
        if self.filtering_paused_until is None:
            return False
        return datetime.utcnow() < self.filtering_paused_until


class ClientCreate(BaseModel):
    """Schema for creating a new client."""

    name: str = Field(..., min_length=1, max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    password: str | None = None


class ClientUpdate(BaseModel):
    """Schema for updating a client."""

    password: str | None = None
    blocklist_ids: list[str] | None = None


class LinkedDevice(BaseModel):
    """A legacy device linked to a client (identified by IP)."""

    id: UUID
    client_id: UUID
    ip_address: str
    hostname: str | None = None  # From PTR lookup
    label: str | None = None  # User-friendly name
    created_at: datetime


class LinkedDeviceCreate(BaseModel):
    """Schema for linking a device."""

    ip_address: str
    label: str | None = None


class Blocklist(BaseModel):
    """Available blocklist source."""

    id: str
    name: str
    url: str
    description: str | None = None
    category: str | None = None  # 'ads', 'malware', 'adult', 'tracking', etc.
    domain_count: int = 0
    last_updated: datetime | None = None
    enabled: bool = True


class BlocklistCreate(BaseModel):
    """Schema for adding a blocklist."""

    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str
    url: str
    description: str | None = None
    category: str | None = None


class ClientRule(BaseModel):
    """Custom allow/deny rule for a client."""

    id: UUID
    client_id: UUID
    domain: str
    rule_type: RuleType
    created_at: datetime


class ClientRuleCreate(BaseModel):
    """Schema for creating a custom rule."""

    domain: str
    rule_type: RuleType


class QueryLog(BaseModel):
    """DNS query log entry."""

    id: int
    timestamp: datetime
    client_id: UUID | None
    client_name: str | None = None
    domain: str
    query_type: str  # 'A', 'AAAA', 'CNAME', etc.
    blocked: bool
    blocklist_id: str | None = None
    response_time_ms: int | None = None


class ClientStats(BaseModel):
    """Statistics for a client."""

    total_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    blocked_percentage: float = 0.0
    top_blocked_domains: list[tuple[str, int]] = Field(default_factory=list)
    queries_by_hour: list[tuple[int, int]] = Field(default_factory=list)


class GlobalStats(BaseModel):
    """Global statistics for admin."""

    total_clients: int = 0
    total_queries_today: int = 0
    total_blocked_today: int = 0
    active_blocklists: int = 0
    total_blocked_domains: int = 0
