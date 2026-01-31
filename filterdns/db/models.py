"""Pydantic models for database entities.

- Profile: DNS filtering configuration (e.g., "my-devices")
- Device: Individual machine using a profile
- Preset: Predefined blocking rule set (e.g., "block-social-media")
"""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class RuleType(str, Enum):
    """Type of custom rule."""

    ALLOW = "allow"
    DENY = "deny"


# =============================================================================
# Profile (formerly Client) - DNS filtering configuration
# =============================================================================


class Profile(BaseModel):
    """DNS filtering profile configuration.

    A profile defines filtering rules for a group of devices.
    Example: "my-devices" for all personal devices.
    """

    id: UUID
    name: str  # e.g., "my-devices" → my-devices.filterdns.example.com
    description: str | None = None
    password_hash: str | None = None
    filtering_paused_until: datetime | None = None
    config_version: int = 1
    maintenance_mode: bool = False
    maintenance_allowlist: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    @property
    def is_filtering_paused(self) -> bool:
        """Check if filtering is currently paused."""
        if self.filtering_paused_until is None:
            return False
        return datetime.utcnow() < self.filtering_paused_until


class ProfileCreate(BaseModel):
    """Schema for creating a new profile."""

    name: str = Field(..., min_length=1, max_length=63, pattern=r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    description: str | None = None
    password: str | None = None


class ProfileUpdate(BaseModel):
    """Schema for updating a profile."""

    description: str | None = None
    password: str | None = None
    blocklist_ids: list[str] | None = None


# =============================================================================
# Device (formerly LinkedDevice) - Individual machine
# =============================================================================


class Device(BaseModel):
    """A device linked to a profile.

    Represents an individual machine (PS5, kiosk, workstation, etc.)
    that uses a profile's DNS filtering configuration.
    """

    id: UUID
    profile_id: UUID
    name: str | None = None  # User-friendly name, e.g., "PS5-01"
    ip_address: str
    hostname: str | None = None  # From PTR lookup
    location: str | None = None  # Physical location, e.g., "Hall 3, Station 2"
    created_at: datetime


class DeviceCreate(BaseModel):
    """Schema for adding a device to a profile."""

    name: str | None = None
    ip_address: str | None = None  # Optional - auto-detect from request
    location: str | None = None


# =============================================================================
# Blocklist - External domain blocklists
# =============================================================================


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


# =============================================================================
# Profile Rules - Custom allow/deny rules
# =============================================================================


class ProfileRule(BaseModel):
    """Custom allow/deny rule for a profile."""

    id: UUID
    profile_id: UUID
    domain: str
    rule_type: RuleType
    created_at: datetime


class ProfileRuleCreate(BaseModel):
    """Schema for creating a custom rule."""

    domain: str
    rule_type: RuleType


# =============================================================================
# Query Logging
# =============================================================================


class QueryLog(BaseModel):
    """DNS query log entry."""

    id: int
    timestamp: datetime
    profile_id: UUID | None
    profile_name: str | None = None
    domain: str
    query_type: str  # 'A', 'AAAA', 'CNAME', etc.
    blocked: bool
    blocklist_id: str | None = None
    response_time_ms: int | None = None


# =============================================================================
# Statistics
# =============================================================================


class ProfileStats(BaseModel):
    """Statistics for a profile."""

    total_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    blocked_percentage: float = 0.0
    top_blocked_domains: list[tuple[str, int, str | None]] = Field(default_factory=list)  # (domain, count, blocklist_id)
    top_allowed_domains: list[tuple[str, int]] = Field(default_factory=list)
    queries_by_hour: list[tuple[int, int]] = Field(default_factory=list)
    avg_response_time_ms: float | None = None
    top_blocklists: list[tuple[str, int]] = Field(default_factory=list)  # (blocklist_id, count)


class GlobalStats(BaseModel):
    """Global statistics for admin."""

    total_profiles: int = 0
    total_devices: int = 0
    total_queries_today: int = 0
    total_blocked_today: int = 0
    active_blocklists: int = 0
    total_blocked_domains: int = 0


# =============================================================================
# Preset (formerly RestrictionProfile) - Predefined blocking rule sets
# =============================================================================


class Preset(BaseModel):
    """Predefined blocking rule set.

    A preset is a collection of domains to block, grouped by purpose.
    Examples: "block-social-media", "block-gaming", "block-os-updates"
    """

    id: str
    name: str
    description: str | None = None
    category: str  # social, gaming, streaming, os-updates, etc.
    is_builtin: bool = False
    created_at: datetime


class PresetCreate(BaseModel):
    """Schema for creating a preset."""

    id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str
    description: str | None = None
    category: str
    domains: list[str] = Field(default_factory=list)


class PresetDomain(BaseModel):
    """Domain entry for a preset."""

    id: int
    preset_id: str
    domain: str


class ProfilePreset(BaseModel):
    """Association between profile and preset."""

    profile_id: UUID
    preset_id: str
    enabled_at: datetime


# =============================================================================
# Cached Configuration (for DNS filtering engine)
# =============================================================================


class ProfileConfig(BaseModel):
    """Cached profile configuration for DNS filtering."""

    profile_id: UUID
    profile_name: str
    config_version: int
    filtering_paused_until: datetime | None = None
    maintenance_mode: bool = False
    maintenance_allowlist: set[str] = Field(default_factory=set)
    allow_rules: set[str] = Field(default_factory=set)
    deny_rules: set[str] = Field(default_factory=set)
    active_blocklist_ids: list[str] = Field(default_factory=list)
    active_preset_ids: list[str] = Field(default_factory=list)


# =============================================================================
# Backwards compatibility aliases (to be removed after full migration)
# =============================================================================

# These aliases help during the transition period
Client = Profile
ClientCreate = ProfileCreate
ClientUpdate = ProfileUpdate
ClientStats = ProfileStats
ClientRule = ProfileRule
ClientRuleCreate = ProfileRuleCreate
LinkedDevice = Device
LinkedDeviceCreate = DeviceCreate
RestrictionProfile = Preset
ProfileDomain = PresetDomain
ClientProfile = ProfilePreset
ClientConfig = ProfileConfig
