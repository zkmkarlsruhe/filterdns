"""Configuration management using pydantic-settings."""

import secrets
import sys
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# List of known weak/default passwords that should be rejected in production
WEAK_PASSWORDS = {
    "changeme", "password", "admin", "123456", "admin123",
    "password123", "letmein", "welcome", "default", "root",
}


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="FILTERDNS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql://filterdns:filterdns@localhost:5432/filterdns",
        alias="DATABASE_URL",
    )

    # Server settings
    domain: str = "filterdns.example.com"
    port: int = 8080  # HTTP port for web UI and API
    admin_port: int = 8080  # Deprecated, use 'port' instead
    dns_port: int = 53
    doh_port: int = 443
    dot_port: int = 853

    # Public URL for profile onboarding (e.g., https://filterdns.example.com)
    # If not set, uses http://localhost:{port}
    public_url: str | None = None

    # TLS certificates (wildcard for *.filterdns.example.com)
    tls_cert: Path | None = None
    tls_key: Path | None = None

    # Upstream DNS servers
    upstream_dns: Annotated[list[str], Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])]
    upstream_timeout: float = 5.0

    # Profile identification for legacy DNS (port 53)
    ptr_server: str | None = None  # e.g., "your-dns-server.local"
    ptr_timeout: float = 2.0
    auto_create_clients: bool = True
    default_client: str = "default"

    # Blocklist updates
    blocklist_update_interval: int = 86400  # 24 hours
    blocklist_cache_dir: Path = Path("./data/blocklists")  # /app/data/blocklists in Docker
    blocklists_config: Path = Path("blocklists.yaml")

    # Query logging
    log_queries: bool = True
    log_retention_days: int = 30
    log_allowed: bool = True

    # Admin auth - MUST be set via environment variable in production
    # If not set, generates a random password and prints it to stdout
    admin_password: str = ""

    # Development mode
    debug: bool = False

    @field_validator("admin_password", mode="before")
    @classmethod
    def validate_admin_password(cls, v: str) -> str:
        """Validate admin password is set and not weak."""
        if not v:
            # Generate random password if not set
            generated = secrets.token_urlsafe(24)
            print(
                f"\n{'=' * 60}\n"
                f"WARNING: FILTERDNS_ADMIN_PASSWORD not set!\n"
                f"Generated random admin password: {generated}\n"
                f"Set FILTERDNS_ADMIN_PASSWORD environment variable in production.\n"
                f"{'=' * 60}\n",
                file=sys.stderr,
            )
            return generated

        if v.lower() in WEAK_PASSWORDS:
            print(
                f"\n{'=' * 60}\n"
                f"SECURITY WARNING: Admin password '{v}' is weak/common!\n"
                f"Please set a strong password via FILTERDNS_ADMIN_PASSWORD.\n"
                f"{'=' * 60}\n",
                file=sys.stderr,
            )
            # In debug mode, allow it with warning; in production, this is dangerous
            # but we'll allow it to not break existing deployments

        if len(v) < 8:
            print(
                f"\n{'=' * 60}\n"
                f"SECURITY WARNING: Admin password is too short ({len(v)} chars)!\n"
                f"Use at least 12 characters for production.\n"
                f"{'=' * 60}\n",
                file=sys.stderr,
            )

        return v

    @property
    def has_tls(self) -> bool:
        """Check if TLS is configured."""
        return self.tls_cert is not None and self.tls_key is not None


settings = Settings()
