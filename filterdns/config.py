"""Configuration management using pydantic-settings."""

from pathlib import Path
from typing import Annotated

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    domain: str = "filterdns.zkm.de"
    admin_port: int = 8080
    dns_port: int = 53
    doh_port: int = 443
    dot_port: int = 853

    # TLS certificates (wildcard for *.filterdns.zkm.de)
    tls_cert: Path | None = None
    tls_key: Path | None = None

    # Upstream DNS servers
    upstream_dns: Annotated[list[str], Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])]
    upstream_timeout: float = 5.0

    # Client identification for legacy DNS (port 53)
    ptr_server: str | None = None  # e.g., "infoblox.zkm.local"
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

    # Admin auth
    admin_password: str = "changeme"

    # Development mode
    debug: bool = False

    @property
    def has_tls(self) -> bool:
        """Check if TLS is configured."""
        return self.tls_cert is not None and self.tls_key is not None


settings = Settings()
