"""Blocklist fetcher using httpx async client."""

import asyncio
from datetime import datetime
from pathlib import Path

import httpx
import structlog
import yaml

from filterdns.blocklist.parser import parse_blocklist
from filterdns.config import settings
from filterdns.db import queries
from filterdns.db.models import BlocklistCreate

logger = structlog.get_logger()


class BlocklistFetcher:
    """Async fetcher for blocklist files."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        timeout: float = 30.0,
    ):
        self.cache_dir = cache_dir or settings.blocklist_cache_dir
        self.timeout = timeout
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BlocklistFetcher":
        """Create async HTTP client on context enter."""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "FilterDNS/1.0"},
        )
        return self

    async def __aexit__(self, *args) -> None:
        """Close async HTTP client on context exit."""
        if self.client:
            await self.client.aclose()

    async def fetch_url(self, url: str) -> str | None:
        """Fetch content from URL.

        Args:
            url: URL to fetch

        Returns:
            Content as string or None on error
        """
        if not self.client:
            raise RuntimeError("Fetcher not initialized. Use async context manager.")

        try:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.text
        except httpx.HTTPError as e:
            logger.error("Failed to fetch blocklist", url=url, error=str(e))
            return None

    async def fetch_and_parse(self, blocklist_id: str, url: str) -> set[str]:
        """Fetch blocklist and parse domains.

        Args:
            blocklist_id: Identifier for logging/caching
            url: URL to fetch

        Returns:
            Set of blocked domains
        """
        logger.info("Fetching blocklist", blocklist_id=blocklist_id, url=url)

        content = await self.fetch_url(url)
        if not content:
            return set()

        # Parse domains
        domains = parse_blocklist(content)
        logger.info(
            "Parsed blocklist",
            blocklist_id=blocklist_id,
            domain_count=len(domains),
        )

        # Cache to disk
        await self._cache_domains(blocklist_id, domains)

        return domains

    async def _cache_domains(self, blocklist_id: str, domains: set[str]) -> None:
        """Cache domains to disk."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = self.cache_dir / f"{blocklist_id}.txt"

        def write_cache():
            with open(cache_file, "w") as f:
                for domain in sorted(domains):
                    f.write(f"{domain}\n")

        await asyncio.to_thread(write_cache)

    async def load_cached(self, blocklist_id: str) -> set[str]:
        """Load domains from cache.

        Args:
            blocklist_id: Identifier for the blocklist

        Returns:
            Set of cached domains or empty set if not cached
        """
        cache_file = self.cache_dir / f"{blocklist_id}.txt"
        if not cache_file.exists():
            return set()

        def read_cache():
            with open(cache_file) as f:
                return {line.strip() for line in f if line.strip()}

        return await asyncio.to_thread(read_cache)


async def load_default_blocklists() -> None:
    """Load default blocklists from config file into database."""
    config_path = settings.blocklists_config
    if not config_path.exists():
        logger.warning("Blocklists config not found", path=str(config_path))
        return

    with open(config_path) as f:
        config = yaml.safe_load(f)

    blocklists = config.get("blocklists", [])
    for bl in blocklists:
        existing = await queries.get_blocklist(bl["id"])
        if not existing:
            await queries.create_blocklist(
                BlocklistCreate(
                    id=bl["id"],
                    name=bl["name"],
                    url=bl["url"],
                    description=bl.get("description"),
                    category=bl.get("category"),
                )
            )
            logger.info("Added default blocklist", blocklist_id=bl["id"])


async def update_all_blocklists(engine: "BlocklistEngine") -> None:
    """Update all enabled blocklists.

    Args:
        engine: BlocklistEngine to update
    """
    from filterdns.blocklist.engine import BlocklistEngine

    blocklists = await queries.list_blocklists(enabled_only=True)

    async with BlocklistFetcher() as fetcher:
        for bl in blocklists:
            try:
                domains = await fetcher.fetch_and_parse(bl.id, bl.url)
                if domains:
                    engine.set_blocklist(bl.id, domains)
                    await queries.update_blocklist_stats(bl.id, len(domains))
            except Exception as e:
                logger.error(
                    "Failed to update blocklist",
                    blocklist_id=bl.id,
                    error=str(e),
                )
