"""PostgreSQL database connection and pool management."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import asyncpg
import structlog

from filterdns.config import settings

logger = structlog.get_logger()

# Global database instance
_db: "Database | None" = None


class Database:
    """Async PostgreSQL database wrapper using asyncpg."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        """Create connection pool."""
        logger.info("Connecting to database", dsn=self.dsn.split("@")[-1])
        self.pool = await asyncpg.create_pool(
            self.dsn,
            min_size=2,
            max_size=20,
            command_timeout=60,
        )
        logger.info("Database connection pool created")

    async def disconnect(self) -> None:
        """Close connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[asyncpg.Connection, None]:
        """Acquire a connection from the pool."""
        if not self.pool:
            raise RuntimeError("Database not connected")
        async with self.pool.acquire() as conn:
            yield conn

    async def execute(self, query: str, *args) -> str:
        """Execute a query."""
        async with self.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args) -> list[asyncpg.Record]:
        """Fetch multiple rows."""
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args) -> asyncpg.Record | None:
        """Fetch a single row."""
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetchval(self, query: str, *args):
        """Fetch a single value."""
        async with self.acquire() as conn:
            return await conn.fetchval(query, *args)


async def init_db() -> Database:
    """Initialize the database connection."""
    global _db
    _db = Database(settings.database_url)
    await _db.connect()
    return _db


async def close_db() -> None:
    """Close the database connection."""
    global _db
    if _db:
        await _db.disconnect()
        _db = None


def get_db() -> Database:
    """Get the database instance."""
    if _db is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _db
