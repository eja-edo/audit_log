"""
Database connection and session management using asyncpg.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import asyncpg
from asyncpg import Pool, Connection

from app.config import settings

logger = logging.getLogger(__name__)


class Database:
    """Async PostgreSQL database connection pool manager."""
    
    def __init__(self):
        self._pool: Optional[Pool] = None
        self._lock = asyncio.Lock()
    
    async def connect(self) -> None:
        """Initialize the connection pool."""
        async with self._lock:
            if self._pool is not None:
                return
            
            # Parse connection string
            dsn = settings.database_url
            if dsn.startswith("postgresql+asyncpg://"):
                dsn = dsn.replace("postgresql+asyncpg://", "postgresql://", 1)
            
            logger.info("Connecting to PostgreSQL...")
            
            self._pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=settings.db_pool_min_size,
                max_size=settings.db_pool_max_size,
                command_timeout=settings.db_command_timeout,
                server_settings={
                    'application_name': settings.app_name,
                }
            )
            
            logger.info("PostgreSQL connection pool created successfully")
    
    async def disconnect(self) -> None:
        """Close the connection pool."""
        async with self._lock:
            if self._pool is None:
                return
            
            logger.info("Closing PostgreSQL connection pool...")
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL connection pool closed")
    
    @property
    def pool(self) -> Pool:
        """Get the connection pool."""
        if self._pool is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._pool
    
    async def execute(self, query: str, *args) -> str:
        """Execute a query and return status."""
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def fetch(self, query: str, *args) -> list:
        """Fetch all rows from a query."""
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow(self, query: str, *args) -> Optional[asyncpg.Record]:
        """Fetch a single row from a query."""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)
    
    async def fetchval(self, query: str, *args):
        """Fetch a single value from a query."""
        async with self.pool.acquire() as conn:
            return await conn.fetchval(query, *args)
    
    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[Connection, None]:
        """Acquire a connection from the pool."""
        async with self.pool.acquire() as conn:
            yield conn
    
    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Connection, None]:
        """Get a connection with transaction context."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                yield conn
    
    async def health_check(self) -> bool:
        """Check database connectivity."""
        try:
            result = await self.fetchval("SELECT 1")
            return result == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Global database instance
database = Database()


async def get_db() -> Database:
    """Dependency injection for database access."""
    return database


async def get_connection() -> AsyncGenerator[Connection, None]:
    """Dependency injection for a database connection."""
    async with database.acquire() as conn:
        yield conn
