import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from app.core.config import settings

logger = logging.getLogger("vajra.database")

# Normalize database URL to ensure async drivers are used
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite://"):
    db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
elif db_url.startswith("postgresql+psycopg2://"):
    db_url = db_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)

# Async SQLAlchemy Engine configuration
is_sqlite = db_url.startswith("sqlite")
engine_kwargs = {
    "echo": False,
    "future": True,
}

if is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20

engine = create_async_engine(
    db_url,
    **engine_kwargs
)

# Async Session Factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Declarative Base for ORM Models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining an asynchronous database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables using metadata."""
    try:
        async with engine.begin() as conn:
            # Import models inside to ensure registration with Base.metadata
            from app.models import user, case  # noqa: F401
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables verified/created successfully.")
    except Exception as e:
        logger.warning(
            f"Could not connect to database at {settings.DATABASE_URL} during startup: {e}. "
            "Ensure PostgreSQL container is running via `docker compose up -d postgres`."
        )
