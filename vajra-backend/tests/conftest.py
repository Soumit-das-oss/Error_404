import pytest_asyncio
from app.core.database import init_db


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Ensure database tables are automatically initialized before tests execute."""
    await init_db()
