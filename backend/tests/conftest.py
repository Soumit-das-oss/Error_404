"""
VAJRA Forensic Platform - Pytest Configuration and Global Fixtures
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from starlette.testclient import TestClient

from app.main import app
from app.storage.memory_store import case_store


@pytest.fixture(autouse=True)
def reset_memory_store():
    """Ensure in-memory FIFO case store is cleared before each test."""
    case_store.clear()
    yield
    case_store.clear()


@pytest.fixture
def sync_client():
    """Synchronous HTTP TestClient."""
    with TestClient(app) as c:
        yield c


@pytest_asyncio.fixture
async def async_client():
    """Asynchronous HTTP test client using ASGITransport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
