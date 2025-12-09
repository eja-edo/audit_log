"""
Test fixtures and configuration for pytest.
"""

import asyncio
import base64
import json
from datetime import datetime
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio

# Import crypto utilities for test key generation
from app.crypto import (
    generate_ed25519_keypair,
    generate_rsa_keypair,
    sign_ed25519,
    sign_rsa_pss,
    canonicalize_event,
    compute_sha256
)


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def ed25519_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair for testing."""
    return generate_ed25519_keypair()


@pytest.fixture
def rsa_keypair() -> tuple[str, str]:
    """Generate an RSA keypair for testing."""
    return generate_rsa_keypair(2048)


@pytest.fixture
def sample_event_data() -> dict:
    """Sample event data for testing."""
    return {
        "actor": "user@example.com",
        "action": "LOGIN",
        "resource": "auth-service",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "session_id": "sess_abc123",
        "timestamp": datetime.utcnow().isoformat()
    }


@pytest.fixture
def signed_event(sample_event_data: dict, ed25519_keypair: tuple[str, str]) -> dict:
    """Create a properly signed event for testing."""
    private_key, public_key = ed25519_keypair
    
    # Create canonical form
    canonical = canonicalize_event(sample_event_data)
    
    # Sign the canonical form
    signature = sign_ed25519(canonical.encode('utf-8'), private_key)
    
    return {
        "service_id": "test-service",
        "event_type": "USER_LOGIN",
        "event": canonical,
        "event_data": sample_event_data,
        "signature": base64.b64encode(signature).decode('utf-8'),
        "public_key_id": "test-service:v1",
        "public_key_pem": public_key,
        "algorithm": "ed25519"
    }


@pytest.fixture
def signed_event_rsa(sample_event_data: dict, rsa_keypair: tuple[str, str]) -> dict:
    """Create an RSA-PSS signed event for testing."""
    private_key, public_key = rsa_keypair
    
    canonical = canonicalize_event(sample_event_data)
    signature = sign_rsa_pss(canonical.encode('utf-8'), private_key)
    
    return {
        "service_id": "test-service-rsa",
        "event_type": "USER_LOGIN",
        "event": canonical,
        "event_data": sample_event_data,
        "signature": base64.b64encode(signature).decode('utf-8'),
        "public_key_id": "test-service-rsa:v1",
        "public_key_pem": public_key,
        "algorithm": "rsa-pss"
    }


@pytest.fixture
def invalid_signature_event(sample_event_data: dict, ed25519_keypair: tuple[str, str]) -> dict:
    """Create an event with an invalid signature."""
    _, public_key = ed25519_keypair
    
    canonical = canonicalize_event(sample_event_data)
    
    return {
        "service_id": "test-service",
        "event_type": "USER_LOGIN",
        "event": canonical,
        "event_data": sample_event_data,
        "signature": base64.b64encode(b"invalid_signature_bytes").decode('utf-8'),
        "public_key_id": "test-service:v1",
        "public_key_pem": public_key,
        "algorithm": "ed25519"
    }


class MockDatabase:
    """Mock database for testing without PostgreSQL."""
    
    def __init__(self):
        self.events = []
        self.keys = {}
        self.chain_state = {}
        self.admin_audit = []
    
    async def fetchrow(self, query: str, *args):
        """Mock fetchrow."""
        if "key_registry" in query and args:
            key_id = args[0]
            return self.keys.get(key_id)
        if "chain_state" in query and args:
            service_id = args[0]
            return self.chain_state.get(service_id)
        return None
    
    async def fetchval(self, query: str, *args):
        """Mock fetchval."""
        if "INSERT INTO audit_events" in query:
            event_id = len(self.events) + 1
            self.events.append({"id": event_id, "args": args})
            return event_id
        if "SELECT COUNT" in query:
            return len(self.events)
        return None
    
    async def execute(self, query: str, *args):
        """Mock execute."""
        return "INSERT 1"
    
    async def fetch(self, query: str, *args):
        """Mock fetch."""
        return []
    
    async def transaction(self):
        """Mock transaction context manager."""
        return MockTransaction(self)
    
    def register_key(self, key_id: str, public_key_pem: str, algorithm: str):
        """Helper to register a key for testing."""
        self.keys[key_id] = {
            "public_key_pem": public_key_pem,
            "algorithm": algorithm
        }


class MockTransaction:
    """Mock transaction context manager."""
    
    def __init__(self, db: MockDatabase):
        self.db = db
    
    async def __aenter__(self):
        return self.db
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def mock_db() -> MockDatabase:
    """Create a mock database for testing."""
    return MockDatabase()


@pytest.fixture
def mock_db_with_key(mock_db: MockDatabase, ed25519_keypair: tuple[str, str]) -> MockDatabase:
    """Create a mock database with a registered key."""
    _, public_key = ed25519_keypair
    mock_db.register_key("test-service:v1", public_key, "ed25519")
    return mock_db
