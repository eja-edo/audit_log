"""
Tests for the event processor service.
"""

import pytest
from datetime import datetime

from app.crypto import compute_sha256, compute_chain_hash, canonicalize_event
from app.services.processor import process_event


class TestChainHash:
    """Tests for chain hash computation."""
    
    def test_genesis_chain_hash(self):
        """Test chain hash with genesis (zero) previous hash."""
        prev_chain = b'\x00' * 32
        event_hash = compute_sha256(b"first event")
        service_id = "test-service"
        
        chain_hash = compute_chain_hash(prev_chain, event_hash, service_id)
        
        assert len(chain_hash) == 32
        assert chain_hash != prev_chain
        assert chain_hash != event_hash
    
    def test_chain_linking(self):
        """Test that chain hashes properly link events."""
        service_id = "test-service"
        
        # First event
        event1_hash = compute_sha256(b"event 1")
        prev_chain = b'\x00' * 32
        chain1 = compute_chain_hash(prev_chain, event1_hash, service_id)
        
        # Second event uses first event's chain hash
        event2_hash = compute_sha256(b"event 2")
        chain2 = compute_chain_hash(chain1, event2_hash, service_id)
        
        # Third event uses second event's chain hash
        event3_hash = compute_sha256(b"event 3")
        chain3 = compute_chain_hash(chain2, event3_hash, service_id)
        
        # All chain hashes should be unique
        assert len({chain1.hex(), chain2.hex(), chain3.hex()}) == 3
        
        # Verify chain is reproducible
        chain2_verify = compute_chain_hash(chain1, event2_hash, service_id)
        assert chain2 == chain2_verify
    
    def test_chain_tamper_detection(self):
        """Test that tampering breaks the chain."""
        service_id = "test-service"
        
        # Build a chain
        events = [b"event 1", b"event 2", b"event 3"]
        chain_hashes = []
        prev_chain = b'\x00' * 32
        
        for event_data in events:
            event_hash = compute_sha256(event_data)
            chain_hash = compute_chain_hash(prev_chain, event_hash, service_id)
            chain_hashes.append(chain_hash)
            prev_chain = chain_hash
        
        # Now "tamper" with event 2 by changing its hash
        tampered_event2_hash = compute_sha256(b"tampered event 2")
        
        # Recompute chain from event 2 onwards
        tampered_chain2 = compute_chain_hash(chain_hashes[0], tampered_event2_hash, service_id)
        
        # Tampered chain hash is different
        assert tampered_chain2 != chain_hashes[1]
        
        # This would cascade to event 3 as well
        event3_hash = compute_sha256(b"event 3")
        tampered_chain3 = compute_chain_hash(tampered_chain2, event3_hash, service_id)
        assert tampered_chain3 != chain_hashes[2]


class TestEventProcessor:
    """Tests for event processing."""
    
    @pytest.mark.asyncio
    async def test_process_event_basic(self, mock_db, ed25519_keypair):
        """Test basic event processing."""
        from app.crypto import sign_ed25519
        
        private_key, public_key = ed25519_keypair
        
        event_data = {"action": "test", "actor": "user1"}
        canonical = canonicalize_event(event_data)
        event_hash = compute_sha256(canonical.encode('utf-8'))
        signature = sign_ed25519(canonical.encode('utf-8'), private_key)
        
        # Register key in mock db
        mock_db.register_key("test:v1", public_key, "ed25519")
        
        # Process event
        event_id = await process_event(
            service_id="test-service",
            event_type="TEST_EVENT",
            event_canonical=canonical,
            event_data=event_data,
            event_hash=event_hash,
            signature=signature,
            public_key_id="test:v1",
            db=mock_db
        )
        
        assert event_id is not None
        assert event_id > 0
    
    @pytest.mark.asyncio
    async def test_process_multiple_events(self, mock_db, ed25519_keypair):
        """Test processing multiple events maintains chain."""
        from app.crypto import sign_ed25519
        
        private_key, public_key = ed25519_keypair
        mock_db.register_key("test:v1", public_key, "ed25519")
        
        event_ids = []
        
        for i in range(5):
            event_data = {"action": f"action_{i}", "sequence": i}
            canonical = canonicalize_event(event_data)
            event_hash = compute_sha256(canonical.encode('utf-8'))
            signature = sign_ed25519(canonical.encode('utf-8'), private_key)
            
            event_id = await process_event(
                service_id="test-service",
                event_type="TEST_EVENT",
                event_canonical=canonical,
                event_data=event_data,
                event_hash=event_hash,
                signature=signature,
                public_key_id="test:v1",
                db=mock_db
            )
            
            event_ids.append(event_id)
        
        # All event IDs should be unique
        assert len(set(event_ids)) == 5
        
        # IDs should be sequential
        assert event_ids == list(range(1, 6))


class TestEventIntegrity:
    """Tests for event data integrity."""
    
    def test_canonical_form_deterministic(self):
        """Test that canonical form is always the same for same data."""
        event_data = {
            "z": 1,
            "a": 2,
            "nested": {"b": 3, "a": 4}
        }
        
        results = [canonicalize_event(event_data) for _ in range(100)]
        
        # All results should be identical
        assert len(set(results)) == 1
    
    def test_event_hash_changes_with_data(self):
        """Test that any change in data changes the hash."""
        base_event = {"actor": "user", "action": "login", "timestamp": "2025-01-01"}
        base_canonical = canonicalize_event(base_event)
        base_hash = compute_sha256(base_canonical.encode('utf-8'))
        
        # Change actor
        modified1 = {"actor": "admin", "action": "login", "timestamp": "2025-01-01"}
        hash1 = compute_sha256(canonicalize_event(modified1).encode('utf-8'))
        assert hash1 != base_hash
        
        # Change action
        modified2 = {"actor": "user", "action": "logout", "timestamp": "2025-01-01"}
        hash2 = compute_sha256(canonicalize_event(modified2).encode('utf-8'))
        assert hash2 != base_hash
        
        # Change timestamp
        modified3 = {"actor": "user", "action": "login", "timestamp": "2025-01-02"}
        hash3 = compute_sha256(canonicalize_event(modified3).encode('utf-8'))
        assert hash3 != base_hash
        
        # All hashes should be unique
        assert len({base_hash.hex(), hash1.hex(), hash2.hex(), hash3.hex()}) == 4
