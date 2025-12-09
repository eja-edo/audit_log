"""
Tests for cryptographic operations.
"""

import pytest
from app.crypto import (
    compute_sha256,
    compute_sha256_hex,
    compute_chain_hash,
    canonicalize_event,
    verify_ed25519_signature,
    verify_rsa_pss_signature,
    verify_signature,
    generate_ed25519_keypair,
    generate_rsa_keypair,
    sign_ed25519,
    sign_rsa_pss,
    constant_time_compare
)


class TestHashing:
    """Tests for hashing functions."""
    
    def test_compute_sha256(self):
        """Test SHA-256 computation."""
        data = b"hello world"
        result = compute_sha256(data)
        
        assert len(result) == 32
        assert isinstance(result, bytes)
    
    def test_compute_sha256_consistency(self):
        """Test that SHA-256 is consistent."""
        data = b"test data"
        result1 = compute_sha256(data)
        result2 = compute_sha256(data)
        
        assert result1 == result2
    
    def test_compute_sha256_hex(self):
        """Test SHA-256 hex output."""
        data = b"hello"
        result = compute_sha256_hex(data)
        
        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_compute_chain_hash(self):
        """Test chain hash computation."""
        prev_hash = b'\x00' * 32
        event_hash = compute_sha256(b"event data")
        service_id = "test-service"
        
        chain_hash = compute_chain_hash(prev_hash, event_hash, service_id)
        
        assert len(chain_hash) == 32
        assert isinstance(chain_hash, bytes)
    
    def test_chain_hash_deterministic(self):
        """Test that chain hash is deterministic."""
        prev_hash = b'\x00' * 32
        event_hash = compute_sha256(b"event data")
        service_id = "test-service"
        
        hash1 = compute_chain_hash(prev_hash, event_hash, service_id)
        hash2 = compute_chain_hash(prev_hash, event_hash, service_id)
        
        assert hash1 == hash2
    
    def test_chain_hash_sensitivity(self):
        """Test that chain hash changes with different inputs."""
        prev_hash = b'\x00' * 32
        event_hash = compute_sha256(b"event data")
        
        hash1 = compute_chain_hash(prev_hash, event_hash, "service-a")
        hash2 = compute_chain_hash(prev_hash, event_hash, "service-b")
        
        assert hash1 != hash2


class TestCanonicalization:
    """Tests for event canonicalization."""
    
    def test_canonicalize_simple(self):
        """Test basic canonicalization."""
        event = {"a": 1, "b": 2}
        result = canonicalize_event(event)
        
        assert result == '{"a":1,"b":2}'
    
    def test_canonicalize_sorted_keys(self):
        """Test that keys are sorted."""
        event = {"z": 1, "a": 2, "m": 3}
        result = canonicalize_event(event)
        
        assert result == '{"a":2,"m":3,"z":1}'
    
    def test_canonicalize_no_whitespace(self):
        """Test that there's no extra whitespace."""
        event = {"key": "value with spaces"}
        result = canonicalize_event(event)
        
        assert result == '{"key":"value with spaces"}'
        assert "  " not in result  # No double spaces
    
    def test_canonicalize_nested(self):
        """Test nested object canonicalization."""
        event = {"outer": {"inner": "value"}}
        result = canonicalize_event(event)
        
        assert result == '{"outer":{"inner":"value"}}'
    
    def test_canonicalize_deterministic(self):
        """Test that canonicalization is deterministic."""
        event = {"b": 1, "a": 2, "c": 3}
        
        result1 = canonicalize_event(event)
        result2 = canonicalize_event(event)
        
        assert result1 == result2


class TestEd25519:
    """Tests for Ed25519 signatures."""
    
    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = generate_ed25519_keypair()
        
        assert "BEGIN PRIVATE KEY" in private_key
        assert "END PRIVATE KEY" in private_key
        assert "BEGIN PUBLIC KEY" in public_key
        assert "END PUBLIC KEY" in public_key
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        private_key, public_key = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = sign_ed25519(message, private_key)
        
        assert len(signature) == 64
        assert verify_ed25519_signature(message, signature, public_key)
    
    def test_verify_invalid_signature(self):
        """Test that invalid signatures are rejected."""
        _, public_key = generate_ed25519_keypair()
        message = b"Hello, World!"
        invalid_signature = b'\x00' * 64
        
        assert not verify_ed25519_signature(message, invalid_signature, public_key)
    
    def test_verify_wrong_message(self):
        """Test that wrong messages don't verify."""
        private_key, public_key = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = sign_ed25519(message, private_key)
        
        assert not verify_ed25519_signature(b"Different message", signature, public_key)
    
    def test_verify_wrong_key(self):
        """Test that wrong keys don't verify."""
        private_key1, _ = generate_ed25519_keypair()
        _, public_key2 = generate_ed25519_keypair()
        message = b"Hello, World!"
        
        signature = sign_ed25519(message, private_key1)
        
        assert not verify_ed25519_signature(message, signature, public_key2)


class TestRSAPSS:
    """Tests for RSA-PSS signatures."""
    
    def test_generate_keypair(self):
        """Test RSA keypair generation."""
        private_key, public_key = generate_rsa_keypair(2048)
        
        assert "BEGIN PRIVATE KEY" in private_key
        assert "BEGIN PUBLIC KEY" in public_key
    
    def test_sign_and_verify(self):
        """Test RSA-PSS signing and verification."""
        private_key, public_key = generate_rsa_keypair(2048)
        message = b"Hello, World!"
        
        signature = sign_rsa_pss(message, private_key)
        
        assert len(signature) == 256  # 2048 bits = 256 bytes
        assert verify_rsa_pss_signature(message, signature, public_key)
    
    def test_verify_invalid_signature(self):
        """Test that invalid RSA signatures are rejected."""
        _, public_key = generate_rsa_keypair(2048)
        message = b"Hello, World!"
        invalid_signature = b'\x00' * 256
        
        assert not verify_rsa_pss_signature(message, invalid_signature, public_key)


class TestVerifySignature:
    """Tests for the unified verify_signature function."""
    
    def test_verify_ed25519(self):
        """Test Ed25519 verification via unified function."""
        private_key, public_key = generate_ed25519_keypair()
        message = b"Test message"
        signature = sign_ed25519(message, private_key)
        
        assert verify_signature(message, signature, public_key, "ed25519")
    
    def test_verify_rsa_pss(self):
        """Test RSA-PSS verification via unified function."""
        private_key, public_key = generate_rsa_keypair(2048)
        message = b"Test message"
        signature = sign_rsa_pss(message, private_key)
        
        assert verify_signature(message, signature, public_key, "rsa-pss")
    
    def test_verify_unknown_algorithm(self):
        """Test that unknown algorithms return False."""
        _, public_key = generate_ed25519_keypair()
        
        assert not verify_signature(b"message", b"sig", public_key, "unknown")


class TestConstantTimeCompare:
    """Tests for constant-time comparison."""
    
    def test_equal_strings(self):
        """Test that equal byte strings return True."""
        a = b"hello"
        b = b"hello"
        
        assert constant_time_compare(a, b)
    
    def test_unequal_strings(self):
        """Test that unequal byte strings return False."""
        a = b"hello"
        b = b"world"
        
        assert not constant_time_compare(a, b)
    
    def test_different_lengths(self):
        """Test that different length strings return False."""
        a = b"short"
        b = b"longer string"
        
        assert not constant_time_compare(a, b)
