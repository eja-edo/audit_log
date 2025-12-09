"""
Cryptographic operations: signature generation, verification, and hashing.
"""

import base64
import hashlib
import logging
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.backends import default_backend
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class SignatureVerificationError(CryptoError):
    """Raised when signature verification fails."""
    pass


class KeyParseError(CryptoError):
    """Raised when key parsing fails."""
    pass


def compute_sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def compute_sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def compute_chain_hash(
    prev_chain_hash: bytes,
    event_hash: bytes,
    service_id: str
) -> bytes:
    """
    Compute the chain hash linking events together.
    
    Formula: SHA256(prev_chain_hash || event_hash || service_id)
    """
    chain_input = prev_chain_hash + event_hash + service_id.encode('utf-8')
    return compute_sha256(chain_input)


def canonicalize_event(event_data: dict) -> str:
    """
    Convert event data to canonical form for signing.
    - Sorted keys
    - No whitespace
    - Consistent JSON encoding
    """
    import json
    return json.dumps(event_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def parse_public_key(public_key_pem: str, algorithm: str) -> PublicKeyTypes:
    """
    Parse a PEM-encoded public key.
    
    Args:
        public_key_pem: PEM-encoded public key string
        algorithm: Either 'ed25519' or 'rsa-pss'
        
    Returns:
        Parsed public key object
        
    Raises:
        KeyParseError: If key parsing fails
    """
    try:
        key_bytes = public_key_pem.encode('utf-8')
        public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
        
        if algorithm == 'ed25519' and not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise KeyParseError(f"Expected Ed25519 key, got {type(public_key).__name__}")
        elif algorithm == 'rsa-pss' and not isinstance(public_key, rsa.RSAPublicKey):
            raise KeyParseError(f"Expected RSA key, got {type(public_key).__name__}")
            
        return public_key
        
    except Exception as e:
        raise KeyParseError(f"Failed to parse public key: {e}")


def verify_ed25519_signature(
    message: bytes,
    signature: bytes,
    public_key_pem: str
) -> bool:
    """
    Verify an Ed25519 signature using PyNaCl (libsodium wrapper).
    
    Args:
        message: Original message bytes
        signature: Signature bytes to verify
        public_key_pem: PEM-encoded Ed25519 public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Parse PEM to extract raw 32-byte Ed25519 public key
        # Remove PEM headers and decode base64
        pem_lines = public_key_pem.strip().split('\n')
        pem_body = ''.join(line for line in pem_lines 
                          if not line.startswith('-----'))
        key_der = base64.b64decode(pem_body)
        
        # For Ed25519, the raw key is the last 32 bytes of the DER encoding
        raw_public_key = key_der[-32:]
        
        verify_key = VerifyKey(raw_public_key)
        verify_key.verify(message, signature)
        return True
        
    except BadSignatureError:
        return False
    except Exception as e:
        logger.debug(f"Ed25519 verification error: {e}")
        return False


def verify_rsa_pss_signature(
    message: bytes,
    signature: bytes,
    public_key_pem: str
) -> bool:
    """
    Verify an RSA-PSS signature using cryptography library.
    
    Args:
        message: Original message bytes
        signature: Signature bytes to verify
        public_key_pem: PEM-encoded RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        if not isinstance(public_key, rsa.RSAPublicKey):
            return False
        
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
        
    except Exception as e:
        logger.debug(f"RSA-PSS verification error: {e}")
        return False


def verify_rsa_pkcs1v15_secure(
    message: bytes,
    signature: bytes,
    public_key_pem: str
) -> bool:
    """
    SECURE RSA PKCS#1 v1.5 signature verification using cryptography library.
    
    This uses the standard library implementation which properly verifies:
    - Full PKCS#1 v1.5 padding structure
    - ASN.1 DigestInfo encoding
    - Correct hash value and position
    
    This is NOT vulnerable to Bleichenbacher signature forgery attacks.
    
    Args:
        message: Original message bytes
        signature: Signature bytes to verify
        public_key_pem: PEM-encoded RSA public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        if not isinstance(public_key, rsa.RSAPublicKey):
            logger.debug("Not an RSA key")
            return False
        
        # Use standard library verification - SECURE!
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
        
    except Exception as e:
        logger.debug(f"RSA PKCS#1 v1.5 (secure) verification error: {e}")
        return False


def verify_signature(
    message: bytes,
    signature: bytes,
    public_key_pem: str,
    algorithm: str
) -> bool:
    """
    Verify a signature using the specified algorithm.
    
    This function uses constant-time operations where possible
    to prevent timing attacks.
    
    Args:
        message: Original message bytes
        signature: Signature bytes
        public_key_pem: PEM-encoded public key
        algorithm: 'ed25519' or 'rsa-pss'
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if algorithm == 'ed25519':
            return verify_ed25519_signature(message, signature, public_key_pem)
        elif algorithm == 'rsa-pss':
            return verify_rsa_pss_signature(message, signature, public_key_pem)
        else:
            logger.warning(f"Unknown algorithm: {algorithm}")
            return False
    except Exception as e:
        # Swallow all exceptions - constant time response
        logger.debug(f"Signature verification error: {e}")
        return False


def generate_ed25519_keypair() -> Tuple[str, str]:
    """
    Generate a new Ed25519 key pair.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate a new RSA key pair.
    
    Args:
        key_size: RSA key size in bits (default: 2048)
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_gen
    
    private_key = rsa_gen.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def sign_ed25519(message: bytes, private_key_pem: str) -> bytes:
    """
    Sign a message using Ed25519 private key.
    
    Args:
        message: Message to sign
        private_key_pem: PEM-encoded Ed25519 private key
        
    Returns:
        Signature bytes
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    if not isinstance(private_key, Ed25519PrivateKey):
        raise CryptoError("Expected Ed25519 private key")
    
    return private_key.sign(message)


def sign_rsa_pss(message: bytes, private_key_pem: str) -> bytes:
    """
    Sign a message using RSA-PSS.
    
    Args:
        message: Message to sign
        private_key_pem: PEM-encoded RSA private key
        
    Returns:
        Signature bytes
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("Expected RSA private key")
    
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def generate_random_bytes(length: int = 32) -> bytes:
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time."""
    return secrets.compare_digest(a, b)


# ============================================================================
# VULNERABLE IMPLEMENTATIONS - FOR SECURITY DEMO ONLY
# ============================================================================
# WARNING: These functions contain INTENTIONAL vulnerabilities to demonstrate
# RSA PKCS#1 v1.5 padding oracle attacks. NEVER use in production!

def verify_rsa_pkcs1v15_vulnerable(
    message: bytes,
    signature: bytes,
    public_key_pem: str
) -> tuple[bool, str]:
    """
    INTENTIONALLY VULNERABLE RSA PKCS#1 v1.5 signature verification.
    
    WEAK VERIFIER - Chỉ check:
    1. EM bắt đầu bằng 00 01
    2. Hash xuất hiện đâu đó trong EM
    
    VULNERABILITIES:
    - Cho phép Bleichenbacher signature forgery với e=3
    - Không check cấu trúc PKCS#1 v1.5 đầy đủ
    - Không check ASN.1 DigestInfo
    - Không check đủ FF padding bytes
    
    FOR SECURITY DEMONSTRATION ONLY!
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        if not isinstance(public_key, rsa.RSAPublicKey):
            return False, "ERROR: Not an RSA key"
        
        # Perform raw RSA: signature^e mod n
        pub_numbers = public_key.public_numbers()
        n = pub_numbers.n
        e = pub_numbers.e
        
        sig_int = int.from_bytes(signature, byteorder='big')
        decrypted_int = pow(sig_int, e, n)
        
        # Convert to bytes
        key_size = (n.bit_length() + 7) // 8
        em = decrypted_int.to_bytes(key_size, byteorder='big')
        
        # WEAK CHECK 1: Chỉ check 2 bytes đầu là 00 01
        if em[0:2] != b'\x00\x01':
            return False, "PADDING_ERROR: Invalid header (expected 0x00 0x01)"
        
        # WEAK CHECK 2: Tìm ANY 00 byte sau vị trí 2 (trong 20 bytes đầu)
        separator_idx = -1
        for i in range(2, min(20, len(em))):
            if em[i] == 0x00:
                separator_idx = i
                break
        
        if separator_idx == -1:
            return False, "PADDING_ERROR: No 00 separator in first 20 bytes"
        
        # WEAK CHECK 3: Chỉ check hash CÓ XUẤT HIỆN ĐÂU ĐÓ trong EM!
        # Đây là lỗ hổng chính cho phép Bleichenbacher attack
        expected_hash = hashlib.sha256(message).digest()
        
        # Tìm hash ở bất kỳ đâu trong phần còn lại!
        remaining = em[separator_idx + 1:]
        if expected_hash in remaining:
            return True, f"WEAK_VALID: Hash found (e={e}) - VULNERABLE!"
        else:
            return False, f"HASH_MISMATCH: Hash not found in EM"
            
    except Exception as ex:
        # VULNERABILITY: Leaking exception details
        return False, f"EXCEPTION: {type(ex).__name__}: {str(ex)}"


def verify_signature_vulnerable(
    message: bytes,
    signature: bytes,
    public_key_pem: str,
    algorithm: str
) -> tuple[bool, str]:
    """
    VULNERABLE signature verification that leaks information.
    
    FOR SECURITY DEMONSTRATION ONLY!
    
    Algorithms:
    - 'rsa-pkcs1v15-vulnerable': Uses weak verifier (INSECURE - for demo)
    - 'rsa-pkcs1v15': Uses standard library (SECURE)
    - 'rsa-pss': RSA-PSS (SECURE)
    - 'ed25519': Ed25519 (SECURE)
    """
    if algorithm == 'rsa-pkcs1v15-vulnerable':
        # VULNERABLE - for security demonstration only!
        return verify_rsa_pkcs1v15_vulnerable(message, signature, public_key_pem)
    elif algorithm == 'rsa-pkcs1v15':
        # SECURE - uses standard library
        result = verify_rsa_pkcs1v15_secure(message, signature, public_key_pem)
        if result:
            return True, "VALID: RSA PKCS#1 v1.5 signature verified (secure)"
        else:
            return False, "SIGNATURE_INVALID: RSA PKCS#1 v1.5 verification failed"
    elif algorithm == 'ed25519':
        # Ed25519 doesn't have this vulnerability
        result = verify_ed25519_signature(message, signature, public_key_pem)
        if result:
            return True, "VALID: Ed25519 signature verified"
        else:
            return False, "SIGNATURE_INVALID: Ed25519 verification failed"
    elif algorithm == 'rsa-pss':
        result = verify_rsa_pss_signature(message, signature, public_key_pem)
        if result:
            return True, "VALID: RSA-PSS signature verified"
        else:
            return False, "SIGNATURE_INVALID: RSA-PSS verification failed"
    else:
        return False, f"UNKNOWN_ALGORITHM: {algorithm}"
