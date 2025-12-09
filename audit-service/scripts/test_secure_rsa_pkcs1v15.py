#!/usr/bin/env python3
"""
Test script for secure RSA PKCS#1 v1.5 implementation.

This script demonstrates:
1. Secure rsa-pkcs1v15 (uses cryptography library - strict verification)
2. Vulnerable rsa-pkcs1v15-vulnerable (weak verification - for demo)

The secure version will REJECT forged signatures that the vulnerable version accepts.
"""

import requests
import time
import hashlib
import base64
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

API_BASE = "http://localhost/v1"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"

# Burp Suite proxy settings
BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080
BURP_PROXIES = None


def check_burp_proxy() -> bool:
    """Check if Burp Suite proxy is running on port 8080."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((BURP_PROXY_HOST, BURP_PROXY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def setup_proxy():
    """Setup proxy if Burp Suite is detected."""
    global BURP_PROXIES
    if check_burp_proxy():
        BURP_PROXIES = {
            "http": f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}",
            "https": f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
        }
        print(f"  🔍 Burp Suite detected on port {BURP_PROXY_PORT}")
        print(f"  📡 All requests will go through proxy")
        return True
    else:
        print(f"  ℹ️  Burp Suite not detected on port {BURP_PROXY_PORT}")
        print(f"  📡 Requests will go directly to API")
        return False


def make_request(method: str, url: str, **kwargs) -> requests.Response:
    """Make HTTP request, optionally through Burp proxy."""
    kwargs.setdefault('timeout', 10)
    if BURP_PROXIES:
        kwargs['proxies'] = BURP_PROXIES
        kwargs['verify'] = False  # Burp uses self-signed cert
    
    if method.upper() == 'GET':
        return requests.get(url, **kwargs)
    elif method.upper() == 'POST':
        return requests.post(url, **kwargs)
    elif method.upper() == 'PUT':
        return requests.put(url, **kwargs)
    elif method.upper() == 'DELETE':
        return requests.delete(url, **kwargs)
    else:
        raise ValueError(f"Unsupported method: {method}")

def generate_rsa_key(e: int = 65537) -> tuple:
    """Generate RSA key pair with specified e."""
    private_key = rsa.generate_private_key(
        public_exponent=e,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_key, private_pem, public_pem


def register_key(service_id: str, public_pem: str, algorithm: str) -> str:
    """Register and approve a key."""
    # Register
    resp = make_request(
        'POST',
        f"{API_BASE}/keys/register",
        json={
            "service_id": service_id,
            "public_key_pem": public_pem,
            "algorithm": algorithm
        }
    )
    if resp.status_code != 200:
        raise Exception(f"Register failed: {resp.text}")
    
    key_id = resp.json().get("public_key_id") or resp.json().get("key_id")
    
    # Approve using admin endpoint
    resp = make_request(
        'POST',
        f"http://localhost/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"}
    )
    if resp.status_code != 200:
        raise Exception(f"Approve failed: {resp.text}")
    
    return key_id


def sign_message(private_key, message: bytes) -> bytes:
    """Sign message with RSA PKCS#1 v1.5."""
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def forge_signature_e3(message: bytes, n: int) -> bytes:
    """
    Forge signature using cube root attack (only works for e=3).
    This is the same attack from the demo scripts.
    """
    msg_hash = hashlib.sha256(message).digest()
    
    # Build EM: 00 01 FF 00 [HASH] [GARBAGE]
    # Weak verifier accepts hash anywhere after separator
    prefix = b'\x00\x01\xff\x00'  # 4 bytes
    garbage_len = 256 - len(prefix) - len(msg_hash)
    em = prefix + msg_hash + b'\x00' * garbage_len
    
    em_int = int.from_bytes(em, 'big')
    
    # Cube root search using Newton's method
    def integer_cube_root(x):
        if x == 0:
            return 0
        guess = 1 << ((x.bit_length() + 2) // 3)
        while True:
            new = (2 * guess + x // (guess * guess)) // 3
            if new >= guess:
                return guess
            guess = new
    
    base = integer_cube_root(em_int)
    
    # Search around the cube root
    for delta in range(-100, 101):
        candidate = base + delta
        if candidate <= 0:
            continue
            
        result = candidate ** 3
        if result >= 2 ** 2048:  # Too large
            continue
            
        result_bytes = result.to_bytes(256, 'big')
        
        # Check if weak verifier would accept
        if result_bytes[0:2] != b'\x00\x01':
            continue
        
        # Find separator in bytes 2-19
        sep_idx = None
        for i in range(2, 20):
            if result_bytes[i] == 0x00:
                sep_idx = i
                break
        
        if sep_idx is None:
            continue
        
        # Check if hash appears after separator
        if msg_hash in result_bytes[sep_idx+1:]:
            return candidate.to_bytes(256, 'big')
    
    return None


def test_algorithm(algorithm: str, use_forge: bool = False, e: int = 65537):
    """Test submitting a log with given algorithm."""
    print(f"\n{'='*60}")
    print(f"  Testing: {algorithm}")
    print(f"  Using {'FORGED' if use_forge else 'VALID'} signature, e={e}")
    print(f"{'='*60}")
    
    import random
    ts = int(time.time())
    rand_suffix = random.randint(1000, 9999)
    service_id = f"test-{algorithm.replace('-', '')[:10]}-{ts}-{rand_suffix}"
    
    # Generate key
    private_key, private_pem, public_pem = generate_rsa_key(e=e)
    n = private_key.public_key().public_numbers().n
    
    print(f"  Generated RSA-{e} key")
    
    # Register
    try:
        key_id = register_key(service_id, public_pem, algorithm)
        print(f"  ✓ Registered key: {key_id}")
    except Exception as ex:
        print(f"  ✗ Registration failed: {ex}")
        return None
    
    # Create event
    event = {
        "timestamp": "2025-01-15T10:30:00Z",
        "actor": {"id": f"user-{ts}", "type": "user"},
        "action": "test.event",
        "status": "success",
        "resource": {"type": "test", "id": "1"}
    }
    
    import json
    message = json.dumps(event, separators=(',', ':'), sort_keys=True).encode()
    print(f"  Message hash: {hashlib.sha256(message).hexdigest()[:16]}...")
    
    # Create signature
    if use_forge and e == 3:
        print(f"  Attempting cube root forge...")
        signature = forge_signature_e3(message, n)
        if signature is None:
            print(f"  ✗ Forge failed")
            return None
        print(f"  ✓ Forged signature")
    elif use_forge:
        # Create random garbage signature
        import os
        signature = os.urandom(256)
        print(f"  Using random garbage as signature")
    else:
        signature = sign_message(private_key, message)
        print(f"  ✓ Valid signature created")
    
    signature_b64 = base64.b64encode(signature).decode()
    
    # Submit to API
    payload = {
        "service_id": service_id,
        "public_key_id": key_id,
        "event_type": "test_event",
        "event": json.dumps(event, separators=(',', ':'), sort_keys=True),
        "event_data": event,
        "signature": signature_b64
    }
    
    resp = make_request('POST', "http://localhost/v1/logs", json=payload)
    
    print(f"\n  API Response:")
    print(f"    Status: {resp.status_code}")
    
    try:
        body = resp.json()
        print(f"    Body: {body}")
    except:
        print(f"    Body: {resp.text[:200]}")
    
    if resp.status_code == 200 and "accepted" in resp.text.lower():
        return "ACCEPTED"
    else:
        return "REJECTED"


def main():
    print("="*70)
    print("  RSA PKCS#1 v1.5: SECURE vs VULNERABLE Comparison")
    print("="*70)
    
    # Check for Burp Suite proxy
    print(f"\n{'-'*60}")
    print("  PROXY DETECTION")
    print(f"{'-'*60}")
    setup_proxy()
    print()
    
    results = []
    
    # Test 1: Secure algorithm with VALID signature
    r1 = test_algorithm("rsa-pkcs1v15", use_forge=False, e=65537)
    results.append(("rsa-pkcs1v15", "Valid sig", r1))
    
    # Test 2: Vulnerable algorithm with VALID signature
    r2 = test_algorithm("rsa-pkcs1v15-vulnerable", use_forge=False, e=65537)
    results.append(("rsa-pkcs1v15-vulnerable", "Valid sig", r2))
    
    # Test 3: Secure algorithm with FORGED signature (e=3)
    r3 = test_algorithm("rsa-pkcs1v15", use_forge=True, e=3)
    results.append(("rsa-pkcs1v15", "Forged sig (e=3)", r3))
    
    # Test 4: Vulnerable algorithm with FORGED signature (e=3)
    r4 = test_algorithm("rsa-pkcs1v15-vulnerable", use_forge=True, e=3)
    results.append(("rsa-pkcs1v15-vulnerable", "Forged sig (e=3)", r4))
    
    # Summary
    print("\n" + "="*70)
    print("  SUMMARY")
    print("="*70)
    
    print("\n  ┌─────────────────────────────┬──────────────────┬──────────────┐")
    print("  │         Algorithm           │   Signature      │    Result    │")
    print("  ├─────────────────────────────┼──────────────────┼──────────────┤")
    for algo, sig_type, result in results:
        algo_str = algo.ljust(27)
        sig_str = sig_type.ljust(16)
        res_str = (result or "ERROR").ljust(12)
        if result == "ACCEPTED" and "Forged" in sig_type:
            res_str = "⚠️ ACCEPTED"
        elif result == "REJECTED" and "Forged" in sig_type:
            res_str = "✓ REJECTED"
        elif result == "ACCEPTED":
            res_str = "✓ ACCEPTED"
        print(f"  │ {algo_str}│ {sig_str}│ {res_str}│")
    print("  └─────────────────────────────┴──────────────────┴──────────────┘")
    
    print("\n  KEY FINDINGS:")
    print("  • rsa-pkcs1v15 (secure): Uses cryptography library, REJECTS forged sigs")
    print("  • rsa-pkcs1v15-vulnerable: Weak verification, ACCEPTS forged sigs (e=3)")
    print()


if __name__ == "__main__":
    main()
