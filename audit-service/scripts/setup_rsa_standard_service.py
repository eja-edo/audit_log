#!/usr/bin/env python3
"""
Setup RSA Standard Service (e=65537)

Script này tạo và đăng ký một RSA keypair với e=65537 (standard).
Lưu tất cả thông tin (public key, key_id, n, e) vào file để dùng cho demo tấn công.

Với e=65537:
- Không thể dùng cube root attack như e=3
- Cần sử dụng Bleichenbacher Padding Oracle Attack
"""

import base64
import json
import os
import time
import requests
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CẤU HÌNH
# ============================================================================
API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"

SERVICE_ID = "vulnerable-rsa-service"
SERVICE_DESCRIPTION = "RSA PKCS#1 v1.5 Service với e=65537 - Demo Padding Oracle Attack"

# Thư mục lưu keys
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# Output file
OUTPUT_FILE = os.path.join(KEYS_DIR, "rsa_standard_service_info.json")


def print_header(title: str):
    print(f"\n{'━'*60}")
    print(f"  {title}")
    print(f"{'━'*60}\n")


def generate_rsa_keypair_standard():
    """
    Tạo RSA keypair với e=65537 (standard, an toàn hơn e=3).
    
    Với e=65537:
    - Cube root attack KHÔNG hoạt động
    - Cần Padding Oracle Attack để khai thác
    """
    print("Tạo RSA-2048 keypair với e=65537 (standard)...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard, không vulnerable với cube root
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    pub_numbers = public_key.public_numbers()
    priv_numbers = private_key.private_numbers()
    
    print(f"  RSA modulus (n): {pub_numbers.n.bit_length()} bits")
    print(f"  Public exponent (e): {pub_numbers.e}")
    print(f"  → e=65537 là giá trị chuẩn, cube root attack KHÔNG hoạt động")
    print(f"  → Cần Padding Oracle Attack để forge signature")
    
    return private_key, public_key


def get_key_pem(private_key, public_key):
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


def register_key_with_api(service_id: str, public_pem: str) -> str:
    """Đăng ký public key với API và approve."""
    timestamp = int(time.time())
    key_id = f"{service_id}:v{timestamp}"
    
    print(f"Đăng ký key: {key_id}")
    
    # Register key
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_id": key_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pkcs1v15-vulnerable",  # Vulnerable algorithm for demo
            "description": SERVICE_DESCRIPTION
        }
    )
    
    if resp.status_code not in (200, 201):
        print(f"  ✗ Register failed: {resp.text}")
        return None
    
    print(f"  ✓ Registered: {key_id}")
    
    # Approve key
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
        print(f"  ⚠ Approve response: {resp.status_code}")
    
    return key_id


def save_service_info(service_id: str, key_id: str, public_key, private_pem: str, public_pem: str):
    """
    Lưu thông tin service vào file JSON.
    
    File này chứa TẤT CẢ thông tin công khai:
    - public_key_pem
    - n (modulus)
    - e (public exponent)
    - key_id
    
    VÀ private key (chỉ để so sánh kết quả, KHÔNG dùng trong attack)
    """
    pub_numbers = public_key.public_numbers()
    
    service_info = {
        "service_id": service_id,
        "key_id": key_id,
        "algorithm": "rsa-pkcs1v15-vulnerable",
        "created_at": datetime.utcnow().isoformat() + "Z",
        
        # PUBLIC INFORMATION - Attacker có thể biết
        "public": {
            "public_key_pem": public_pem,
            "n": pub_numbers.n,  # RSA modulus
            "n_hex": hex(pub_numbers.n),
            "n_bits": pub_numbers.n.bit_length(),
            "e": pub_numbers.e,  # Public exponent
            "key_size_bytes": (pub_numbers.n.bit_length() + 7) // 8
        },
        
        # PRIVATE INFORMATION - CHỈ để verify kết quả attack
        # KHÔNG ĐƯỢC SỬ DỤNG trong script tấn công!
        "private": {
            "private_key_pem": private_pem,
            "note": "CHỈ để verify kết quả - KHÔNG DÙNG trong attack!"
        },
        
        # API endpoints
        "api": {
            "base_url": API_BASE,
            "submit_log": f"{API_BASE}/v1/logs",
            "note": "Endpoint /v1/logs sử dụng vulnerable verifier cho rsa-pkcs1v15-vulnerable"
        },
        
        # Attack info
        "attack_notes": {
            "vulnerability": "Weak PKCS#1 v1.5 signature verification",
            "attack_type": "Bleichenbacher Padding Oracle Attack",
            "oracle_behavior": [
                "00 01 prefix → khác với các prefix khác",
                "00 separator found → khác với không tìm thấy",
                "Hash match → khác với hash mismatch"
            ],
            "why_not_cube_root": f"e={pub_numbers.e} quá lớn, sig^e luôn > n"
        }
    }
    
    # Save to file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(service_info, f, indent=2)
    
    print(f"\n✓ Đã lưu thông tin vào: {OUTPUT_FILE}")
    
    return service_info


def create_sample_signed_event(service_id: str, key_id: str, private_pem: str):
    """
    Tạo một event với chữ ký THẬT (dùng private key).
    Lưu lại để so sánh với forged signature.
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    private_key = serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Sample event
    event_data = {
        "action": "sample.test_event",
        "actor": "test@example.com",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "details": "This is a legitimately signed event"
    }
    
    # Canonical form
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    message = event_canonical.encode('utf-8')
    
    # Sign with PKCS#1 v1.5 (real signature)
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    sample = {
        "event_data": event_data,
        "event_canonical": event_canonical,
        "message_bytes_hex": message.hex(),
        "signature_b64": base64.b64encode(signature).decode('utf-8'),
        "signature_hex": signature.hex()
    }
    
    sample_file = os.path.join(KEYS_DIR, "rsa_standard_sample_event.json")
    with open(sample_file, 'w') as f:
        json.dump(sample, f, indent=2)
    
    print(f"✓ Đã tạo sample signed event: {sample_file}")
    
    # Submit to API to verify it works
    print("\nGửi sample event lên API để xác nhận...")
    
    resp = requests.post(
        f"{API_BASE}/v1/logs",
        json={
            "service_id": service_id,
            "event_type": "SAMPLE_TEST",
            "event": event_canonical,
            "event_data": event_data,
            "signature": sample["signature_b64"],
            "public_key_id": key_id
        }
    )
    
    if resp.status_code == 200:
        result = resp.json()
        print(f"  ✓ Event accepted! ID: {result.get('id')}")
        print(f"  Message: {result.get('message')}")
    else:
        print(f"  ✗ Failed: {resp.status_code} - {resp.text}")
    
    return sample


def main():
    print("=" * 60)
    print("   SETUP RSA STANDARD SERVICE (e=65537)")
    print("   For Bleichenbacher Padding Oracle Attack Demo")
    print("=" * 60)
    
    # ========================================
    # PHẦN 1: Tạo keypair
    # ========================================
    print_header("PHẦN 1: TẠO RSA KEYPAIR")
    
    private_key, public_key = generate_rsa_keypair_standard()
    private_pem, public_pem = get_key_pem(private_key, public_key)
    
    # ========================================
    # PHẦN 2: Đăng ký với API
    # ========================================
    print_header("PHẦN 2: ĐĂNG KÝ VÀ APPROVE KEY")
    
    key_id = register_key_with_api(SERVICE_ID, public_pem)
    
    if not key_id:
        print("✗ Không thể đăng ký key!")
        return
    
    # ========================================
    # PHẦN 3: Lưu thông tin
    # ========================================
    print_header("PHẦN 3: LƯU THÔNG TIN SERVICE")
    
    service_info = save_service_info(
        SERVICE_ID, key_id, public_key, private_pem, public_pem
    )
    
    print("\nThông tin PUBLIC (attacker có thể biết):")
    print(f"  service_id: {service_info['service_id']}")
    print(f"  key_id: {service_info['key_id']}")
    print(f"  n bits: {service_info['public']['n_bits']}")
    print(f"  e: {service_info['public']['e']}")
    print(f"  key_size_bytes: {service_info['public']['key_size_bytes']}")
    
    # ========================================
    # PHẦN 4: Tạo sample event
    # ========================================
    print_header("PHẦN 4: TẠO SAMPLE SIGNED EVENT")
    
    create_sample_signed_event(SERVICE_ID, key_id, private_pem)
    
    # ========================================
    # HOÀN TẤT
    # ========================================
    print_header("HOÀN TẤT")
    
    print("Đã setup xong service với thông tin:")
    print(f"  • Service ID: {SERVICE_ID}")
    print(f"  • Key ID: {key_id}")
    print(f"  • Algorithm: RSA PKCS#1 v1.5 (vulnerable)")
    print(f"  • e = 65537 (standard)")
    print()
    print("Files đã tạo:")
    print(f"  1. {OUTPUT_FILE}")
    print(f"     → Chứa n, e, public_key_pem, key_id")
    print(f"  2. {os.path.join(KEYS_DIR, 'rsa_standard_sample_event.json')}")
    print(f"     → Sample event với chữ ký thật")
    print()
    print("Bước tiếp theo:")
    print("  Chạy script 'bleichenbacher_padding_oracle_attack.py'")
    print("  để thực hiện tấn công Padding Oracle!")


if __name__ == "__main__":
    main()
