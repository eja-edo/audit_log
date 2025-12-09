#!/usr/bin/env python3
"""
Script ghi log cho service sử dụng RSA-PSS

RSA-PSS (Probabilistic Signature Scheme) là phương pháp ký an toàn hơn RSA PKCS#1 v1.5:
- Sử dụng padding ngẫu nhiên (probabilistic)
- Chống được Bleichenbacher attack
- Được khuyến nghị sử dụng cho các ứng dụng mới
"""

import base64
import hashlib
import json
import time
import os
import requests
from datetime import datetime

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ============================================================================
# CẤU HÌNH
# ============================================================================
API_BASE = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"

# Service info
SERVICE_ID = "billing-service"
SERVICE_DESCRIPTION = "Billing Service - RSA-PSS signatures"

# Thư mục lưu keys
KEYS_DIR = os.path.join(os.path.dirname(__file__), "demo_keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# Proxy config (set USE_PROXY = True để gửi qua Burp)
USE_PROXY = False
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
PROXIES = {
    "http": f"http://{PROXY_HOST}:{PROXY_PORT}",
    "https": f"http://{PROXY_HOST}:{PROXY_PORT}"
}

# ============================================================================
# KEY MANAGEMENT
# ============================================================================

def get_existing_key_for_service(service_id: str):
    """Kiểm tra xem service đã có key approved chưa."""
    kwargs = {"timeout": 30}
    if USE_PROXY:
        kwargs["proxies"] = PROXIES
    
    try:
        # Lấy danh sách keys của service
        resp = requests.get(
            f"{API_BASE}/v1/admin/keys",
            headers={"X-Admin-Token": ADMIN_TOKEN},
            params={"service_id": service_id, "status": "approved"},
            **kwargs
        )
        
        if resp.status_code == 200:
            data = resp.json()
            keys = data.get("keys", [])
            
            # Tìm key rsa-pss đã approved và chưa disabled
            for key in keys:
                if key.get("algorithm") == "rsa-pss" and key.get("status") == "approved":
                    return key.get("public_key_id")
    except Exception as e:
        print(f"  ⚠ Không thể kiểm tra key: {e}")
    
    return None


def get_key_file_path(service_id: str) -> str:
    """Trả về path file lưu key."""
    # Thử cả 2 tên file
    pem_path = os.path.join(KEYS_DIR, f"{service_id}_rsa_pss.pem")
    txt_path = os.path.join(KEYS_DIR, f"{service_id}_keys.txt")
    if os.path.exists(pem_path):
        return pem_path
    return txt_path


def save_private_key(service_id: str, key_id: str, private_pem: str):
    """Lưu private key và key_id vào file."""
    file_path = os.path.join(KEYS_DIR, f"{service_id}_rsa_pss.pem")
    with open(file_path, 'w') as f:
        f.write(f"# Key ID: {key_id}\n")
        f.write(f"# Algorithm: rsa-pss\n")
        f.write(f"# Service: {service_id}\n")
        f.write(f"# Created: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"KEY_ID={key_id}\n")
        f.write(private_pem)
    print(f"  💾 Đã lưu private key vào: {file_path}")


def load_private_key(service_id: str):
    """Đọc private key và key_id từ file."""
    file_path = get_key_file_path(service_id)
    if not os.path.exists(file_path):
        return None, None
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Parse key_id - hỗ trợ nhiều format
    key_id = None
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('KEY_ID='):
            key_id = line.split('=', 1)[1].strip()
            break
        elif line.startswith('Public Key ID:'):
            key_id = line.split(':', 1)[1].strip()
            break
    
    # Extract Private Key PEM
    private_start = content.find('-----BEGIN PRIVATE KEY-----')
    if private_start == -1:
        return None, None
    
    private_end = content.find('-----END PRIVATE KEY-----', private_start)
    if private_end == -1:
        return None, None
    
    private_pem = content[private_start:private_end + len('-----END PRIVATE KEY-----')]
    
    return key_id, private_pem


def generate_rsa_keypair():
    """Tạo RSA keypair với e=65537 (standard, an toàn)."""
    print("Tạo RSA-2048 keypair với e=65537...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard, safe
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
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


def sign_message_rsa_pss(message: bytes, private_key_pem: str) -> bytes:
    """Ký message bằng RSA-PSS."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def register_key(service_id: str, public_pem: str) -> str:
    """Đăng ký và approve key."""
    timestamp = int(time.time())
    key_id = f"{service_id}:v{timestamp}"
    
    kwargs = {"timeout": 30}
    if USE_PROXY:
        kwargs["proxies"] = PROXIES
    
    # Register
    resp = requests.post(
        f"{API_BASE}/v1/keys/register",
        json={
            "service_id": service_id,
            "public_key_id": key_id,
            "public_key_pem": public_pem,
            "algorithm": "rsa-pss",
            "description": SERVICE_DESCRIPTION
        },
        **kwargs
    )
    
    if resp.status_code not in (200, 201):
        print(f"  ✗ Register failed: {resp.text}")
        return None
    
    print(f"  ✓ Registered: {key_id}")
    
    # Approve
    resp = requests.post(
        f"{API_BASE}/v1/admin/keys/review",
        headers={"X-Admin-Token": ADMIN_TOKEN},
        json={"public_key_id": key_id, "action": "approve"},
        **kwargs
    )
    
    if resp.status_code == 200:
        print(f"  ✓ Key approved!")
    else:
        print(f"  ⚠ Approve: {resp.status_code}")
    
    return key_id


def send_log_event(service_id: str, key_id: str, private_key_pem: str, event_data: dict, event_type: str = "BILLING_EVENT"):
    """Gửi log event với chữ ký RSA-PSS hợp lệ."""
    # Canonical JSON
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    # Sign với RSA-PSS
    signature = sign_message_rsa_pss(event_canonical.encode('utf-8'), private_key_pem)
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    payload = {
        "service_id": service_id,
        "event_type": event_type,
        "event": event_canonical,
        "event_data": event_data,
        "signature": sig_b64,
        "public_key_id": key_id
    }
    
    kwargs = {"timeout": 30}
    if USE_PROXY:
        kwargs["proxies"] = PROXIES
    
    resp = requests.post(f"{API_BASE}/v1/logs", json=payload, **kwargs)
    return resp


def main():
    print("=" * 60)
    print("     RSA-PSS SERVICE - AUDIT LOG CLIENT")
    print("=" * 60)
    print()
    print(f"Service: {SERVICE_ID}")
    print(f"Algorithm: RSA-PSS (SHA-256)")
    print(f"Proxy: {'Enabled' if USE_PROXY else 'Disabled'}")
    print()
    
    # 1. Kiểm tra xem đã có key lưu trong file chưa
    print("━━━ Kiểm tra key đã tồn tại ━━━")
    saved_key_id, saved_private_pem = load_private_key(SERVICE_ID)
    
    key_id = None
    private_pem = None
    
    if saved_key_id and saved_private_pem:
        # Kiểm tra key còn valid trong server không
        existing_key_id = get_existing_key_for_service(SERVICE_ID)
        if existing_key_id == saved_key_id:
            print(f"  ✓ Sử dụng key đã lưu: {saved_key_id}")
            key_id = saved_key_id
            private_pem = saved_private_pem
        else:
            print(f"  ⚠ Key trong file không còn valid trên server")
            if existing_key_id:
                print(f"  ⚠ Server có key khác: {existing_key_id}")
                print(f"  ✗ Không có private key cho key này!")
                print(f"  → Cần disable key cũ trên server hoặc tìm private key")
                return
            print(f"  → Tạo key mới...")
    else:
        # Kiểm tra server có key không
        existing_key_id = get_existing_key_for_service(SERVICE_ID)
        if existing_key_id:
            print(f"  ⚠ Server có key: {existing_key_id}")
            print(f"  ✗ Không có private key trong file local!")
            print(f"  → Cần disable key cũ trên server hoặc tìm private key")
            return
    
    if not key_id:
        # Tạo key mới
        print("\n━━━ Tạo và đăng ký key mới ━━━")
        private_pem, public_pem = generate_rsa_keypair()
        key_id = register_key(SERVICE_ID, public_pem)
        if not key_id:
            print("✗ Không thể đăng ký key!")
            return
        
        # Lưu key vào file
        save_private_key(SERVICE_ID, key_id, private_pem)
        print(f"  Key ID: {key_id}")
    
    # 2. Gửi các log events
    print("\n━━━ Gửi log events ━━━\n")
    
    events = [
        {
            "type": "INVOICE_CREATED",
            "data": {
                "action": "invoice.create",
                "actor": "billing-worker@system",
                "invoice_id": f"INV-{int(time.time())}",
                "customer_id": "CUST-12345",
                "amount": 1500.00,
                "currency": "USD",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        },
        {
            "type": "PAYMENT_PROCESSED",
            "data": {
                "action": "payment.process",
                "actor": "payment-gateway@system",
                "payment_id": f"PAY-{int(time.time())}",
                "invoice_id": f"INV-{int(time.time())-1}",
                "amount": 1500.00,
                "method": "credit_card",
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        },
        {
            "type": "REFUND_ISSUED",
            "data": {
                "action": "refund.issue",
                "actor": "support@company.com",
                "refund_id": f"REF-{int(time.time())}",
                "original_payment_id": f"PAY-{int(time.time())-100}",
                "amount": 250.00,
                "reason": "Customer request",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
    ]
    
    for event in events:
        print(f"  Gửi {event['type']}...")
        resp = send_log_event(SERVICE_ID, key_id, private_pem, event['data'], event['type'])
        
        if resp.status_code == 200:
            resp_json = resp.json()
            print(f"    ✓ Accepted! Event ID: {resp_json.get('id')}")
            if resp_json.get('message'):
                print(f"    Message: {resp_json.get('message')}")
        else:
            print(f"    ✗ Failed: {resp.status_code} - {resp.text}")
        print()
    
    print("━━━ Hoàn tất ━━━")
    print(f"Đã gửi {len(events)} events từ {SERVICE_ID}")
    print(f"Algorithm: RSA-PSS (an toàn, chống Bleichenbacher attack)")


if __name__ == "__main__":
    main()
