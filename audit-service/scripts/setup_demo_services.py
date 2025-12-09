"""
Script tạo 3 demo services với 3 loại thuật toán khác nhau.
Lưu keys và tạo sample audit logs cho mỗi service.

Services:
1. auth-service      - Ed25519 (recommended)
2. billing-service   - RSA-PSS (secure RSA)
3. legacy-service    - RSA PKCS#1 v1.5 (vulnerable demo)
"""

import json
import base64
import time
import requests
from datetime import datetime, timedelta
from pathlib import Path

# Cryptographic libraries
from nacl.signing import SigningKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Configuration
API_URL = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"
OUTPUT_DIR = Path(__file__).parent / "demo_keys"


def generate_ed25519_keypair():
    """Generate Ed25519 keypair."""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    public_key_bytes = bytes(verify_key)
    private_key_bytes = bytes(signing_key)
    
    # Ed25519 SPKI format
    ed25519_oid = bytes([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    spki_der = ed25519_oid + public_key_bytes
    
    public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\n" +
        base64.b64encode(spki_der).decode() + "\n" +
        "-----END PUBLIC KEY-----"
    )
    
    return {
        "algorithm": "ed25519",
        "public_key_pem": public_key_pem,
        "private_key_bytes": private_key_bytes,
        "private_key_b64": base64.b64encode(private_key_bytes).decode(),
        "signing_key": signing_key
    }


def generate_rsa_keypair(key_size=2048):
    """Generate RSA keypair for RSA-PSS or RSA PKCS#1 v1.5."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    return {
        "public_key_pem": public_key_pem,
        "private_key_pem": private_key_pem,
        "private_key": private_key,
        "public_key": public_key
    }


def sign_ed25519(message: bytes, signing_key: SigningKey) -> bytes:
    """Sign message with Ed25519."""
    signed = signing_key.sign(message)
    return signed.signature


def sign_rsa_pss(message: bytes, private_key) -> bytes:
    """Sign message with RSA-PSS."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def sign_rsa_pkcs1v15(message: bytes, private_key) -> bytes:
    """Sign message with RSA PKCS#1 v1.5 (vulnerable)."""
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def register_key_and_approve(service_id: str, public_key_pem: str, algorithm: str) -> str:
    """Register key and auto-approve it."""
    # Step 1: Register key (service self-registration)
    payload = {
        "service_id": service_id,
        "public_key_pem": public_key_pem,
        "algorithm": algorithm,
        "metadata": {
            "description": f"Demo {algorithm} service",
            "created_by_script": "setup_demo_services.py",
            "created_at": datetime.utcnow().isoformat()
        }
    }
    
    response = requests.post(
        f"{API_URL}/v1/keys/register",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code != 200:
        # Check if already exists
        if "already exists" in response.text.lower():
            # Try to get existing key
            headers = {"X-Admin-Token": ADMIN_TOKEN}
            keys_resp = requests.get(
                f"{API_URL}/v1/admin/keys?service_id={service_id}",
                headers=headers
            )
            if keys_resp.status_code == 200:
                keys = keys_resp.json().get("keys", [])
                for key in keys:
                    if key.get("status") == "approved" and not key.get("disabled_at"):
                        return key["public_key_id"]
        raise Exception(f"Failed to register key: {response.text}")
    
    result = response.json()
    public_key_id = result["public_key_id"]
    
    # Step 2: Admin approve
    if result.get("status") == "pending":
        headers = {
            "X-Admin-Token": ADMIN_TOKEN,
            "Content-Type": "application/json"
        }
        approve_payload = {
            "public_key_id": public_key_id,
            "action": "approve"
        }
        
        approve_response = requests.post(
            f"{API_URL}/v1/admin/keys/review",
            json=approve_payload,
            headers=headers
        )
        
        if approve_response.status_code != 200:
            raise Exception(f"Failed to approve key: {approve_response.text}")
    
    return public_key_id


def submit_event(service_id: str, event_type: str, event_data: dict, 
                 public_key_id: str, sign_func, sign_key) -> dict:
    """Submit a signed audit event."""
    # Create canonical form (sorted keys, no whitespace)
    event_canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    # Sign the canonical form
    signature_bytes = sign_func(event_canonical.encode('utf-8'), sign_key)
    signature_b64 = base64.b64encode(signature_bytes).decode()
    
    payload = {
        "service_id": service_id,
        "event_type": event_type,
        "event": event_canonical,
        "event_data": event_data,
        "signature": signature_b64,
        "public_key_id": public_key_id
    }
    
    response = requests.post(
        f"{API_URL}/v1/logs",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    return response.json()


def save_keys_to_file(service_info: dict, filepath: Path):
    """Save service keys and info to file."""
    content = f"""
================================================================================
SERVICE: {service_info['service_id']}
================================================================================
Algorithm:      {service_info['algorithm']}
Public Key ID:  {service_info['public_key_id']}
Created At:     {datetime.utcnow().isoformat()}

--------------------------------------------------------------------------------
PUBLIC KEY (PEM):
--------------------------------------------------------------------------------
{service_info['public_key_pem']}

--------------------------------------------------------------------------------
PRIVATE KEY:
--------------------------------------------------------------------------------
{service_info['private_key_data']}

--------------------------------------------------------------------------------
USAGE EXAMPLE:
--------------------------------------------------------------------------------
Service ID:     {service_info['service_id']}
Public Key ID:  {service_info['public_key_id']}
Algorithm:      {service_info['algorithm']}

To submit an event:
1. Create event_data as JSON
2. Create canonical form: json.dumps(event_data, sort_keys=True, separators=(',',':'))
3. Sign canonical form with private key using {service_info['algorithm']}
4. POST to /v1/logs with signature (base64)

================================================================================
"""
    filepath.write_text(content)


def main():
    print("=" * 70)
    print("DEMO SERVICES SETUP SCRIPT")
    print("=" * 70)
    
    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    # =========================================================================
    # Service 1: auth-service with Ed25519
    # =========================================================================
    print("\n[1/3] Setting up auth-service (Ed25519)...")
    
    ed25519_keys = generate_ed25519_keypair()
    auth_service_id = "auth-service"
    
    try:
        auth_key_id = register_key_and_approve(
            auth_service_id,
            ed25519_keys["public_key_pem"],
            "ed25519"
        )
        print(f"      ✓ Key registered: {auth_key_id}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        return
    
    auth_info = {
        "service_id": auth_service_id,
        "algorithm": "ed25519",
        "public_key_id": auth_key_id,
        "public_key_pem": ed25519_keys["public_key_pem"],
        "private_key_data": f"Base64: {ed25519_keys['private_key_b64']}",
        "signing_key": ed25519_keys["signing_key"]
    }
    
    save_keys_to_file(auth_info, OUTPUT_DIR / "auth-service_keys.txt")
    print(f"      ✓ Keys saved to: {OUTPUT_DIR / 'auth-service_keys.txt'}")
    
    # Create auth events
    auth_events = [
        {"event_type": "USER_LOGIN", "data": {"user_id": "user001", "ip": "192.168.1.100", "method": "password", "success": True}},
        {"event_type": "USER_LOGIN", "data": {"user_id": "user002", "ip": "10.0.0.50", "method": "oauth", "provider": "google", "success": True}},
        {"event_type": "USER_LOGOUT", "data": {"user_id": "user001", "session_duration_minutes": 45}},
        {"event_type": "PASSWORD_CHANGE", "data": {"user_id": "user003", "changed_by": "self", "ip": "172.16.0.25"}},
        {"event_type": "USER_LOGIN_FAILED", "data": {"user_id": "admin", "ip": "203.0.113.50", "reason": "invalid_password", "attempt": 3}},
        {"event_type": "MFA_ENABLED", "data": {"user_id": "user001", "mfa_type": "totp", "enabled_by": "self"}},
        {"event_type": "SESSION_CREATED", "data": {"user_id": "user004", "session_id": "sess_abc123", "device": "Chrome/Windows"}},
        {"event_type": "TOKEN_REFRESHED", "data": {"user_id": "user002", "token_type": "access_token", "expires_in": 3600}},
    ]
    
    print(f"      Creating {len(auth_events)} auth events...")
    for i, evt in enumerate(auth_events):
        evt["data"]["timestamp"] = (datetime.utcnow() - timedelta(hours=len(auth_events)-i)).isoformat()
        result = submit_event(
            auth_service_id, evt["event_type"], evt["data"],
            auth_key_id, sign_ed25519, auth_info["signing_key"]
        )
        status = "✓" if result.get("status") == "accepted" else "✗"
        print(f"        {status} {evt['event_type']}: {result.get('status', 'error')}")
    
    # =========================================================================
    # Service 2: billing-service with RSA-PSS
    # =========================================================================
    print("\n[2/3] Setting up billing-service (RSA-PSS)...")
    
    rsa_pss_keys = generate_rsa_keypair(2048)
    billing_service_id = "billing-service"
    
    try:
        billing_key_id = register_key_and_approve(
            billing_service_id,
            rsa_pss_keys["public_key_pem"],
            "rsa-pss"
        )
        print(f"      ✓ Key registered: {billing_key_id}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        return
    
    billing_info = {
        "service_id": billing_service_id,
        "algorithm": "rsa-pss",
        "public_key_id": billing_key_id,
        "public_key_pem": rsa_pss_keys["public_key_pem"],
        "private_key_data": rsa_pss_keys["private_key_pem"],
        "private_key": rsa_pss_keys["private_key"]
    }
    
    save_keys_to_file(billing_info, OUTPUT_DIR / "billing-service_keys.txt")
    print(f"      ✓ Keys saved to: {OUTPUT_DIR / 'billing-service_keys.txt'}")
    
    # Create billing events
    billing_events = [
        {"event_type": "INVOICE_CREATED", "data": {"invoice_id": "INV-2025-001", "customer_id": "cust_001", "amount": 1500.00, "currency": "USD"}},
        {"event_type": "PAYMENT_RECEIVED", "data": {"payment_id": "PAY-001", "invoice_id": "INV-2025-001", "amount": 1500.00, "method": "credit_card"}},
        {"event_type": "SUBSCRIPTION_STARTED", "data": {"subscription_id": "SUB-001", "customer_id": "cust_002", "plan": "enterprise", "monthly_fee": 299.99}},
        {"event_type": "REFUND_ISSUED", "data": {"refund_id": "REF-001", "payment_id": "PAY-002", "amount": 50.00, "reason": "partial_refund"}},
        {"event_type": "INVOICE_OVERDUE", "data": {"invoice_id": "INV-2025-003", "customer_id": "cust_003", "days_overdue": 15, "amount_due": 750.00}},
        {"event_type": "PAYMENT_FAILED", "data": {"payment_id": "PAY-003", "invoice_id": "INV-2025-004", "error": "insufficient_funds", "retry_count": 2}},
        {"event_type": "SUBSCRIPTION_CANCELLED", "data": {"subscription_id": "SUB-002", "customer_id": "cust_004", "reason": "customer_request", "refund_amount": 99.99}},
        {"event_type": "TAX_CALCULATED", "data": {"invoice_id": "INV-2025-005", "subtotal": 1000.00, "tax_rate": 0.08, "tax_amount": 80.00, "total": 1080.00}},
    ]
    
    print(f"      Creating {len(billing_events)} billing events...")
    for i, evt in enumerate(billing_events):
        evt["data"]["timestamp"] = (datetime.utcnow() - timedelta(hours=len(billing_events)-i)).isoformat()
        result = submit_event(
            billing_service_id, evt["event_type"], evt["data"],
            billing_key_id, sign_rsa_pss, billing_info["private_key"]
        )
        status = "✓" if result.get("status") == "accepted" else "✗"
        print(f"        {status} {evt['event_type']}: {result.get('status', 'error')}")
    
    # =========================================================================
    # Service 3: legacy-service with RSA PKCS#1 v1.5 (VULNERABLE)
    # =========================================================================
    print("\n[3/3] Setting up legacy-service (RSA PKCS#1 v1.5 - VULNERABLE)...")
    
    rsa_pkcs1_keys = generate_rsa_keypair(2048)
    legacy_service_id = "legacy-service"
    
    try:
        legacy_key_id = register_key_and_approve(
            legacy_service_id,
            rsa_pkcs1_keys["public_key_pem"],
            "rsa-pkcs1v15"
        )
        print(f"      ✓ Key registered: {legacy_key_id}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        return
    
    legacy_info = {
        "service_id": legacy_service_id,
        "algorithm": "rsa-pkcs1v15-vulnerable",  # For Bleichenbacher attack demo
        "public_key_id": legacy_key_id,
        "public_key_pem": rsa_pkcs1_keys["public_key_pem"],
        "private_key_data": rsa_pkcs1_keys["private_key_pem"],
        "private_key": rsa_pkcs1_keys["private_key"]
    }
    
    save_keys_to_file(legacy_info, OUTPUT_DIR / "legacy-service_keys.txt")
    print(f"      ✓ Keys saved to: {OUTPUT_DIR / 'legacy-service_keys.txt'}")
    print(f"      ⚠️  WARNING: This service uses vulnerable RSA PKCS#1 v1.5!")
    
    # Create legacy events
    legacy_events = [
        {"event_type": "DATA_EXPORT", "data": {"export_id": "EXP-001", "user_id": "admin", "tables": ["users", "orders"], "format": "csv"}},
        {"event_type": "CONFIG_CHANGE", "data": {"setting": "max_connections", "old_value": 100, "new_value": 200, "changed_by": "admin"}},
        {"event_type": "BATCH_JOB_STARTED", "data": {"job_id": "JOB-001", "job_type": "daily_report", "scheduled_by": "cron"}},
        {"event_type": "BATCH_JOB_COMPLETED", "data": {"job_id": "JOB-001", "duration_seconds": 145, "records_processed": 15000, "status": "success"}},
        {"event_type": "SYSTEM_ALERT", "data": {"alert_id": "ALERT-001", "severity": "warning", "message": "High memory usage detected", "threshold": "85%"}},
        {"event_type": "DATABASE_BACKUP", "data": {"backup_id": "BKP-001", "database": "production", "size_mb": 2500, "duration_seconds": 300}},
        {"event_type": "API_RATE_LIMIT", "data": {"client_id": "api_client_005", "endpoint": "/v1/data", "requests_per_minute": 1000, "limit": 500}},
        {"event_type": "MAINTENANCE_MODE", "data": {"enabled": True, "reason": "scheduled_upgrade", "estimated_duration_minutes": 30, "initiated_by": "ops-team"}},
    ]
    
    print(f"      Creating {len(legacy_events)} legacy events...")
    for i, evt in enumerate(legacy_events):
        evt["data"]["timestamp"] = (datetime.utcnow() - timedelta(hours=len(legacy_events)-i)).isoformat()
        result = submit_event(
            legacy_service_id, evt["event_type"], evt["data"],
            legacy_key_id, sign_rsa_pkcs1v15, legacy_info["private_key"]
        )
        status = "✓" if result.get("status") == "accepted" else "✗"
        print(f"        {status} {evt['event_type']}: {result.get('status', 'error')}")
    
    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 70)
    print("SETUP COMPLETE!")
    print("=" * 70)
    
    summary = f"""
SERVICES CREATED:
-----------------
1. auth-service     (Ed25519)       - {auth_key_id}
2. billing-service  (RSA-PSS)       - {billing_key_id}
3. legacy-service   (RSA-PKCS1v15)  - {legacy_key_id}

EVENTS CREATED:
---------------
- auth-service:     {len(auth_events)} events
- billing-service:  {len(billing_events)} events
- legacy-service:   {len(legacy_events)} events
- TOTAL:            {len(auth_events) + len(billing_events) + len(legacy_events)} events

KEY FILES SAVED TO:
-------------------
{OUTPUT_DIR}/
├── auth-service_keys.txt
├── billing-service_keys.txt
└── legacy-service_keys.txt

VERIFY SETUP:
-------------
1. Check events: GET http://localhost/v1/logs
2. Check keys:   GET http://localhost/v1/admin/keys (with X-Admin-Token)
3. Web UI:       Open web/index.html in browser
"""
    
    print(summary)
    
    # Save summary
    summary_file = OUTPUT_DIR / "SUMMARY.txt"
    summary_file.write_text(f"Generated at: {datetime.utcnow().isoformat()}\n{summary}")
    print(f"\nSummary saved to: {summary_file}")


if __name__ == "__main__":
    main()
