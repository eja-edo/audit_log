"""
Script to register a new service with the Audit Log Service.
Generates a new Ed25519 keypair and registers the public key.
"""

import json
import base64
import requests
from nacl.signing import SigningKey
from datetime import datetime

# Configuration
API_URL = "http://localhost"
ADMIN_TOKEN = "my-super-secret-admin-token-2025"

def generate_ed25519_keypair():
    """Generate a new Ed25519 signing keypair."""
    # Generate private key
    signing_key = SigningKey.generate()
    
    # Get public key
    verify_key = signing_key.verify_key
    
    # Convert to PEM format
    # Ed25519 public key in raw format (32 bytes)
    public_key_bytes = bytes(verify_key)
    private_key_bytes = bytes(signing_key)
    
    # Create PEM format (simplified for Ed25519)
    # Standard Ed25519 public key PEM
    import base64
    
    # Ed25519 OID prefix for SPKI format
    ed25519_oid = bytes([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    spki_der = ed25519_oid + public_key_bytes
    
    public_key_pem = (
        "-----BEGIN PUBLIC KEY-----\n" +
        base64.b64encode(spki_der).decode() + "\n" +
        "-----END PUBLIC KEY-----"
    )
    
    # Ed25519 private key PEM (PKCS#8 format)
    # Simplified: just store raw key for demo
    private_key_b64 = base64.b64encode(private_key_bytes).decode()
    
    return {
        "public_key_pem": public_key_pem,
        "private_key_bytes": private_key_bytes,
        "private_key_b64": private_key_b64,
        "signing_key": signing_key
    }


def register_service(service_id: str, description: str = None):
    """Register a new service with the Audit Log API."""
    
    print(f"\n{'='*60}")
    print(f"Registering Service: {service_id}")
    print(f"{'='*60}\n")
    
    # Step 1: Generate keypair
    print("1. Generating Ed25519 keypair...")
    keypair = generate_ed25519_keypair()
    print("   ✓ Keypair generated successfully")
    
    # Step 2: Register public key with API (Service self-registration - no admin token needed)
    print("\n2. Submitting key registration request...")
    print("   (Note: Key will be in PENDING status until admin approves)")
    
    payload = {
        "service_id": service_id,
        "public_key_pem": keypair["public_key_pem"],
        "algorithm": "ed25519",
        "metadata": {
            "description": description or f"Service {service_id}",
            "registered_at": datetime.utcnow().isoformat(),
            "environment": "development"
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/v1/keys/register",
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✓ Key registration request submitted!")
            print(f"\n{'='*60}")
            print("REGISTRATION DETAILS")
            print(f"{'='*60}")
            print(f"Service ID:     {service_id}")
            print(f"Public Key ID:  {result.get('public_key_id', 'N/A')}")
            print(f"Status:         {result.get('status', 'N/A')}")
            print(f"\n⚠️  IMPORTANT: Admin must approve this key before you can submit events!")
            print(f"   Check status at: GET /v1/keys/status/{result.get('public_key_id', '')}")
            print(f"Algorithm:      {result.get('algorithm', 'ed25519')}")
            print(f"Created At:     {result.get('created_at', 'N/A')}")
            
            print(f"\n{'='*60}")
            print("PRIVATE KEY (SAVE THIS SECURELY!)")
            print(f"{'='*60}")
            print(f"Base64: {keypair['private_key_b64']}")
            
            print(f"\n{'='*60}")
            print("PUBLIC KEY")
            print(f"{'='*60}")
            print(keypair['public_key_pem'])
            
            # Save keys to files
            keys_dir = f"keys/{service_id}"
            import os
            os.makedirs(keys_dir, exist_ok=True)
            
            with open(f"{keys_dir}/private.key", "wb") as f:
                f.write(keypair['private_key_bytes'])
            
            with open(f"{keys_dir}/public.pem", "w") as f:
                f.write(keypair['public_key_pem'])
            
            with open(f"{keys_dir}/key_info.json", "w") as f:
                json.dump({
                    "service_id": service_id,
                    "public_key_id": result.get('public_key_id'),
                    "algorithm": "ed25519",
                    "created_at": result.get('created_at'),
                    "private_key_b64": keypair['private_key_b64']
                }, f, indent=2, default=str)
            
            print(f"\n{'='*60}")
            print("KEYS SAVED TO")
            print(f"{'='*60}")
            print(f"Private Key: {keys_dir}/private.key")
            print(f"Public Key:  {keys_dir}/public.pem")
            print(f"Key Info:    {keys_dir}/key_info.json")
            
            return result
            
        else:
            print(f"   ✗ Registration failed!")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"   ✗ Could not connect to API at {API_URL}")
        print("   Make sure the service is running: docker-compose up -d")
        return None
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return None


def test_signing(service_id: str):
    """Test signing an event with the registered service."""
    
    print(f"\n{'='*60}")
    print(f"Testing Event Signing for: {service_id}")
    print(f"{'='*60}\n")
    
    # Load private key
    try:
        with open(f"keys/{service_id}/private.key", "rb") as f:
            private_key_bytes = f.read()
        
        with open(f"keys/{service_id}/key_info.json", "r") as f:
            key_info = json.load(f)
    except FileNotFoundError:
        print("   ✗ Keys not found. Register the service first.")
        return
    
    # Create signing key
    signing_key = SigningKey(private_key_bytes)
    
    # Create test event
    event_data = {
        "action": "user.login",
        "user_id": "user_12345",
        "ip_address": "192.168.1.100",
        "timestamp": datetime.utcnow().isoformat(),
        "details": {
            "browser": "Chrome",
            "os": "Windows 11"
        }
    }
    
    # Canonical form for signing (sorted JSON)
    canonical_event = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
    
    # Sign the event
    signed = signing_key.sign(canonical_event.encode())
    signature = base64.b64encode(signed.signature).decode()
    
    print("1. Event Data:")
    print(json.dumps(event_data, indent=2))
    
    print(f"\n2. Canonical Form:")
    print(canonical_event)
    
    print(f"\n3. Signature (Base64):")
    print(signature)
    
    # Submit to API
    print(f"\n4. Submitting to API...")
    
    payload = {
        "service_id": service_id,
        "event_type": "USER_LOGIN",
        "event": canonical_event,
        "event_data": event_data,
        "signature": signature,
        "public_key_id": key_info["public_key_id"]
    }
    
    try:
        response = requests.post(
            f"{API_URL}/v1/logs",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        
    except Exception as e:
        print(f"   ✗ Error: {e}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        # Default: register a demo service
        service_id = "demo-service"
    else:
        service_id = sys.argv[1]
    
    description = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Register the service
    result = register_service(service_id, description)
    
    if result:
        # Test signing
        print("\n")
        test_signing(service_id)
