"""
Sample Publisher Client

This script demonstrates how to send signed audit events to the audit log service.
"""

import base64
import json
import sys
from datetime import datetime
from typing import Any, Dict

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend


class AuditLogPublisher:
    """
    Client for publishing signed audit events to the Audit Log Service.
    """
    
    def __init__(
        self,
        api_url: str,
        service_id: str,
        private_key_pem: str,
        public_key_id: str,
        client_cert: tuple[str, str] = None,
        ca_cert: str = None
    ):
        """
        Initialize the publisher.
        
        Args:
            api_url: Base URL of the audit log API
            service_id: Your service identifier
            private_key_pem: PEM-encoded Ed25519 private key
            public_key_id: ID of the registered public key
            client_cert: Tuple of (cert_path, key_path) for mTLS
            ca_cert: Path to CA certificate for verification
        """
        self.api_url = api_url.rstrip('/')
        self.service_id = service_id
        self.public_key_id = public_key_id
        
        # Load private key
        self.private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Configure HTTP client
        self.client = httpx.Client(
            cert=client_cert,
            verify=ca_cert or True,
            timeout=30.0
        )
    
    def canonicalize(self, event_data: Dict[str, Any]) -> str:
        """
        Convert event data to canonical form for signing.
        
        Args:
            event_data: Event data dictionary
            
        Returns:
            Canonical JSON string (sorted keys, no whitespace)
        """
        return json.dumps(event_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with the private key.
        
        Args:
            message: Message bytes to sign
            
        Returns:
            Signature bytes
        """
        if isinstance(self.private_key, Ed25519PrivateKey):
            return self.private_key.sign(message)
        else:
            raise ValueError("Unsupported key type")
    
    def publish(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        timestamp: datetime = None
    ) -> dict:
        """
        Publish a signed audit event.
        
        Args:
            event_type: Type of the event (e.g., "USER_LOGIN")
            event_data: Event data dictionary
            timestamp: Optional event timestamp (defaults to now)
            
        Returns:
            API response as dictionary
            
        Raises:
            httpx.HTTPError: On API errors
        """
        # Add timestamp if not provided
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        if 'timestamp' not in event_data:
            event_data['timestamp'] = timestamp.isoformat() + 'Z'
        
        # Canonicalize
        canonical = self.canonicalize(event_data)
        
        # Sign
        signature = self.sign(canonical.encode('utf-8'))
        
        # Build payload
        payload = {
            "service_id": self.service_id,
            "event_type": event_type,
            "event": canonical,
            "event_data": event_data,
            "signature": base64.b64encode(signature).decode('utf-8'),
            "public_key_id": self.public_key_id
        }
        
        # Send request
        response = self.client.post(
            f"{self.api_url}/v1/logs",
            json=payload
        )
        
        response.raise_for_status()
        return response.json()
    
    def close(self):
        """Close the HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def generate_keypair():
    """Generate a new Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
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


# Example usage
if __name__ == "__main__":
    # Generate keypair for demo
    private_key, public_key = generate_keypair()
    
    print("=== Audit Log Publisher Demo ===\n")
    print("Generated Public Key (register this with the service):")
    print(public_key)
    print("\n" + "="*50 + "\n")
    
    # Note: In real usage, you would:
    # 1. Register the public key with the audit log service first
    # 2. Store the private key securely
    # 3. Use mTLS certificates for authentication
    
    # Example of how to use the publisher:
    example_code = '''
# Example usage:
from publisher_client import AuditLogPublisher

# Initialize publisher
publisher = AuditLogPublisher(
    api_url="https://audit.example.com",
    service_id="my-service",
    private_key_pem=PRIVATE_KEY_PEM,  # Your Ed25519 private key
    public_key_id="my-service:v1",
    client_cert=("client.crt", "client.key"),  # For mTLS
    ca_cert="ca.crt"
)

# Publish an event
with publisher:
    response = publisher.publish(
        event_type="USER_LOGIN",
        event_data={
            "actor": "user@example.com",
            "action": "LOGIN",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "success": True
        }
    )
    print(f"Event published: {response}")
'''
    
    print("Example code:")
    print(example_code)
