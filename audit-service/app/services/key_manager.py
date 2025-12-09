"""
Key management service.

Handles public key registration, rotation, and lifecycle management.
"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from app.database import Database
from app.crypto import generate_ed25519_keypair, generate_rsa_keypair

logger = logging.getLogger(__name__)


class KeyManager:
    """
    Service for managing cryptographic keys.
    
    Handles:
    - Public key registration
    - Key rotation
    - Key revocation/disabling
    - Key lifecycle tracking
    """
    
    def __init__(self, db: Database):
        self.db = db
    
    async def register_key(
        self,
        service_id: str,
        public_key_pem: str,
        algorithm: str,
        created_by: str = "system",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a new public key for a service.
        
        Args:
            service_id: The service identifier
            public_key_pem: PEM-encoded public key
            algorithm: Key algorithm ('ed25519' or 'rsa-pss')
            created_by: Who is registering the key
            metadata: Optional metadata about the key
            
        Returns:
            The generated public_key_id
            
        Raises:
            ValueError: If an active key already exists for the service
        """
        # Generate versioned key ID
        public_key_id = f"{service_id}:v{int(time.time())}"
        
        # Check for existing active key
        existing = await self.db.fetchval(
            """
            SELECT public_key_id FROM key_registry 
            WHERE service_id = $1 AND disabled_at IS NULL AND rotated_to IS NULL
            """,
            service_id
        )
        
        if existing:
            raise ValueError(
                f"Active key '{existing}' already exists for service '{service_id}'. "
                "Use rotate_key() instead."
            )
        
        # Insert new key
        await self.db.execute(
            """
            INSERT INTO key_registry (
                public_key_id, service_id, public_key_pem,
                algorithm, created_by, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6)
            """,
            public_key_id,
            service_id,
            public_key_pem,
            algorithm,
            created_by,
            metadata
        )
        
        logger.info(f"Registered new key: {public_key_id} for service {service_id}")
        
        return public_key_id
    
    async def rotate_key(
        self,
        service_id: str,
        new_public_key_pem: str,
        algorithm: str,
        rotated_by: str = "system"
    ) -> str:
        """
        Rotate the public key for a service.
        
        This creates a new key and marks the old key as rotated.
        The old key can still be used to verify historical signatures.
        
        Args:
            service_id: The service identifier
            new_public_key_pem: The new PEM-encoded public key
            algorithm: Key algorithm
            rotated_by: Who is performing the rotation
            
        Returns:
            The new public_key_id
        """
        new_key_id = f"{service_id}:v{int(time.time())}"
        
        async with self.db.transaction() as conn:
            # Find and update old key
            old_key_id = await conn.fetchval(
                """
                UPDATE key_registry 
                SET rotated_to = $1
                WHERE service_id = $2 
                  AND disabled_at IS NULL 
                  AND rotated_to IS NULL
                RETURNING public_key_id
                """,
                new_key_id,
                service_id
            )
            
            # Insert new key
            await conn.execute(
                """
                INSERT INTO key_registry (
                    public_key_id, service_id, public_key_pem,
                    algorithm, created_by
                ) VALUES ($1, $2, $3, $4, $5)
                """,
                new_key_id,
                service_id,
                new_public_key_pem,
                algorithm,
                rotated_by
            )
            
            # Log the rotation
            await conn.execute(
                """
                INSERT INTO admin_audit (action, actor, target_resource, details, signature)
                VALUES ('key_rotation', $1, $2, $3, $4)
                """,
                rotated_by,
                service_id,
                {"old_key": old_key_id, "new_key": new_key_id},
                b''
            )
        
        logger.info(f"Rotated key for {service_id}: {old_key_id} -> {new_key_id}")
        
        return new_key_id
    
    async def disable_key(
        self,
        public_key_id: str,
        disabled_by: str = "system",
        reason: Optional[str] = None
    ) -> bool:
        """
        Disable a public key.
        
        Disabled keys cannot be used for signature verification.
        This should be used when a key is compromised.
        
        Args:
            public_key_id: The key to disable
            disabled_by: Who is disabling the key
            reason: Optional reason for disabling
            
        Returns:
            True if key was disabled, False if key not found
        """
        result = await self.db.execute(
            "UPDATE key_registry SET disabled_at = now() WHERE public_key_id = $1",
            public_key_id
        )
        
        if result == "UPDATE 0":
            return False
        
        # Log the action
        await self.db.execute(
            """
            INSERT INTO admin_audit (action, actor, target_resource, details, signature)
            VALUES ('key_disabled', $1, $2, $3, $4)
            """,
            disabled_by,
            public_key_id,
            {"reason": reason or "unspecified"},
            b''
        )
        
        logger.warning(f"Key disabled: {public_key_id} by {disabled_by}")
        
        return True
    
    async def get_key(self, public_key_id: str) -> Optional[Dict[str, Any]]:
        """
        Get key information by ID.
        
        Args:
            public_key_id: The key ID
            
        Returns:
            Key information dict or None
        """
        key = await self.db.fetchrow(
            """
            SELECT public_key_id, service_id, public_key_pem, algorithm,
                   created_at, created_by, disabled_at, rotated_to, metadata
            FROM key_registry
            WHERE public_key_id = $1
            """,
            public_key_id
        )
        
        return dict(key) if key else None
    
    async def get_active_key(self, service_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the currently active key for a service.
        
        Args:
            service_id: The service identifier
            
        Returns:
            Active key information or None
        """
        key = await self.db.fetchrow(
            """
            SELECT public_key_id, public_key_pem, algorithm, created_at
            FROM key_registry
            WHERE service_id = $1 
              AND disabled_at IS NULL 
              AND rotated_to IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            service_id
        )
        
        return dict(key) if key else None
    
    async def list_keys(
        self,
        service_id: Optional[str] = None,
        include_disabled: bool = False,
        include_rotated: bool = True
    ) -> List[Dict[str, Any]]:
        """
        List registered keys.
        
        Args:
            service_id: Optional filter by service
            include_disabled: Include disabled keys
            include_rotated: Include rotated keys
            
        Returns:
            List of key information dicts
        """
        conditions = []
        params = []
        
        if service_id:
            conditions.append(f"service_id = ${len(params) + 1}")
            params.append(service_id)
        
        if not include_disabled:
            conditions.append("disabled_at IS NULL")
        
        if not include_rotated:
            conditions.append("rotated_to IS NULL")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        keys = await self.db.fetch(
            f"""
            SELECT public_key_id, service_id, algorithm,
                   created_at, disabled_at, rotated_to
            FROM key_registry
            WHERE {where_clause}
            ORDER BY created_at DESC
            """,
            *params
        )
        
        return [dict(k) for k in keys]
    
    async def get_key_history(self, service_id: str) -> List[Dict[str, Any]]:
        """
        Get the key rotation history for a service.
        
        Args:
            service_id: The service identifier
            
        Returns:
            List of keys in chronological order
        """
        keys = await self.db.fetch(
            """
            SELECT public_key_id, algorithm, created_at, 
                   disabled_at, rotated_to,
                   CASE 
                       WHEN disabled_at IS NOT NULL THEN 'disabled'
                       WHEN rotated_to IS NOT NULL THEN 'rotated'
                       ELSE 'active'
                   END as status
            FROM key_registry
            WHERE service_id = $1
            ORDER BY created_at ASC
            """,
            service_id
        )
        
        return [dict(k) for k in keys]


def load_key_from_file(path: Path) -> str:
    """
    Load a key from a file.
    
    Args:
        path: Path to the key file
        
    Returns:
        Key contents as string
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file isn't readable
    """
    return path.read_text()


def generate_service_keypair(
    algorithm: str = "ed25519"
) -> tuple[str, str]:
    """
    Generate a new keypair for a service.
    
    Args:
        algorithm: 'ed25519' or 'rsa-pss'
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    if algorithm == "ed25519":
        return generate_ed25519_keypair()
    elif algorithm == "rsa-pss":
        return generate_rsa_keypair()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
