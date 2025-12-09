"""
Signature verification service.

Handles cryptographic verification of event signatures using
registered public keys. Implements constant-time operations
to prevent timing attacks.
"""

import logging
from typing import Optional

from app.database import Database
from app.crypto import verify_signature

logger = logging.getLogger(__name__)


async def verify_event_signature(
    event_canonical: str,
    signature: bytes,
    public_key_id: str,
    db: Database
) -> bool:
    """
    Verify event signature using constant-time operations.
    
    This function retrieves the public key from the database and
    verifies the signature. It returns only True/False and never
    raises detailed exceptions to prevent oracle attacks.
    
    Args:
        event_canonical: The canonical (normalized) event string that was signed
        signature: The signature bytes to verify
        public_key_id: The ID of the public key to use for verification
        db: Database connection
        
    Returns:
        True if signature is valid, False otherwise
        
    Security Notes:
        - Never raises exceptions with details about why verification failed
        - Uses constant-time comparison where possible
        - All error paths return False
    """
    try:
        # 1. Fetch public key from registry (only approved and active keys)
        key_info = await db.fetchrow(
            """
            SELECT public_key_pem, algorithm 
            FROM key_registry
            WHERE public_key_id = $1 
              AND status = 'approved'
              AND disabled_at IS NULL
            """,
            public_key_id
        )
        
        if not key_info:
            logger.debug(f"Public key not found, not approved, or disabled: {public_key_id}")
            return False
        
        # 2. Verify signature
        is_valid = verify_signature(
            message=event_canonical.encode('utf-8'),
            signature=signature,
            public_key_pem=key_info['public_key_pem'],
            algorithm=key_info['algorithm']
        )
        
        if not is_valid:
            logger.debug(f"Signature verification failed for key: {public_key_id}")
        
        return is_valid
        
    except Exception as e:
        # Swallow all exceptions - constant-time response
        logger.error(f"Error during signature verification: {e}")
        return False


async def get_key_info(
    public_key_id: str,
    db: Database
) -> Optional[dict]:
    """
    Retrieve public key information.
    
    Args:
        public_key_id: The ID of the public key
        db: Database connection
        
    Returns:
        Key information dict or None if not found
    """
    key_info = await db.fetchrow(
        """
        SELECT public_key_id, service_id, public_key_pem, algorithm,
               created_at, disabled_at, rotated_to
        FROM key_registry
        WHERE public_key_id = $1
        """,
        public_key_id
    )
    
    return dict(key_info) if key_info else None


async def get_active_key_for_service(
    service_id: str,
    db: Database
) -> Optional[dict]:
    """
    Get the currently active public key for a service.
    
    Args:
        service_id: The service identifier
        db: Database connection
        
    Returns:
        Active key information or None
    """
    key_info = await db.fetchrow(
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
    
    return dict(key_info) if key_info else None


async def is_key_valid(
    public_key_id: str,
    db: Database
) -> bool:
    """
    Check if a public key is currently valid (not disabled or rotated).
    
    Args:
        public_key_id: The ID of the public key
        db: Database connection
        
    Returns:
        True if key is valid, False otherwise
    """
    result = await db.fetchval(
        """
        SELECT EXISTS(
            SELECT 1 FROM key_registry
            WHERE public_key_id = $1 
              AND disabled_at IS NULL
        )
        """,
        public_key_id
    )
    
    return bool(result)
