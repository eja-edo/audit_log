"""
Public Key Registration endpoints for services.
Services can submit key registration requests without admin authentication.
Admin approval is required before keys become active.
"""

import json
import logging
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends

from app.models import PublicKeyRegistration, PublicKeyInfo
from app.database import Database, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/keys", tags=["key-registration"])


@router.post("/register", response_model=PublicKeyInfo)
async def request_key_registration(
    registration: PublicKeyRegistration,
    db: Database = Depends(get_db)
):
    """
    Submit a public key registration request.
    
    This endpoint allows services to submit their public keys for registration.
    The key will be in 'pending' status until an administrator approves it.
    
    **No authentication required** - Services can self-register.
    
    **Request Body:**
    - `service_id`: Service identifier
    - `public_key_pem`: PEM-encoded public key
    - `algorithm`: Key algorithm ('ed25519', 'rsa-pss', or 'rsa-pkcs1v15')
    - `metadata`: Optional metadata about the key
    
    **Returns:**
    - Key information with status='pending'
    
    **Note:** The key cannot be used for signature verification until 
    an administrator approves it.
    """
    # Generate versioned key ID
    public_key_id = f"{registration.service_id}:v{int(time.time())}"
    
    async with db.transaction() as conn:
        # Check for existing pending request
        existing_pending = await conn.fetchrow(
            """
            SELECT public_key_id FROM key_registry 
            WHERE service_id = $1 AND status = 'pending'
            """,
            registration.service_id
        )
        
        if existing_pending:
            raise HTTPException(
                status_code=400,
                detail=f"A pending key request already exists for this service. "
                       f"Please wait for admin approval or contact administrator."
            )
        
        # Check for existing active (approved) key
        existing_active = await conn.fetchrow(
            """
            SELECT public_key_id FROM key_registry 
            WHERE service_id = $1 AND status = 'approved' AND disabled_at IS NULL
            """,
            registration.service_id
        )
        
        if existing_active:
            raise HTTPException(
                status_code=400,
                detail=f"An active key already exists for this service. "
                       f"Use key rotation endpoint to update your key."
            )
        
        # Insert new key with pending status
        await conn.execute(
            """
            INSERT INTO key_registry (
                public_key_id, service_id, public_key_pem, 
                algorithm, status, created_by, metadata
            ) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            """,
            public_key_id,
            registration.service_id,
            registration.public_key_pem,
            registration.algorithm,
            registration.service_id,  # created_by = service itself
            json.dumps(registration.metadata) if registration.metadata else None
        )
        
        logger.info(f"Key registration request submitted: {public_key_id}")
    
    return PublicKeyInfo(
        public_key_id=public_key_id,
        service_id=registration.service_id,
        algorithm=registration.algorithm,
        status="pending",
        created_at=datetime.utcnow(),
        created_by=registration.service_id,
        reviewed_by=None,
        reviewed_at=None,
        rejection_reason=None,
        disabled_at=None,
        rotated_to=None
    )


@router.get("/status/{public_key_id}")
async def get_key_status(
    public_key_id: str,
    db: Database = Depends(get_db)
):
    """
    Check the status of a key registration request.
    
    Services can poll this endpoint to check if their key has been
    approved or rejected.
    
    **Returns:**
    - `status`: 'pending', 'approved', or 'rejected'
    - `rejection_reason`: Reason if rejected
    """
    key = await db.fetchrow(
        """
        SELECT public_key_id, service_id, algorithm, status, 
               created_at, created_by, reviewed_by, reviewed_at,
               rejection_reason, disabled_at, rotated_to
        FROM key_registry
        WHERE public_key_id = $1
        """,
        public_key_id
    )
    
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return dict(key)


@router.post("/rotate", response_model=PublicKeyInfo)
async def request_key_rotation(
    service_id: str,
    registration: PublicKeyRegistration,
    db: Database = Depends(get_db)
):
    """
    Submit a key rotation request.
    
    Services can request to rotate their key. The new key will be pending
    until approved by an administrator.
    
    **Request Body:**
    - `service_id`: Must match the existing service
    - `public_key_pem`: New PEM-encoded public key
    - `algorithm`: Key algorithm
    - `metadata`: Optional metadata
    
    **Note:** The existing key remains active until the new key is approved.
    """
    if registration.service_id != service_id:
        raise HTTPException(
            status_code=400,
            detail="Service ID in body must match path parameter"
        )
    
    # Generate new key ID
    new_key_id = f"{service_id}:v{int(time.time())}"
    
    async with db.transaction() as conn:
        # Check for existing approved key
        existing = await conn.fetchrow(
            """
            SELECT public_key_id FROM key_registry 
            WHERE service_id = $1 AND status = 'approved' AND disabled_at IS NULL
            """,
            service_id
        )
        
        if not existing:
            raise HTTPException(
                status_code=400,
                detail="No active key found for this service. Use register endpoint instead."
            )
        
        # Check for pending rotation request
        pending = await conn.fetchrow(
            """
            SELECT public_key_id FROM key_registry 
            WHERE service_id = $1 AND status = 'pending'
            """,
            service_id
        )
        
        if pending:
            raise HTTPException(
                status_code=400,
                detail=f"A pending key request already exists: {pending['public_key_id']}"
            )
        
        # Insert new key with pending status
        await conn.execute(
            """
            INSERT INTO key_registry (
                public_key_id, service_id, public_key_pem, 
                algorithm, status, created_by, metadata
            ) VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            """,
            new_key_id,
            service_id,
            registration.public_key_pem,
            registration.algorithm,
            service_id,
            json.dumps(registration.metadata) if registration.metadata else None
        )
        
        logger.info(f"Key rotation request submitted: {new_key_id} for service {service_id}")
    
    return PublicKeyInfo(
        public_key_id=new_key_id,
        service_id=service_id,
        algorithm=registration.algorithm,
        status="pending",
        created_at=datetime.utcnow(),
        created_by=service_id,
        reviewed_by=None,
        reviewed_at=None,
        rejection_reason=None,
        disabled_at=None,
        rotated_to=None
    )
