"""
Admin endpoints for key management, chain verification, and system operations.
"""

import base64
import json
import logging
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.security import APIKeyHeader

from app.models import (
    PublicKeyRegistration, PublicKeyInfo, KeyRotationRequest,
    ChainVerificationResult, AdminAction, KeyApprovalRequest
)
from app.database import Database, get_db
from app.crypto import compute_sha256, compute_chain_hash
from app.config import settings
from app.auth import User, get_admin_user_or_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin", tags=["admin"])


# ============================================================================
# Key Approval Management
# ============================================================================

@router.get("/keys/pending")
async def list_pending_keys(
    current_user: User = Depends(get_admin_user_or_token),
    db: Database = Depends(get_db)
):
    """
    List all pending key registration requests.
    
    Admin can view all keys awaiting approval.
    
    **Authentication:** Bearer token or X-Admin-Token (legacy)
    """
    keys = await db.fetch(
        """
        SELECT public_key_id, service_id, algorithm, public_key_pem,
               status, created_at, created_by, metadata
        FROM key_registry
        WHERE status = 'pending'
        ORDER BY created_at ASC
        """
    )
    
    return {
        "pending_count": len(keys),
        "keys": [dict(k) for k in keys]
    }


@router.post("/keys/review", response_model=PublicKeyInfo)
async def review_key_request(
    request: KeyApprovalRequest,
    current_user: User = Depends(get_admin_user_or_token),
    db: Database = Depends(get_db)
):
    """
    Approve or reject a pending key registration request.
    
    **Authentication:** Bearer token or X-Admin-Token (legacy)
    
    **Request Body:**
    - `public_key_id`: ID of the pending key
    - `action`: 'approve' or 'reject'
    - `reason`: Required if rejecting
    
    **Effects:**
    - If approved: Key status changes to 'approved', can be used for verification
    - If rejected: Key status changes to 'rejected', cannot be used
    - For rotation approvals: Old key is marked as rotated
    """
    if request.action == "reject" and not request.reason:
        raise HTTPException(
            status_code=400,
            detail="Reason is required when rejecting a key"
        )
    
    async with db.transaction() as conn:
        # Fetch pending key
        key = await conn.fetchrow(
            """
            SELECT public_key_id, service_id, algorithm, status,
                   created_at, created_by
            FROM key_registry
            WHERE public_key_id = $1
            """,
            request.public_key_id
        )
        
        if not key:
            raise HTTPException(status_code=404, detail="Key not found")
        
        if key['status'] != 'pending':
            raise HTTPException(
                status_code=400,
                detail=f"Key is not pending. Current status: {key['status']}"
            )
        
        new_status = 'approved' if request.action == 'approve' else 'rejected'
        
        # Update key status
        await conn.execute(
            """
            UPDATE key_registry 
            SET status = $1, 
                reviewed_by = $2, 
                reviewed_at = now(),
                rejection_reason = $3
            WHERE public_key_id = $4
            """,
            new_status,
            "admin",  # TODO: Extract from token
            request.reason if request.action == 'reject' else None,
            request.public_key_id
        )
        
        # If approving a rotation, mark old key as rotated
        if request.action == 'approve':
            old_key = await conn.fetchrow(
                """
                SELECT public_key_id FROM key_registry 
                WHERE service_id = $1 
                  AND status = 'approved' 
                  AND disabled_at IS NULL
                  AND public_key_id != $2
                """,
                key['service_id'],
                request.public_key_id
            )
            
            if old_key:
                await conn.execute(
                    """
                    UPDATE key_registry 
                    SET rotated_to = $1 
                    WHERE public_key_id = $2
                    """,
                    request.public_key_id,
                    old_key['public_key_id']
                )
        
        # Log admin action
        await conn.execute(
            """
            INSERT INTO admin_audit (action, actor, target_resource, details, signature)
            VALUES ($1, $2, $3, $4, $5)
            """,
            f"key_{request.action}",
            "admin",
            request.public_key_id,
            json.dumps({
                "service_id": key['service_id'],
                "action": request.action,
                "reason": request.reason
            }),
            b''
        )
        
        logger.info(f"Key {request.public_key_id} {request.action}d by admin")
        
        # Fetch updated key
        updated_key = await conn.fetchrow(
            """
            SELECT public_key_id, service_id, algorithm, status,
                   created_at, created_by, reviewed_by, reviewed_at,
                   rejection_reason, disabled_at, rotated_to
            FROM key_registry
            WHERE public_key_id = $1
            """,
            request.public_key_id
        )
    
    return PublicKeyInfo(
        public_key_id=updated_key['public_key_id'],
        service_id=updated_key['service_id'],
        algorithm=updated_key['algorithm'],
        status=updated_key['status'],
        created_at=updated_key['created_at'],
        created_by=updated_key['created_by'],
        reviewed_by=updated_key['reviewed_by'],
        reviewed_at=updated_key['reviewed_at'],
        rejection_reason=updated_key['rejection_reason'],
        disabled_at=updated_key['disabled_at'],
        rotated_to=updated_key['rotated_to']
    )


# ============================================================================
# Key Management (Admin)
# ============================================================================

@router.delete("/keys/{public_key_id}")
async def disable_key(
    public_key_id: str,
    current_user: User = Depends(get_admin_user_or_token),
    db: Database = Depends(get_db)
):
    """
    Disable a public key.
    
    Disabled keys can no longer be used for signature verification.
    This is useful for revoking compromised keys.
    
    **Authentication:** Bearer token or X-Admin-Token (legacy)
    
    **Note:** Only approved keys can be disabled.
    """
    async with db.transaction() as conn:
        # Check key exists and is approved
        key = await conn.fetchrow(
            "SELECT status FROM key_registry WHERE public_key_id = $1",
            public_key_id
        )
        
        if not key:
            raise HTTPException(status_code=404, detail="Key not found")
        
        if key['status'] != 'approved':
            raise HTTPException(
                status_code=400, 
                detail=f"Only approved keys can be disabled. Current status: {key['status']}"
            )
        
        await conn.execute(
            "UPDATE key_registry SET disabled_at = now() WHERE public_key_id = $1",
            public_key_id
        )
        
        await conn.execute(
            """
            INSERT INTO admin_audit (action, actor, target_resource, details, signature)
            VALUES ('disable_key', $1, $2, $3, $4)
            """,
            "admin",
            public_key_id,
            json.dumps({"reason": "admin_disabled"}),
            b''
        )
    
    return {"status": "disabled", "public_key_id": public_key_id}


@router.get("/keys")
async def list_keys(
    service_id: Optional[str] = None,
    status: Optional[str] = None,
    include_disabled: bool = False,
    current_user: User = Depends(get_admin_user_or_token),
    db: Database = Depends(get_db)
):
    """
    List registered public keys.
    
    **Authentication:** Bearer token or X-Admin-Token (legacy)
    
    **Query Parameters:**
    - `service_id`: Filter by service
    - `status`: Filter by status ('pending', 'approved', 'rejected')
    - `include_disabled`: Include disabled keys
    """
    conditions = []
    params = []
    param_count = 0
    
    if service_id:
        param_count += 1
        conditions.append(f"service_id = ${param_count}")
        params.append(service_id)
    
    if status:
        param_count += 1
        conditions.append(f"status = ${param_count}")
        params.append(status)
    
    if not include_disabled:
        conditions.append("disabled_at IS NULL")
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    
    keys = await db.fetch(
        f"""
        SELECT public_key_id, service_id, algorithm, status,
               created_at, created_by, reviewed_by, reviewed_at,
               rejection_reason, disabled_at, rotated_to
        FROM key_registry
        WHERE {where_clause}
        ORDER BY created_at DESC
        """,
        *params
    )
    
    return {"keys": [dict(k) for k in keys]}


# ============================================================================
# Chain Verification
# ============================================================================

@router.post("/verify-chain", response_model=ChainVerificationResult)
async def verify_chain(
    service_id: str,
    limit: int = 10000,
    db: Database = Depends(get_db)
):
    """
    Verify the hash chain integrity for a service.
    
    This checks that all events in the chain have valid chain_hash
    values, ensuring no tampering has occurred.
    """
    # Fetch events in order
    events = await db.fetch(
        """
        SELECT id, event_hash, chain_hash
        FROM audit_events
        WHERE service_id = $1
        ORDER BY id ASC
        LIMIT $2
        """,
        service_id,
        limit
    )
    
    if not events:
        return ChainVerificationResult(
            service_id=service_id,
            is_valid=True,
            events_checked=0
        )
    
    # Verify chain
    prev_chain_hash = b'\x00' * 32  # Genesis
    
    for event in events:
        expected_chain_hash = compute_chain_hash(
            prev_chain_hash,
            bytes(event['event_hash']),
            service_id
        )
        
        if expected_chain_hash != bytes(event['chain_hash']):
            return ChainVerificationResult(
                service_id=service_id,
                is_valid=False,
                events_checked=events.index(event) + 1,
                first_invalid_event_id=event['id'],
                error_message="Chain hash mismatch detected"
            )
        
        prev_chain_hash = expected_chain_hash
    
    return ChainVerificationResult(
        service_id=service_id,
        is_valid=True,
        events_checked=len(events)
    )


# ============================================================================
# Audit & Stats
# ============================================================================

@router.get("/audit-log")
async def get_admin_audit_log(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Database = Depends(get_db)
):
    """
    Retrieve admin audit log entries.
    """
    conditions = []
    params = []
    param_count = 0
    
    if actor:
        param_count += 1
        conditions.append(f"actor = ${param_count}")
        params.append(actor)
    
    if action:
        param_count += 1
        conditions.append(f"action = ${param_count}")
        params.append(action)
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    
    entries = await db.fetch(
        f"""
        SELECT id, action, actor, target_resource, details, timestamp_utc
        FROM admin_audit
        WHERE {where_clause}
        ORDER BY timestamp_utc DESC
        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
        """,
        *params, limit, offset
    )
    
    return {
        "entries": [dict(e) for e in entries],
        "count": len(entries)
    }


@router.get("/stats")
async def get_service_stats(
    db: Database = Depends(get_db)
):
    """
    Get service statistics and metrics.
    """
    # Total events
    total = await db.fetchval("SELECT COUNT(*) FROM audit_events")
    
    # Events last hour
    last_hour = await db.fetchval(
        "SELECT COUNT(*) FROM audit_events WHERE timestamp_utc > now() - interval '1 hour'"
    )
    
    # Events last day
    last_day = await db.fetchval(
        "SELECT COUNT(*) FROM audit_events WHERE timestamp_utc > now() - interval '1 day'"
    )
    
    # Unique services
    services = await db.fetchval(
        "SELECT COUNT(DISTINCT service_id) FROM audit_events"
    )
    
    # Failed verifications
    failed = await db.fetchval(
        "SELECT COUNT(*) FROM audit_events WHERE NOT verified"
    )
    
    # Events by service (last 24h)
    by_service = await db.fetch(
        """
        SELECT service_id, COUNT(*) as count
        FROM audit_events
        WHERE timestamp_utc > now() - interval '1 day'
        GROUP BY service_id
        ORDER BY count DESC
        LIMIT 10
        """
    )
    
    # Events by type (last 24h)
    by_type = await db.fetch(
        """
        SELECT event_type, COUNT(*) as count
        FROM audit_events
        WHERE timestamp_utc > now() - interval '1 day'
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 10
        """
    )
    
    return {
        "total_events": total,
        "events_last_hour": last_hour,
        "events_last_day": last_day,
        "unique_services": services,
        "failed_verifications": failed,
        "by_service": [dict(s) for s in by_service],
        "by_type": [dict(t) for t in by_type]
    }


@router.post("/refresh-stats-view")
async def refresh_stats_view(
    current_user: User = Depends(get_admin_user_or_token),
    db: Database = Depends(get_db)
):
    """
    Manually refresh the statistics materialized view.
    
    **Authentication:** Bearer token or X-Admin-Token (legacy)
    """
    await db.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY event_stats_hourly")
    return {"status": "refreshed"}
