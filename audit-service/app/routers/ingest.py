"""
Event ingestion endpoint - POST /v1/logs
"""

import base64
import hashlib
import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from prometheus_client import Counter, Histogram

from app.models import EventSubmission, EventResponse
from app.database import Database, get_db
from app.services.verifier import verify_event_signature
from app.services.processor import process_event
from app.crypto import verify_signature_vulnerable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["events"])

# Prometheus metrics
events_received = Counter(
    'audit_events_received_total',
    'Total events received',
    ['service_id', 'event_type']
)
events_rejected = Counter(
    'audit_events_rejected_total',
    'Total events rejected',
    ['service_id', 'reason']
)
signature_verify_duration = Histogram(
    'signature_verification_seconds',
    'Signature verification duration'
)
db_write_duration = Histogram(
    'db_write_seconds',
    'Database write duration'
)


@router.post("/logs", response_model=EventResponse)
async def submit_log(
    submission: EventSubmission,
    db: Database = Depends(get_db)
):
    """
    Submit a signed audit event.
    
    This endpoint receives audit events from publisher services.
    Each event must be cryptographically signed using the publisher's
    private key. The signature is verified against the registered
    public key before the event is stored.
    
    **Supported Algorithms:**
    - `ed25519`: Ed25519 signatures (SECURE, recommended)
    - `rsa-pss`: RSA-PSS with SHA-256 (SECURE)
    - `rsa-pkcs1v15`: RSA PKCS#1 v1.5 with standard library (SECURE)
    - `rsa-pkcs1v15-vulnerable`: Weak PKCS#1 v1.5 verifier (INSECURE - demo only!)
    
    **Security Notes:**
    - `rsa-pkcs1v15-vulnerable` is intentionally weak for Bleichenbacher attack demo
    - All other algorithms use secure standard library implementations
    - Events are stored with hash chaining for tamper detection
    
    **Request Body:**
    - `service_id`: Unique identifier of the publishing service
    - `event_type`: Type/category of the event
    - `event`: Canonical (normalized) form of the event for signature verification
    - `event_data`: Structured event data as JSON
    - `signature`: Base64-encoded signature of the canonical event
    - `public_key_id`: ID of the public key to verify signature
    
    **Returns:**
    - `status`: "accepted" or "rejected"
    - `id`: Event ID if accepted (null if rejected)
    - `message`: Details about verification (for demo purposes)
    """
    try:
        # Increment received counter
        events_received.labels(
            service_id=submission.service_id,
            event_type=submission.event_type
        ).inc()
        
        # 1. Decode signature
        try:
            signature_bytes = base64.b64decode(submission.signature)
        except Exception:
            events_rejected.labels(
                service_id=submission.service_id,
                reason="invalid_signature_encoding"
            ).inc()
            raise HTTPException(status_code=400, detail="rejected: invalid base64")
        
        # 2. Fetch key info to check algorithm
        key_info = await db.fetchrow(
            """
            SELECT public_key_pem, algorithm 
            FROM key_registry
            WHERE public_key_id = $1 AND disabled_at IS NULL AND status = 'approved'
            """,
            submission.public_key_id
        )
        
        if not key_info:
            events_rejected.labels(
                service_id=submission.service_id,
                reason="key_not_found"
            ).inc()
            raise HTTPException(status_code=400, detail="rejected: key not found or not approved")
        
        algorithm = key_info['algorithm']
        public_key_pem = key_info['public_key_pem']
        
        # 3. Verify signature based on algorithm
        with signature_verify_duration.time():
            if algorithm == 'rsa-pkcs1v15-vulnerable':
                # VULNERABLE verification - weak checker for demo
                # WARNING: This is intentionally insecure for Bleichenbacher attack demo!
                is_valid, verification_msg = verify_signature_vulnerable(
                    message=submission.event.encode('utf-8'),
                    signature=signature_bytes,
                    public_key_pem=public_key_pem,
                    algorithm=algorithm
                )
            elif algorithm in ('rsa-pkcs1v15', 'rsa-pss', 'ed25519'):
                # SECURE verification using standard library
                is_valid, verification_msg = verify_signature_vulnerable(
                    message=submission.event.encode('utf-8'),
                    signature=signature_bytes,
                    public_key_pem=public_key_pem,
                    algorithm=algorithm
                )
            else:
                # Unknown algorithm - also use verify_signature_vulnerable for error handling
                is_valid, verification_msg = verify_signature_vulnerable(
                    message=submission.event.encode('utf-8'),
                    signature=signature_bytes,
                    public_key_pem=public_key_pem,
                    algorithm=algorithm
                )
        
        if not is_valid:
            events_rejected.labels(
                service_id=submission.service_id,
                reason="invalid_signature"
            ).inc()
            # Return detailed message for demo purposes
            raise HTTPException(status_code=400, detail=f"rejected: {verification_msg}")
        
        # 4. Compute event hash
        event_hash = hashlib.sha256(
            submission.event.encode('utf-8')
        ).digest()
        
        # 5. Process and store with timing
        with db_write_duration.time():
            event_id = await process_event(
                service_id=submission.service_id,
                event_type=submission.event_type,
                event_canonical=submission.event,
                event_data=submission.event_data,
                event_hash=event_hash,
                signature=signature_bytes,
                public_key_id=submission.public_key_id,
                timestamp=submission.timestamp,
                db=db
            )
        
        # 6. Success response with verification info
        return EventResponse(
            status="accepted",
            id=str(event_id),
            message=f"Event stored successfully. Verification: {verification_msg}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Log internally but return generic error
        logger.exception(f"Event processing failed: {e}")
        events_rejected.labels(
            service_id=submission.service_id,
            reason="internal_error"
        ).inc()
        raise HTTPException(status_code=400, detail=f"rejected: {str(e)}")


@router.get("/logs/{event_id}")
async def get_event(
    event_id: int,
    db: Database = Depends(get_db)
):
    """
    Retrieve a single audit event by ID.
    
    **Note:** This endpoint is typically protected and may require
    additional authorization depending on your security requirements.
    """
    event = await db.fetchrow(
        """
        SELECT id, service_id, event_type, event_data, 
               encode(event_hash, 'hex') as event_hash,
               encode(chain_hash, 'hex') as chain_hash,
               verified, timestamp_utc, received_at, public_key_id
        FROM audit_events
        WHERE id = $1
        """,
        event_id
    )
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return dict(event)


@router.get("/logs")
async def list_events(
    service_id: str = None,
    event_type: str = None,
    start_time: datetime = None,
    end_time: datetime = None,
    limit: int = 100,
    offset: int = 0,
    db: Database = Depends(get_db)
):
    """
    List audit events with optional filtering.
    
    **Query Parameters:**
    - `service_id`: Filter by service ID
    - `event_type`: Filter by event type
    - `start_time`: Filter events after this time (ISO 8601)
    - `end_time`: Filter events before this time (ISO 8601)
    - `limit`: Maximum number of events to return (default: 100, max: 1000)
    - `offset`: Number of events to skip (for pagination)
    """
    # Build dynamic query
    conditions = []
    params = []
    param_count = 0
    
    if service_id:
        param_count += 1
        conditions.append(f"service_id = ${param_count}")
        params.append(service_id)
    
    if event_type:
        param_count += 1
        conditions.append(f"event_type = ${param_count}")
        params.append(event_type)
    
    if start_time:
        param_count += 1
        conditions.append(f"timestamp_utc >= ${param_count}")
        params.append(start_time)
    
    if end_time:
        param_count += 1
        conditions.append(f"timestamp_utc <= ${param_count}")
        params.append(end_time)
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    
    # Clamp limit
    limit = min(limit, 1000)
    
    query = f"""
        SELECT id, service_id, event_type, event_data,
               verified, timestamp_utc, public_key_id
        FROM audit_events
        WHERE {where_clause}
        ORDER BY timestamp_utc DESC
        LIMIT ${param_count + 1} OFFSET ${param_count + 2}
    """
    params.extend([limit, offset])
    
    events = await db.fetch(query, *params)
    
    return {
        "events": [dict(e) for e in events],
        "count": len(events),
        "limit": limit,
        "offset": offset
    }


@router.post("/logs/search")
async def search_events(
    search_text: str,
    service_id: str = None,
    start_time: datetime = None,
    end_time: datetime = None,
    limit: int = 100,
    db: Database = Depends(get_db)
):
    """
    Full-text search across audit events.
    
    Uses PostgreSQL's built-in full-text search capabilities.
    
    **Request Body:**
    - `search_text`: Text to search for in event data
    - `service_id`: Optional filter by service ID
    - `start_time`: Optional filter for events after this time
    - `end_time`: Optional filter for events before this time
    - `limit`: Maximum number of results (default: 100)
    """
    # Build search query
    conditions = ["to_tsvector('english', event_canonical) @@ plainto_tsquery('english', $1)"]
    params = [search_text]
    param_count = 1
    
    if service_id:
        param_count += 1
        conditions.append(f"service_id = ${param_count}")
        params.append(service_id)
    
    if start_time:
        param_count += 1
        conditions.append(f"timestamp_utc >= ${param_count}")
        params.append(start_time)
    
    if end_time:
        param_count += 1
        conditions.append(f"timestamp_utc <= ${param_count}")
        params.append(end_time)
    
    where_clause = " AND ".join(conditions)
    limit = min(limit, 1000)
    
    query = f"""
        SELECT id, service_id, event_type, event_data,
               verified, timestamp_utc,
               ts_rank(to_tsvector('english', event_canonical), plainto_tsquery('english', $1)) as rank
        FROM audit_events
        WHERE {where_clause}
        ORDER BY rank DESC, timestamp_utc DESC
        LIMIT ${param_count + 1}
    """
    params.append(limit)
    
    events = await db.fetch(query, *params)
    
    return {
        "events": [dict(e) for e in events],
        "count": len(events),
        "search_text": search_text
    }
