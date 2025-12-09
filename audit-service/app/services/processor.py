"""
Event processing service.

Handles event storage with hash chaining for tamper detection.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.database import Database
from app.crypto import compute_chain_hash

logger = logging.getLogger(__name__)


async def process_event(
    service_id: str,
    event_type: str,
    event_canonical: str,
    event_data: Dict[str, Any],
    event_hash: bytes,
    signature: bytes,
    public_key_id: str,
    db: Database,
    timestamp: Optional[datetime] = None
) -> int:
    """
    Process a verified event: compute chain hash and insert to database.
    
    This function implements hash chaining where each event is cryptographically
    linked to the previous event for the same service. This creates a tamper-evident
    log where any modification to historical events can be detected.
    
    Args:
        service_id: The service that published the event
        event_type: The type/category of the event
        event_canonical: The canonical form of the event (used for hashing)
        event_data: The structured event data as a dict
        event_hash: SHA-256 hash of the canonical event
        signature: The cryptographic signature
        public_key_id: The ID of the key used to sign
        db: Database connection
        timestamp: Optional event timestamp (uses current time if not provided)
        
    Returns:
        The ID of the inserted event
        
    Raises:
        Exception: If database insertion fails
    """
    # Use provided timestamp or current time
    event_timestamp = timestamp or datetime.utcnow()
    
    # Get last chain hash for service (or genesis hash)
    chain_state = await db.fetchrow(
        "SELECT last_chain_hash FROM chain_state WHERE service_id = $1",
        service_id
    )
    
    prev_chain = bytes(chain_state['last_chain_hash']) if chain_state else b'\x00' * 32
    
    # Compute new chain hash: SHA256(prev_chain || event_hash || service_id)
    new_chain_hash = compute_chain_hash(prev_chain, event_hash, service_id)
    
    # Insert event and update chain state in a transaction
    async with db.transaction() as conn:
        # Insert the event
        event_id = await conn.fetchval(
            """
            INSERT INTO audit_events (
                service_id, event_type, event_data, event_canonical,
                event_hash, signature, public_key_id, chain_hash,
                verified, timestamp_utc, received_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, now())
            RETURNING id
            """,
            service_id,
            event_type,
            json.dumps(event_data),  # Convert to JSON string for storage
            event_canonical,
            event_hash,
            signature,
            public_key_id,
            new_chain_hash,
            event_timestamp
        )
        
        # Update chain state (upsert)
        await conn.execute(
            """
            INSERT INTO chain_state (service_id, last_chain_hash, last_event_id, last_updated)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (service_id) DO UPDATE
            SET last_chain_hash = EXCLUDED.last_chain_hash,
                last_event_id = EXCLUDED.last_event_id,
                last_updated = now()
            """,
            service_id,
            new_chain_hash,
            event_id
        )
    
    logger.info(f"Event stored: id={event_id}, service={service_id}, type={event_type}")
    
    return event_id


async def get_event_by_id(
    event_id: int,
    db: Database
) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single event by ID.
    
    Args:
        event_id: The event ID
        db: Database connection
        
    Returns:
        Event data dict or None if not found
    """
    event = await db.fetchrow(
        """
        SELECT id, service_id, event_type, event_data, event_canonical,
               encode(event_hash, 'hex') as event_hash_hex,
               encode(chain_hash, 'hex') as chain_hash_hex,
               verified, timestamp_utc, received_at, public_key_id
        FROM audit_events
        WHERE id = $1
        """,
        event_id
    )
    
    if not event:
        return None
    
    return dict(event)


async def get_chain_state(
    service_id: str,
    db: Database
) -> Optional[Dict[str, Any]]:
    """
    Get the current chain state for a service.
    
    Args:
        service_id: The service identifier
        db: Database connection
        
    Returns:
        Chain state dict or None if no events exist for service
    """
    state = await db.fetchrow(
        """
        SELECT service_id, 
               encode(last_chain_hash, 'hex') as last_chain_hash_hex,
               last_event_id, last_updated
        FROM chain_state
        WHERE service_id = $1
        """,
        service_id
    )
    
    return dict(state) if state else None


async def get_events_for_verification(
    service_id: str,
    start_id: int = 0,
    limit: int = 1000,
    db: Database = None
) -> list:
    """
    Get events for chain verification.
    
    Args:
        service_id: The service identifier
        start_id: Start from this event ID
        limit: Maximum number of events to retrieve
        db: Database connection
        
    Returns:
        List of events ordered by ID
    """
    events = await db.fetch(
        """
        SELECT id, event_hash, chain_hash
        FROM audit_events
        WHERE service_id = $1 AND id > $2
        ORDER BY id ASC
        LIMIT $3
        """,
        service_id,
        start_id,
        limit
    )
    
    return [dict(e) for e in events]


async def count_events(
    service_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    db: Database = None
) -> int:
    """
    Count events matching the given criteria.
    
    Args:
        service_id: Optional filter by service
        event_type: Optional filter by event type
        since: Optional filter by timestamp
        db: Database connection
        
    Returns:
        Count of matching events
    """
    conditions = []
    params = []
    
    if service_id:
        conditions.append(f"service_id = ${len(params) + 1}")
        params.append(service_id)
    
    if event_type:
        conditions.append(f"event_type = ${len(params) + 1}")
        params.append(event_type)
    
    if since:
        conditions.append(f"timestamp_utc >= ${len(params) + 1}")
        params.append(since)
    
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    
    count = await db.fetchval(
        f"SELECT COUNT(*) FROM audit_events WHERE {where_clause}",
        *params
    )
    
    return count
