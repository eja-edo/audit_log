"""
Chain Verification Script

This script verifies the integrity of the hash chain for audit events.
It can be run periodically to detect any tampering.
"""

import asyncio
import hashlib
import sys
from datetime import datetime

import asyncpg


async def verify_chain(
    database_url: str,
    service_id: str,
    batch_size: int = 10000,
    verbose: bool = False
) -> dict:
    """
    Verify the hash chain integrity for a service.
    
    Args:
        database_url: PostgreSQL connection URL
        service_id: Service ID to verify
        batch_size: Number of events to process per batch
        verbose: Print progress information
        
    Returns:
        Verification result dictionary
    """
    conn = await asyncpg.connect(database_url)
    
    try:
        # Get total event count
        total_count = await conn.fetchval(
            "SELECT COUNT(*) FROM audit_events WHERE service_id = $1",
            service_id
        )
        
        if total_count == 0:
            return {
                "service_id": service_id,
                "is_valid": True,
                "events_checked": 0,
                "message": "No events found for this service"
            }
        
        if verbose:
            print(f"Verifying {total_count} events for service: {service_id}")
        
        # Verify in batches
        prev_chain_hash = b'\x00' * 32  # Genesis hash
        events_checked = 0
        last_id = 0
        
        while True:
            # Fetch batch
            events = await conn.fetch(
                """
                SELECT id, event_hash, chain_hash
                FROM audit_events
                WHERE service_id = $1 AND id > $2
                ORDER BY id ASC
                LIMIT $3
                """,
                service_id,
                last_id,
                batch_size
            )
            
            if not events:
                break
            
            for event in events:
                # Compute expected chain hash
                chain_input = (
                    prev_chain_hash +
                    bytes(event['event_hash']) +
                    service_id.encode('utf-8')
                )
                expected_hash = hashlib.sha256(chain_input).digest()
                
                # Compare with stored hash
                stored_hash = bytes(event['chain_hash'])
                
                if expected_hash != stored_hash:
                    return {
                        "service_id": service_id,
                        "is_valid": False,
                        "events_checked": events_checked + 1,
                        "first_invalid_id": event['id'],
                        "message": f"Chain hash mismatch at event ID {event['id']}",
                        "expected_hash": expected_hash.hex(),
                        "stored_hash": stored_hash.hex()
                    }
                
                prev_chain_hash = stored_hash
                events_checked += 1
                last_id = event['id']
            
            if verbose:
                progress = (events_checked / total_count) * 100
                print(f"Progress: {events_checked}/{total_count} ({progress:.1f}%)")
        
        return {
            "service_id": service_id,
            "is_valid": True,
            "events_checked": events_checked,
            "message": "Chain integrity verified successfully"
        }
        
    finally:
        await conn.close()


async def verify_all_services(
    database_url: str,
    verbose: bool = False
) -> list:
    """
    Verify chain integrity for all services.
    
    Args:
        database_url: PostgreSQL connection URL
        verbose: Print progress information
        
    Returns:
        List of verification results
    """
    conn = await asyncpg.connect(database_url)
    
    try:
        # Get all service IDs
        services = await conn.fetch(
            "SELECT DISTINCT service_id FROM audit_events ORDER BY service_id"
        )
        
        results = []
        for row in services:
            service_id = row['service_id']
            if verbose:
                print(f"\n{'='*50}")
                print(f"Verifying service: {service_id}")
                print('='*50)
            
            result = await verify_chain(database_url, service_id, verbose=verbose)
            results.append(result)
        
        return results
        
    finally:
        await conn.close()


def print_results(results: list):
    """Print verification results in a formatted way."""
    print("\n" + "="*60)
    print("CHAIN VERIFICATION RESULTS")
    print("="*60)
    print(f"Timestamp: {datetime.utcnow().isoformat()}Z")
    print("-"*60)
    
    all_valid = True
    
    for result in results:
        status = "✅ VALID" if result['is_valid'] else "❌ INVALID"
        print(f"\nService: {result['service_id']}")
        print(f"  Status: {status}")
        print(f"  Events checked: {result['events_checked']}")
        print(f"  Message: {result['message']}")
        
        if not result['is_valid']:
            all_valid = False
            print(f"  First invalid ID: {result.get('first_invalid_id')}")
    
    print("\n" + "="*60)
    if all_valid:
        print("✅ ALL CHAINS VERIFIED SUCCESSFULLY")
    else:
        print("❌ SOME CHAINS HAVE INTEGRITY ISSUES")
    print("="*60 + "\n")


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Verify audit log hash chain integrity"
    )
    parser.add_argument(
        "--database-url",
        default="postgresql://audit_user:password@localhost:5432/audit_db",
        help="PostgreSQL connection URL"
    )
    parser.add_argument(
        "--service-id",
        help="Specific service ID to verify (verifies all if not specified)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print progress information"
    )
    
    args = parser.parse_args()
    
    if args.service_id:
        result = await verify_chain(
            args.database_url,
            args.service_id,
            verbose=args.verbose
        )
        print_results([result])
    else:
        results = await verify_all_services(
            args.database_url,
            verbose=args.verbose
        )
        print_results(results)


if __name__ == "__main__":
    asyncio.run(main())
