# Audit Log Service - AI Coding Instructions

## Architecture Overview

This is a **cost-optimized audit logging system** using PostgreSQL as the single source of truth (no Kafka, S3, or Elasticsearch). Key design decisions:

- **FastAPI + asyncpg**: Async-first for high throughput
- **Hash chaining**: Events are linked cryptographically like a blockchain (`chain_hash = SHA256(prev_hash || event_hash || service_id)`)
- **Ed25519/RSA-PSS signatures**: All events must be signed by registered publishers
- **Append-only**: The `audit_events` table forbids UPDATE/DELETE operations

## Project Structure

```
app/
├── main.py              # FastAPI app with lifespan management
├── config.py            # Pydantic settings from .env
├── database.py          # asyncpg connection pool
├── crypto.py            # Signature verification, hashing, key parsing
├── models.py            # Pydantic request/response models
├── routers/
│   ├── ingest.py        # POST /v1/logs - event ingestion
│   ├── admin.py         # Key management, chain verification
│   └── health.py        # Health/metrics endpoints
└── services/
    ├── verifier.py      # Signature verification logic
    ├── processor.py     # Event processing & chain hash
    └── event_consumer.py # PostgreSQL LISTEN/NOTIFY consumer
```

## Critical Patterns

### 1. Event Signing Flow
Publishers must sign the **canonical form** of events (sorted keys, no whitespace):
```python
canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
signature = sign_ed25519(canonical.encode(), private_key)
```

### 2. Database Interactions
Always use the `Database` dependency and async context managers:
```python
async with db.transaction() as conn:
    await conn.execute("INSERT INTO ...", param1, param2)
```

### 3. JSON in PostgreSQL
When inserting dicts to TEXT/JSONB columns, serialize with `json.dumps()`:
```python
await conn.execute("INSERT INTO table (metadata) VALUES ($1)", json.dumps(metadata))
```

### 4. Admin Authentication
Admin endpoints require `X-Admin-Token` header validated via `verify_admin_token` dependency:
```python
@router.post("/admin/endpoint")
async def endpoint(token: str = Depends(verify_admin_token)):
```

## Key Commands

```bash
# Start services (HTTP mode, no mTLS)
docker-compose up -d

# Rebuild API after code changes
docker-compose up -d --build api

# View API logs
docker logs audit-service-api-1 --tail 50

# Register a new service with keypair
python scripts/register_service.py <service-id> "<description>"

# Run tests
pytest tests/ -v
```

## Environment Configuration

Key variables in `.env`:
- `DEBUG=true` - Enables `/docs` Swagger UI
- `ADMIN_TOKEN` - Token for admin API authentication
- `DATABASE_URL` - PostgreSQL connection string

## Database Schema

The `audit_events` table is **partitioned by month** for performance. Key columns:
- `event_canonical`: Normalized JSON string used for signature verification
- `event_hash`: SHA-256 of canonical form
- `chain_hash`: Links to previous event (tamper detection)
- `verified`: Set to true after signature verification

## Testing Patterns

Use fixtures from `tests/conftest.py`:
```python
def test_signature(ed25519_keypair, sample_event_data):
    private_pem, public_pem = ed25519_keypair
    # Test signing/verification
```

## Common Pitfalls

1. **Dict to SQL**: Always `json.dumps()` dicts before passing to asyncpg
2. **Signature format**: Signatures must be base64-encoded in API requests
3. **Key registration**: Register public keys via `/v1/admin/keys` before sending events
4. **Canonical form**: Events signed with different JSON serialization will fail verification
