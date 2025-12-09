# THIẾT KẾ AUDIT LOG HỆ THỐNG - TỐI ƯU CHI PHÍ

## 1. KIẾN TRÚC TỔNG QUAN

```
Publishers (services) 
    ↓ HTTPS + mTLS
[API Gateway - FastAPI]
    ↓ verify signature
[PostgreSQL ONLY - Single Source of Truth]
    ↓ async trigger/CDC
[Search Index - PostgreSQL FTS / Meilisearch (optional)]
```

### Nguyên tắc thiết kế:
- **Single database PostgreSQL** làm source of truth
- **Không dùng Kafka** - async bằng PostgreSQL LISTEN/NOTIFY hoặc pg_cron
- **Không dùng S3** - lưu trực tiếp JSON trong PostgreSQL (TOAST tự động compress)
- **Không dùng Elasticsearch** - dùng PostgreSQL Full-Text Search hoặc Meilisearch nhẹ
- **Không dùng Vault** - dùng PostgreSQL `pgcrypto` + file-based keys với encryption at rest

---

## 2. STACK CÔNG NGHỆ CHI PHÍ THẤP

| Component | Giải pháp | Chi phí | Lý do |
|-----------|-----------|---------|-------|
| **API Gateway** | FastAPI + uvicorn | Free | Đơn giản, hiệu năng tốt |
| **Database** | PostgreSQL 15+ | Free | All-in-one: ACID, FTS, JSONB, partitioning |
| **Search** | pg_trgm + GIN index | Free | Built-in PostgreSQL |
| **Message Queue** | PostgreSQL LISTEN/NOTIFY | Free | Native, đủ cho audit log |
| **Object Storage** | PostgreSQL TOAST | Free | Auto compress, inline lưu trong DB |
| **Key Management** | File + pgcrypto | Free | Đơn giản, đủ security |
| **Container** | Docker Compose | Free | Đủ cho < 100K events/day |
| **Monitoring** | Prometheus + Grafana | Free | Standard stack |
| **Load Balancer** | Nginx | Free | Reverse proxy + rate limit |

**Tổng chi phí license: $0**
**Chi phí vận hành: Chỉ server + bandwidth**

---

## 3. DATABASE SCHEMA - TỔNG QUAN

Database có **4 bảng chính** + **1 materialized view**:

| Bảng | Mục đích | Đặc điểm |
|------|----------|----------|
| `audit_events` | Lưu tất cả events | Append-only, partitioned, immutable |
| `key_registry` | Quản lý public keys | Versioning, rotation tracking |
| `chain_state` | Track hash chain | Per-service chain head |
| `admin_audit` | Meta-audit admin actions | Self-auditing system |
| `event_stats_hourly` | Dashboard metrics | Materialized view, auto-refresh |

---

## 3. DATABASE SCHEMA - POSTGRESQL SINGLE SOURCE

### 3.1. Bảng chính `audit_events` - TÂM ĐIỂM HỆ THỐNG

**Mục đích:** Lưu trữ TẤT CẢ audit events - đây là single source of truth

**Đặc điểm:**
- ✅ **Append-only**: Không cho phép UPDATE/DELETE
- ✅ **Partitioned by time**: Chia theo tháng để query nhanh
- ✅ **JSONB compression**: PostgreSQL TOAST tự động nén data > 2KB
- ✅ **Hash chaining**: Mỗi event link với event trước đó
- ✅ **Cryptographic proof**: Lưu signature + hash để verify

```sql
-- Extension cần thiết
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- Mã hóa
CREATE EXTENSION IF NOT EXISTS pg_trgm;   -- Full-text search

-- Bảng audit events - append only, partitioned
CREATE TABLE audit_events (
    -- === IDENTITY FIELDS ===
    id BIGSERIAL,                          -- Auto-increment ID (unique trong partition)
    service_id TEXT NOT NULL,              -- Tên service gửi log (vd: "user-service", "payment-api")
    event_type TEXT NOT NULL,              -- Loại event (vd: "USER_LOGIN", "PAYMENT_CREATED")
    
    -- === PAYLOAD - NỘI DUNG EVENT ===
    event_data JSONB NOT NULL,             -- Data dạng JSON (tự động compress nếu > 2KB)
                                           -- VD: {"user_id": 123, "ip": "1.2.3.4", "action": "login"}
    
    event_canonical TEXT NOT NULL,         -- Chuỗi canonical đã được normalize để ký
                                           -- (sorted keys, no whitespace) - QUAN TRỌNG cho verify
    
    -- === CRYPTOGRAPHIC PROOF ===
    event_hash BYTEA NOT NULL,             -- SHA256 hash của event_canonical
                                           -- Dùng để verify integrity
    
    signature BYTEA NOT NULL,              -- Chữ ký số của publisher (Ed25519/RSA-PSS)
                                           -- Publisher ký event_canonical bằng private key
    
    public_key_id TEXT NOT NULL,           -- ID của public key dùng để verify
                                           -- VD: "user-service:v2" (service + version)
    
    chain_hash BYTEA NOT NULL,             -- Hash chain linking
                                           -- SHA256(prev_chain_hash || event_hash || timestamp)
                                           -- Tạo blockchain-like chain để detect tampering
    
    -- === VERIFICATION STATUS ===
    verified BOOLEAN NOT NULL DEFAULT false, -- Gateway đã verify signature thành công?
    
    -- === TIMESTAMP ===
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Thời gian event xảy ra (do publisher gửi)
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),    -- Thời gian gateway nhận được
    
    -- === CONSTRAINTS ===
    PRIMARY KEY (id, timestamp_utc)        -- Composite key để support partitioning
) PARTITION BY RANGE (timestamp_utc);      -- Chia partition theo tháng

-- Partition template (tự động tạo mỗi tháng qua pg_cron)
CREATE TABLE audit_events_2025_12 PARTITION OF audit_events
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Indexes
CREATE INDEX idx_service_time ON audit_events(service_id, timestamp_utc DESC);
CREATE INDEX idx_event_type ON audit_events(event_type, timestamp_utc DESC);
CREATE INDEX idx_event_hash ON audit_events USING hash(event_hash);
CREATE INDEX idx_chain_hash ON audit_events(chain_hash);

-- Full-text search index
CREATE INDEX idx_event_data_gin ON audit_events USING gin(event_data jsonb_path_ops);
CREATE INDEX idx_event_text ON audit_events USING gin(to_tsvector('english', event_canonical));

-- Prevent UPDATE/DELETE
CREATE RULE no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE RULE no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;
```

### 3.2. Bảng `key_registry`

```sql
CREATE TABLE key_registry (
    public_key_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    
    -- Key data (PEM format)
    public_key_pem TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('ed25519', 'rsa-pss')),
    
    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_to TEXT REFERENCES key_registry(public_key_id),
    disabled_at TIMESTAMPTZ,
    
    -- Metadata
    created_by TEXT NOT NULL,
    metadata JSONB
);

CREATE INDEX idx_service_keys ON key_registry(service_id) WHERE disabled_at IS NULL;
```

### 3.3. Bảng `chain_state` - Track chain hash per service

```sql
CREATE TABLE chain_state (
    service_id TEXT PRIMARY KEY,
    last_chain_hash BYTEA NOT NULL,
    last_event_id BIGINT NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 3.4. Bảng `admin_audit` - Meta audit

```sql
CREATE TABLE admin_audit (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_resource TEXT,
    details JSONB,
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature BYTEA NOT NULL -- Admin key signature
);

CREATE INDEX idx_admin_actor ON admin_audit(actor, timestamp_utc DESC);
```

---

## 4. API GATEWAY - FASTAPI

### 4.1. Cấu trúc project

```
audit-service/
├── app/
│   ├── main.py              # FastAPI app
│   ├── config.py            # Settings
│   ├── models.py            # Pydantic models
│   ├── crypto.py            # Signature verification
│   ├── database.py          # DB connection
│   ├── routers/
│   │   ├── ingest.py        # POST /v1/logs
│   │   ├── admin.py         # Admin endpoints
│   │   └── health.py        # Health check
│   └── services/
│       ├── verifier.py      # Crypto verification
│       ├── processor.py     # Event processing
│       └── key_manager.py   # Key operations
├── tests/
├── docker-compose.yml
├── requirements.txt
└── README.md
```

### 4.2. Dependencies (requirements.txt)

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
asyncpg==0.29.0
sqlalchemy==2.0.25
cryptography==42.0.0
PyNaCl==1.5.0
python-multipart==0.0.6
prometheus-client==0.19.0
```

### 4.3. Core endpoint - Event ingest

```python
# app/routers/ingest.py
from fastapi import APIRouter, HTTPException, Depends
from app.models import EventSubmission, EventResponse
from app.services.verifier import verify_event_signature
from app.services.processor import process_event
from app.database import get_db
import hashlib
import base64

router = APIRouter()

@router.post("/v1/logs", response_model=EventResponse)
async def submit_log(
    submission: EventSubmission,
    db = Depends(get_db)
):
    """
    Submit a signed audit event.
    Always returns generic response to prevent oracle attacks.
    """
    try:
        # 1. Verify signature
        is_valid = await verify_event_signature(
            event_canonical=submission.event,
            signature=base64.b64decode(submission.signature),
            public_key_id=submission.public_key_id,
            db=db
        )
        
        if not is_valid:
            # Generic error - no details leaked
            raise HTTPException(status_code=400, detail="rejected")
        
        # 2. Compute event hash
        event_hash = hashlib.sha256(
            submission.event.encode('utf-8')
        ).digest()
        
        # 3. Process and store
        event_id = await process_event(
            service_id=submission.service_id,
            event_type=submission.event_type,
            event_canonical=submission.event,
            event_data=submission.event_data,
            event_hash=event_hash,
            signature=base64.b64decode(submission.signature),
            public_key_id=submission.public_key_id,
            db=db
        )
        
        # 4. Generic success response
        return EventResponse(
            status="accepted",
            id=str(event_id)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Log internally but return generic error
        # logger.error(f"Event processing failed: {e}")
        raise HTTPException(status_code=400, detail="rejected")
```

### 4.4. Signature verification

```python
# app/services/verifier.py
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import base64

async def verify_event_signature(
    event_canonical: str,
    signature: bytes,
    public_key_id: str,
    db
) -> bool:
    """
    Verify event signature using constant-time operations.
    Returns bool only - never raise detailed exceptions.
    """
    try:
        # 1. Fetch public key
        key_info = await db.fetchrow(
            "SELECT public_key_pem, algorithm FROM key_registry "
            "WHERE public_key_id = $1 AND disabled_at IS NULL",
            public_key_id
        )
        
        if not key_info:
            return False
        
        # 2. Verify based on algorithm
        if key_info['algorithm'] == 'ed25519':
            return verify_ed25519(
                event_canonical.encode('utf-8'),
                signature,
                key_info['public_key_pem']
            )
        elif key_info['algorithm'] == 'rsa-pss':
            return verify_rsa_pss(
                event_canonical.encode('utf-8'),
                signature,
                key_info['public_key_pem']
            )
        
        return False
        
    except Exception:
        # Swallow all exceptions - constant-time response
        return False

def verify_ed25519(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    """Ed25519 verification using PyNaCl (libsodium wrapper)"""
    try:
        # Parse PEM to raw 32-byte key
        public_key_bytes = base64.b64decode(
            public_key_pem.replace('-----BEGIN PUBLIC KEY-----', '')
                          .replace('-----END PUBLIC KEY-----', '')
                          .replace('\n', '')
        )[-32:]  # Last 32 bytes
        
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        return False
    except Exception:
        return False

def verify_rsa_pss(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    """RSA-PSS verification"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
```

### 4.5. Event processor

```python
# app/services/processor.py
import hashlib
from datetime import datetime

async def process_event(
    service_id: str,
    event_type: str,
    event_canonical: str,
    event_data: dict,
    event_hash: bytes,
    signature: bytes,
    public_key_id: str,
    db
) -> int:
    """
    Process verified event: compute chain hash and insert to DB.
    """
    # 1. Get last chain hash for service
    chain_state = await db.fetchrow(
        "SELECT last_chain_hash FROM chain_state WHERE service_id = $1",
        service_id
    )
    
    prev_chain = chain_state['last_chain_hash'] if chain_state else b'\x00' * 32
    
    # 2. Compute new chain hash
    chain_input = prev_chain + event_hash + service_id.encode('utf-8')
    new_chain_hash = hashlib.sha256(chain_input).digest()
    
    # 3. Insert event
    async with db.transaction():
        event_id = await db.fetchval(
            """
            INSERT INTO audit_events (
                service_id, event_type, event_data, event_canonical,
                event_hash, signature, public_key_id, chain_hash,
                verified, timestamp_utc
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9)
            RETURNING id
            """,
            service_id, event_type, event_data, event_canonical,
            event_hash, signature, public_key_id, new_chain_hash,
            datetime.utcnow()
        )
        
        # 4. Update chain state
        await db.execute(
            """
            INSERT INTO chain_state (service_id, last_chain_hash, last_event_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (service_id) DO UPDATE
            SET last_chain_hash = $2, last_event_id = $3, last_updated = now()
            """,
            service_id, new_chain_hash, event_id
        )
    
    return event_id
```

---

## 5. ASYNC PROCESSING - POSTGRESQL LISTEN/NOTIFY

Thay vì Kafka, dùng PostgreSQL native:

```sql
-- Trigger function to notify new events
CREATE OR REPLACE FUNCTION notify_new_audit_event()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('audit_events', json_build_object(
        'id', NEW.id,
        'service_id', NEW.service_id,
        'event_type', NEW.event_type
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger
CREATE TRIGGER trigger_notify_audit_event
AFTER INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION notify_new_audit_event();
```

Consumer (Python):

```python
# app/services/event_consumer.py
import asyncpg
import asyncio
import json

async def consume_audit_events():
    """
    Listen to PostgreSQL notifications for async processing.
    Use for: analytics indexing, alerting, webhooks.
    """
    conn = await asyncpg.connect(DATABASE_URL)
    
    async def listener(connection, pid, channel, payload):
        event = json.loads(payload)
        # Process event: index to search, send alerts, etc.
        await index_to_search(event)
    
    await conn.add_listener('audit_events', listener)
    
    # Keep alive
    while True:
        await asyncio.sleep(1)
```

---

## 6. SEARCH & ANALYTICS - POSTGRESQL FTS

### 6.1. Full-text search trong PostgreSQL

```sql
-- Tìm kiếm trong event_data (JSONB)
SELECT id, service_id, event_type, event_data, timestamp_utc
FROM audit_events
WHERE event_data @> '{"actor": "alice"}'
  AND timestamp_utc > now() - interval '7 days'
ORDER BY timestamp_utc DESC
LIMIT 100;

-- Full-text search trong event_canonical
SELECT id, service_id, event_type, 
       ts_rank(to_tsvector('english', event_canonical), query) as rank
FROM audit_events,
     to_tsquery('english', 'fraud & delete') query
WHERE to_tsvector('english', event_canonical) @@ query
  AND timestamp_utc > now() - interval '30 days'
ORDER BY rank DESC
LIMIT 100;
```

### 6.2. Materialized view cho dashboard

```sql
-- Aggregation view - refresh hourly
CREATE MATERIALIZED VIEW event_stats_hourly AS
SELECT 
    date_trunc('hour', timestamp_utc) as hour,
    service_id,
    event_type,
    count(*) as event_count,
    count(*) FILTER (WHERE NOT verified) as failed_count
FROM audit_events
GROUP BY 1, 2, 3;

CREATE UNIQUE INDEX ON event_stats_hourly (hour, service_id, event_type);

-- Refresh via pg_cron
SELECT cron.schedule('refresh-stats', '0 * * * *', 
    'REFRESH MATERIALIZED VIEW CONCURRENTLY event_stats_hourly');
```

### 6.3. Optional: Meilisearch cho search UX tốt hơn

Nếu cần search phức tạp, thêm Meilisearch (nhẹ hơn Elasticsearch 10x):

```python
# Sync to Meilisearch via LISTEN/NOTIFY consumer
import meilisearch

client = meilisearch.Client('http://meilisearch:7700', 'master_key')
index = client.index('audit_events')

async def index_to_meilisearch(event_id: int, db):
    event = await db.fetchrow(
        "SELECT * FROM audit_events WHERE id = $1", event_id
    )
    
    await index.add_documents([{
        'id': event['id'],
        'service_id': event['service_id'],
        'event_type': event['event_type'],
        'timestamp': event['timestamp_utc'].isoformat(),
        'data': event['event_data'],
        'text': event['event_canonical']
    }])
```

---

## 7. KEY MANAGEMENT - FILE-BASED + PGCRYPTO

### 7.1. Key storage structure

```
/etc/audit-service/keys/
├── master.key          # Master encryption key (AES-256)
├── admin-signing.pem   # Admin operations signing key
└── publishers/
    ├── service-a.pub   # Publisher public keys
    └── service-b.pub
```

### 7.2. Encrypt sensitive data at rest

```sql
-- Mã hóa signature trong DB (optional)
INSERT INTO audit_events (..., signature, ...)
VALUES (..., pgp_sym_encrypt($signature, $master_key), ...);

-- Giải mã khi cần
SELECT pgp_sym_decrypt(signature, $master_key) FROM audit_events WHERE id = $1;
```

### 7.3. Key rotation script

```python
# scripts/rotate_key.py
async def rotate_service_key(service_id: str, new_public_key_pem: str):
    """Rotate public key for a service"""
    new_key_id = f"{service_id}:v{int(time.time())}"
    
    async with db.transaction():
        # Mark old key as rotated
        await db.execute(
            "UPDATE key_registry SET rotated_to = $1 WHERE service_id = $2 AND disabled_at IS NULL",
            new_key_id, service_id
        )
        
        # Insert new key
        await db.execute(
            """
            INSERT INTO key_registry (public_key_id, service_id, public_key_pem, algorithm, created_by)
            VALUES ($1, $2, $3, $4, $5)
            """,
            new_key_id, service_id, new_public_key_pem, 'ed25519', 'admin'
        )
        
        # Log admin action
        await db.execute(
            "INSERT INTO admin_audit (action, actor, target_resource, details) "
            "VALUES ('rotate_key', 'admin', $1, $2)",
            service_id, {'old_key': 'previous', 'new_key': new_key_id}
        )
```

---

## 8. DEPLOYMENT - DOCKER COMPOSE (CHI PHÍ THẤP)

```yaml
# docker-compose.yml
version: '3.9'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: audit_db
      POSTGRES_USER: audit_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    command: 
      - "postgres"
      - "-c" 
      - "shared_buffers=256MB"
      - "-c"
      - "max_connections=200"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U audit_user"]
      interval: 10s

  api:
    build: .
    environment:
      DATABASE_URL: postgresql://audit_user:${DB_PASSWORD}@postgres:5432/audit_db
      MASTER_KEY_PATH: /keys/master.key
    volumes:
      - ./keys:/keys:ro
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
    deploy:
      replicas: 2
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - api

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD}
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana

  # Optional: Meilisearch for better search UX
  meilisearch:
    image: getmeili/meilisearch:latest
    environment:
      MEILI_MASTER_KEY: ${MEILI_KEY}
    ports:
      - "7700:7700"
    volumes:
      - meili-data:/meili_data

volumes:
  pgdata:
  grafana-data:
  meili-data:
```

---

## 9. NGINX CONFIG - MTLS + RATE LIMITING

```nginx
# nginx.conf
upstream api_backend {
    least_conn;
    server api:8000;
}

# Rate limiting zones
limit_req_zone $ssl_client_s_dn zone=publisher_limit:10m rate=1000r/s;
limit_conn_zone $ssl_client_s_dn zone=conn_limit:10m;

server {
    listen 443 ssl http2;
    server_name audit.example.com;

    # TLS 1.3
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_protocols TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # mTLS for /v1/logs
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client optional;

    location /v1/logs {
        # Require client cert
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }

        # Rate limiting
        limit_req zone=publisher_limit burst=100 nodelay;
        limit_conn conn_limit 10;

        proxy_pass http://api_backend;
        proxy_set_header X-Client-DN $ssl_client_s_dn;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /v1/admin {
        # Admin requires OAuth2 (implement via auth_request)
        auth_request /auth;
        
        proxy_pass http://api_backend;
    }

    location /metrics {
        # Internal only
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://api_backend;
    }
}
```

---

## 10. MONITORING & ALERTING

### 10.1. Prometheus metrics

```python
# app/main.py
from prometheus_client import Counter, Histogram, generate_latest

# Metrics
events_received = Counter('audit_events_received_total', 'Total events received', ['service_id'])
events_rejected = Counter('audit_events_rejected_total', 'Total events rejected', ['service_id'])
signature_verify_duration = Histogram('signature_verification_seconds', 'Signature verification duration')
db_write_duration = Histogram('db_write_seconds', 'Database write duration')

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### 10.2. Grafana dashboards

```yaml
# grafana_dashboard.json (tóm tắt)
- Event ingest rate by service (events_received_total)
- Rejection rate (events_rejected_total / events_received_total)
- P95/P99 signature verification latency
- Database write latency
- Partition size growth
- Failed events by service
- Chain verification status
```

### 10.3. Alerts (Prometheus rules)

```yaml
# prometheus_rules.yml
groups:
  - name: audit_alerts
    rules:
      - alert: HighRejectionRate
        expr: rate(audit_events_rejected_total[5m]) > 10
        for: 5m
        annotations:
          summary: "High event rejection rate"
      
      - alert: SignatureVerificationSlow
        expr: histogram_quantile(0.95, signature_verification_seconds) > 0.1
        for: 5m
        annotations:
          summary: "Signature verification is slow"
      
      - alert: DatabaseWriteSlow
        expr: histogram_quantile(0.95, db_write_seconds) > 0.5
        for: 5m
```

---

## 11. SECURITY HARDENING

### 11.1. PostgreSQL security

```sql
-- Create limited role for API
CREATE ROLE audit_api_role LOGIN PASSWORD 'strong_password';

-- Only INSERT privilege on audit_events
GRANT INSERT ON audit_events TO audit_api_role;
GRANT SELECT ON key_registry TO audit_api_role;
GRANT UPDATE ON chain_state TO audit_api_role;

-- No UPDATE/DELETE
REVOKE UPDATE, DELETE ON audit_events FROM audit_api_role;

-- Read-only role for analytics
CREATE ROLE audit_readonly LOGIN PASSWORD 'read_password';
GRANT SELECT ON audit_events TO audit_readonly;
```

### 11.2. API rate limiting per service

```python
# app/middleware/rate_limit.py
from fastapi import Request, HTTPException
from redis import Redis
from datetime import datetime

redis_client = Redis(host='redis', port=6379, decode_responses=True)

async def rate_limit_middleware(request: Request, call_next):
    service_id = request.headers.get('X-Service-ID')
    if not service_id:
        raise HTTPException(400, "Missing X-Service-ID")
    
    # Rate limit: 1000 req/min per service
    key = f"ratelimit:{service_id}:{datetime.utcnow().strftime('%Y%m%d%H%M')}"
    count = redis_client.incr(key)
    redis_client.expire(key, 60)
    
    if count > 1000:
        raise HTTPException(429, "Rate limit exceeded")
    
    response = await call_next(request)
    return response
```

### 11.3. Intrusion detection

```sql
-- Detect anomalies
CREATE VIEW suspicious_activity AS
SELECT 
    service_id,
    count(*) as failed_attempts,
    array_agg(DISTINCT public_key_id) as keys_used
FROM audit_events
WHERE NOT verified
  AND timestamp_utc > now() - interval '1 hour'
GROUP BY service_id
HAVING count(*) > 100;

-- Alert on suspicious activity
SELECT cron.schedule('check-suspicious', '*/5 * * * *',
    $$
    SELECT pg_notify('security_alert', row_to_json(t)::text)
    FROM suspicious_activity t
    $$
);
```

---

## 12. BACKUP & DISASTER RECOVERY

### 12.1. PostgreSQL continuous backup

```bash
# WAL archiving (postgresql.conf)
wal_level = replica
archive_mode = on
archive_command = 'cp %p /backup/wal/%f'

# Base backup script
#!/bin/bash
pg_basebackup -h localhost -U postgres -D /backup/base/$(date +%Y%m%d) -