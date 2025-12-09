# Audit Log Service

**A cost-optimized, production-ready audit logging system with cryptographic integrity.**

## 🎯 Overview

This audit log service provides a secure, tamper-evident logging system using:
- **PostgreSQL** as the single source of truth (no Kafka, S3, or Elasticsearch needed)
- **FastAPI** for high-performance API handling
- **Ed25519/RSA-PSS** digital signatures for event integrity
- **Hash chaining** for tamper detection (blockchain-like)
- **PostgreSQL LISTEN/NOTIFY** for async processing

## 📋 Features

### Security
- ✅ Cryptographic signatures on all events
- ✅ Hash chaining for tamper detection
- ✅ mTLS authentication for publishers
- ✅ Append-only audit trail (no UPDATE/DELETE)
- ✅ Key rotation support

### Performance
- ✅ Partitioned tables for fast queries
- ✅ Connection pooling with asyncpg
- ✅ Full-text search with PostgreSQL FTS
- ✅ Materialized views for analytics

### Operations
- ✅ Prometheus metrics
- ✅ Grafana dashboards
- ✅ Health checks (liveness/readiness)
- ✅ Docker Compose deployment

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- OpenSSL (for certificate generation)

### 1. Clone and Configure

```bash
# Copy environment file
cp .env.example .env

# Edit configuration
nano .env
```

### 2. Generate Certificates (for mTLS)

```bash
# Create certificates directory
mkdir -p certs keys

# Generate CA
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
    -subj "/CN=Audit Log CA"

# Generate server certificate
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
    -subj "/CN=audit.example.com"
openssl x509 -req -days 365 -in certs/server.csr \
    -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
    -out certs/server.crt

# Generate master key
openssl rand -base64 32 > keys/master.key
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# With Meilisearch for advanced search
docker-compose --profile with-search up -d
```

### 4. Verify Installation

```bash
# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f api
```

## 📖 API Usage

### Register a Public Key

```bash
curl -X POST http://localhost:8000/v1/admin/keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: your-admin-token" \
  -d '{
    "service_id": "my-service",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "algorithm": "ed25519"
  }'
```

### Submit an Audit Event

```python
import base64
import json
import httpx
from nacl.signing import SigningKey

# Generate or load your signing key
signing_key = SigningKey.generate()

# Create event
event_data = {
    "actor": "user@example.com",
    "action": "LOGIN",
    "timestamp": "2025-01-01T00:00:00Z"
}

# Canonicalize (sorted keys, no whitespace)
canonical = json.dumps(event_data, sort_keys=True, separators=(',', ':'))

# Sign
signature = signing_key.sign(canonical.encode()).signature

# Submit
response = httpx.post(
    "https://audit.example.com/v1/logs",
    json={
        "service_id": "my-service",
        "event_type": "USER_LOGIN",
        "event": canonical,
        "event_data": event_data,
        "signature": base64.b64encode(signature).decode(),
        "public_key_id": "my-service:v1"
    },
    cert=("client.crt", "client.key"),
    verify="ca.crt"
)
```

### Query Events

```bash
# List events
curl "http://localhost:8000/v1/logs?service_id=my-service&limit=10"

# Search events
curl -X POST "http://localhost:8000/v1/logs/search" \
  -H "Content-Type: application/json" \
  -d '{"search_text": "fraud", "limit": 100}'
```

### Verify Chain Integrity

```bash
curl -X POST "http://localhost:8000/v1/admin/verify-chain?service_id=my-service" \
  -H "X-Admin-Token: your-admin-token"
```

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Publishers    │────▶│  Nginx (mTLS)   │────▶│   FastAPI API   │
│  (Services)     │     │  Rate Limiting  │     │  Verification   │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                ▼                                │
                        │  ┌─────────────────────────────────────────────────────────┐   │
                        │  │                    PostgreSQL                            │   │
                        │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │   │
                        │  │  │audit_events │  │key_registry │  │chain_state  │      │   │
                        │  │  │(partitioned)│  │             │  │             │      │   │
                        │  │  └─────────────┘  └─────────────┘  └─────────────┘      │   │
                        │  │                                                          │   │
                        │  │  LISTEN/NOTIFY ─────────────────────────────────────────│   │
                        │  └─────────────────────────────────────────────────────────┘   │
                        │                                │                                │
                        └────────────────────────────────┼────────────────────────────────┘
                                                         ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │ Event Consumer  │     │   Meilisearch   │
                        │ (Async Worker)  │────▶│   (Optional)    │
                        └─────────────────┘     └─────────────────┘
```

## 📊 Monitoring

### Prometheus Metrics

Available at `/metrics`:
- `audit_events_received_total` - Events received by service
- `audit_events_rejected_total` - Events rejected by reason
- `signature_verification_seconds` - Verification latency
- `db_write_seconds` - Database write latency

### Grafana Dashboards

Access Grafana at http://localhost:3000 (default: admin/admin)

Pre-configured dashboards:
- **Audit Log Service** - Main operational dashboard
- Event ingestion rate
- Rejection rates
- Latency percentiles

## 🔐 Security

### Authentication
- Publishers authenticate via mTLS client certificates
- Admin endpoints require X-Admin-Token header

### Signatures
- Ed25519 (recommended) - 64-byte signatures
- RSA-PSS (2048+ bits) - For legacy systems

### Key Rotation

```bash
curl -X POST http://localhost:8000/v1/admin/keys/rotate \
  -H "X-Admin-Token: your-admin-token" \
  -d '{
    "service_id": "my-service",
    "new_public_key_pem": "...",
    "algorithm": "ed25519"
  }'
```

## 📁 Project Structure

```
audit-service/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── database.py          # Database connection
│   ├── crypto.py            # Cryptographic operations
│   ├── models.py            # Pydantic models
│   ├── routers/
│   │   ├── ingest.py        # POST /v1/logs
│   │   ├── admin.py         # Admin endpoints
│   │   └── health.py        # Health checks
│   └── services/
│       ├── verifier.py      # Signature verification
│       ├── processor.py     # Event processing
│       ├── key_manager.py   # Key management
│       └── event_consumer.py # Async consumer
├── sql/
│   ├── init.sql             # Database schema
│   └── functions.sql        # Stored procedures
├── nginx/
│   └── nginx.conf           # Nginx configuration
├── monitoring/
│   ├── prometheus.yml       # Prometheus config
│   └── grafana/             # Grafana dashboards
├── tests/
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## 🧪 Testing

```bash
# Run tests
pip install -r requirements.txt
pytest tests/ -v

# With coverage
pytest tests/ --cov=app --cov-report=html
```

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...` |
| `MASTER_KEY_PATH` | Path to master encryption key | `/keys/master.key` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `RATE_LIMIT_REQUESTS` | Requests per minute | `1000` |
| `MEILISEARCH_URL` | Optional search URL | `null` |

## 📈 Scaling

### Horizontal Scaling
- Increase `api` replicas in docker-compose
- Use external PostgreSQL with connection pooling (PgBouncer)

### Data Retention
```sql
-- Keep 24 months of data
SELECT * FROM drop_old_partitions(24);
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pytest tests/`
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.
