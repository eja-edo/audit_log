"""
FastAPI Application Entry Point

This is the main application module that sets up the FastAPI app,
configures middleware, and includes all routers.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import database
from app.routers import ingest, admin, health, keys

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events:
    - Startup: Initialize database connection pool
    - Shutdown: Close database connections gracefully
    """
    # Startup
    logger.info("Starting Audit Log Service...")
    await database.connect()
    logger.info("Audit Log Service started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Audit Log Service...")
    await database.disconnect()
    logger.info("Audit Log Service stopped")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    # Audit Log Service API
    
    A cost-optimized, production-ready audit logging system with:
    
    - **Cryptographic Signatures**: Ed25519/RSA-PSS for event integrity
    - **Hash Chaining**: Tamper-evident event chain (blockchain-like)
    - **Full-Text Search**: PostgreSQL FTS for event searching
    - **High Performance**: Async processing with connection pooling
    
    ## Architecture
    
    - Single PostgreSQL database as source of truth
    - FastAPI for high-performance API handling
    - LISTEN/NOTIFY for async event processing
    - No Kafka, S3, or Elasticsearch required
    
    ## Security Features
    
    - mTLS for publisher authentication
    - Signature verification on all events
    - Append-only audit trail
    - Chain verification for tamper detection
    """,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan
)


# ============================================================================
# Middleware
# ============================================================================

# CORS (configure appropriately for production)
if settings.debug:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def add_request_timing(request: Request, call_next):
    """Add request timing header for monitoring."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests."""
    logger.debug(f"{request.method} {request.url.path}")
    response = await call_next(request)
    return response


# ============================================================================
# Exception Handlers
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler.
    
    Returns generic error responses to prevent information leakage.
    Detailed errors are logged internally.
    """
    logger.exception(f"Unhandled exception: {exc}")
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# ============================================================================
# Include Routers
# ============================================================================

# Event ingestion endpoints
app.include_router(ingest.router)

# Key registration endpoints (service self-registration)
app.include_router(keys.router)

# Admin endpoints (key approval, verification)
app.include_router(admin.router)

# Health check and monitoring
app.include_router(health.router)


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint.
    
    Returns basic service information.
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running"
    }


# ============================================================================
# Development Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers
    )
