"""
Health check and monitoring endpoints.
"""

import time
from datetime import datetime

from fastapi import APIRouter, Depends, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.config import settings
from app.database import Database, get_db
from app.models import HealthStatus

router = APIRouter(tags=["monitoring"])

# Track application start time
START_TIME = time.time()


@router.get("/health", response_model=HealthStatus)
async def health_check(db: Database = Depends(get_db)):
    """
    Health check endpoint.
    
    Returns the overall health status of the service including:
    - Database connectivity
    - Service uptime
    - Application version
    
    This endpoint is typically used by load balancers and
    orchestration systems (Kubernetes, Docker Swarm) for
    health monitoring.
    """
    # Check database
    db_healthy = await db.health_check()
    
    return HealthStatus(
        status="healthy" if db_healthy else "unhealthy",
        version=settings.app_version,
        database="connected" if db_healthy else "disconnected",
        uptime_seconds=time.time() - START_TIME,
        timestamp=datetime.utcnow()
    )


@router.get("/health/live")
async def liveness_check():
    """
    Kubernetes liveness probe.
    
    Simple check that the application is running.
    Does not check dependencies.
    """
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness_check(db: Database = Depends(get_db)):
    """
    Kubernetes readiness probe.
    
    Checks that the application is ready to receive traffic.
    Verifies database connectivity.
    """
    db_healthy = await db.health_check()
    
    if not db_healthy:
        return Response(
            content='{"status": "not ready", "reason": "database disconnected"}',
            status_code=503,
            media_type="application/json"
        )
    
    return {"status": "ready"}


@router.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.
    
    Returns metrics in Prometheus text format including:
    - Event ingestion rates
    - Signature verification latency
    - Database write latency
    - Error counts
    """
    if not settings.enable_metrics:
        return Response(status_code=404)
    
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@router.get("/info")
async def info():
    """
    Service information endpoint.
    
    Returns basic information about the running service.
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "uptime_seconds": time.time() - START_TIME
    }
