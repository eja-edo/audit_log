"""
Pydantic models for request/response validation.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Event Models
# ============================================================================

class EventSubmission(BaseModel):
    """Request model for submitting an audit event."""
    
    service_id: str = Field(
        ..., 
        min_length=1, 
        max_length=100,
        description="Unique identifier of the publishing service",
        examples=["user-service", "payment-api"]
    )
    
    event_type: str = Field(
        ..., 
        min_length=1, 
        max_length=100,
        description="Type of the audit event",
        examples=["USER_LOGIN", "PAYMENT_CREATED", "DATA_DELETED"]
    )
    
    event: str = Field(
        ..., 
        min_length=1,
        description="Canonical form of event data (normalized, sorted keys)",
        examples=['{"action":"login","actor":"alice","timestamp":"2025-01-01T00:00:00Z"}']
    )
    
    event_data: Dict[str, Any] = Field(
        ...,
        description="Structured event data as JSON object"
    )
    
    signature: str = Field(
        ..., 
        min_length=1,
        description="Base64-encoded signature of the canonical event",
        examples=["BASE64_ENCODED_SIGNATURE"]
    )
    
    public_key_id: str = Field(
        ..., 
        min_length=1, 
        max_length=200,
        description="ID of the public key to verify signature",
        examples=["user-service:v1", "payment-api:v2"]
    )
    
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Event timestamp (uses server time if not provided)"
    )
    
    @field_validator('service_id', 'event_type')
    @classmethod
    def validate_alphanumeric_with_separators(cls, v: str) -> str:
        """Allow only alphanumeric characters, hyphens, and underscores."""
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Must contain only alphanumeric characters, hyphens, and underscores')
        return v


class EventResponse(BaseModel):
    """Response model for event submission."""
    
    status: str = Field(
        ...,
        description="Submission status",
        examples=["accepted", "rejected"]
    )
    
    id: Optional[str] = Field(
        default=None,
        description="Event ID if accepted"
    )
    
    message: Optional[str] = Field(
        default=None,
        description="Additional verification details (for demo purposes)"
    )


class EventQuery(BaseModel):
    """Query parameters for searching events."""
    
    service_id: Optional[str] = None
    event_type: Optional[str] = None
    actor: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search_text: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class EventDetail(BaseModel):
    """Detailed event information."""
    
    id: int
    service_id: str
    event_type: str
    event_data: Dict[str, Any]
    event_hash: str
    chain_hash: str
    verified: bool
    timestamp_utc: datetime
    received_at: datetime
    public_key_id: str


# ============================================================================
# Key Management Models
# ============================================================================

class PublicKeyRegistration(BaseModel):
    """Request to register a new public key."""
    
    service_id: str = Field(..., min_length=1, max_length=100)
    public_key_pem: str = Field(..., description="PEM-encoded public key")
    algorithm: str = Field(
        ..., 
        pattern="^(ed25519|rsa-pss|rsa-pkcs1v15|rsa-pkcs1v15-vulnerable)$",
        description="Signature algorithm. Use 'rsa-pkcs1v15-vulnerable' for Bleichenbacher attack demo only!"
    )
    metadata: Optional[Dict[str, Any]] = None


class PublicKeyInfo(BaseModel):
    """Public key information response."""
    
    public_key_id: str
    service_id: str
    algorithm: str
    status: str = Field(default="pending", description="pending, approved, rejected")
    created_at: datetime
    created_by: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    disabled_at: Optional[datetime] = None
    rotated_to: Optional[str] = None


class KeyRotationRequest(BaseModel):
    """Request to rotate a service's key."""
    
    service_id: str
    new_public_key_pem: str
    algorithm: str = Field(
        default="ed25519", 
        pattern="^(ed25519|rsa-pss|rsa-pkcs1v15|rsa-pkcs1v15-vulnerable)$"
    )


class KeyApprovalRequest(BaseModel):
    """Request to approve or reject a pending key."""
    
    public_key_id: str = Field(..., description="ID of the pending key")
    action: str = Field(..., pattern="^(approve|reject)$", description="approve or reject")
    reason: Optional[str] = Field(None, description="Reason for rejection (required if rejecting)")


# ============================================================================
# Admin Models
# ============================================================================

class AdminAction(BaseModel):
    """Admin action audit record."""
    
    id: int
    action: str
    actor: str
    target_resource: Optional[str]
    details: Optional[Dict[str, Any]]
    timestamp_utc: datetime


class ChainVerificationResult(BaseModel):
    """Result of chain integrity verification."""
    
    service_id: str
    is_valid: bool
    events_checked: int
    first_invalid_event_id: Optional[int] = None
    error_message: Optional[str] = None


# ============================================================================
# Health Check Models
# ============================================================================

class HealthStatus(BaseModel):
    """Health check response."""
    
    status: str = Field(..., examples=["healthy", "unhealthy"])
    version: str
    database: str = Field(..., examples=["connected", "disconnected"])
    uptime_seconds: float
    timestamp: datetime


class ServiceStats(BaseModel):
    """Service statistics."""
    
    total_events: int
    events_last_hour: int
    events_last_day: int
    services_count: int
    failed_verifications: int
