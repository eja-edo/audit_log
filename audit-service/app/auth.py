"""
Authentication module with JWT and password hashing.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from app.config import settings
from app.database import Database, get_db

logger = logging.getLogger(__name__)

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/v1/auth/login", auto_error=False)


# ============================================================================
# Models
# ============================================================================

class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Data extracted from JWT token."""
    username: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None


class User(BaseModel):
    """User model."""
    id: int
    username: str
    email: Optional[str] = None
    role: str = "user"
    is_active: bool = True


class UserInDB(User):
    """User model with hashed password."""
    hashed_password: str


class LoginRequest(BaseModel):
    """Login request body."""
    username: str
    password: str


class UserCreate(BaseModel):
    """User creation request."""
    username: str
    password: str
    email: Optional[str] = None
    role: str = "admin"


# ============================================================================
# Password Functions
# ============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using bcrypt."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')


# ============================================================================
# JWT Functions
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode
        expires_delta: Token expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.jwt_secret_key, 
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


def decode_access_token(token: str) -> Optional[TokenData]:
    """
    Decode and validate a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        TokenData if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=[settings.jwt_algorithm]
        )
        
        username: str = payload.get("sub")
        role: str = payload.get("role", "user")
        exp = payload.get("exp")
        
        if username is None:
            return None
            
        return TokenData(username=username, role=role, exp=exp)
        
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        return None


# ============================================================================
# User Database Functions
# ============================================================================

async def get_user_by_username(db: Database, username: str) -> Optional[UserInDB]:
    """Fetch user from database by username."""
    row = await db.fetchrow(
        """
        SELECT id, username, email, hashed_password, role, is_active
        FROM admin_users
        WHERE username = $1
        """,
        username
    )
    
    if row:
        return UserInDB(
            id=row['id'],
            username=row['username'],
            email=row['email'],
            hashed_password=row['hashed_password'],
            role=row['role'],
            is_active=row['is_active']
        )
    return None


async def authenticate_user(db: Database, username: str, password: str) -> Optional[User]:
    """
    Authenticate user with username and password.
    
    Args:
        db: Database connection
        username: Username
        password: Plain text password
        
    Returns:
        User object if authenticated, None otherwise
    """
    user = await get_user_by_username(db, username)
    
    if not user:
        logger.warning(f"Login attempt for non-existent user: {username}")
        return None
        
    if not user.is_active:
        logger.warning(f"Login attempt for inactive user: {username}")
        return None
        
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Invalid password for user: {username}")
        return None
    
    logger.info(f"User authenticated: {username}")
    return User(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active
    )


async def create_user(db: Database, user_create: UserCreate) -> User:
    """Create a new admin user."""
    hashed_password = get_password_hash(user_create.password)
    
    row = await db.fetchrow(
        """
        INSERT INTO admin_users (username, email, hashed_password, role, is_active)
        VALUES ($1, $2, $3, $4, true)
        RETURNING id, username, email, role, is_active
        """,
        user_create.username,
        user_create.email,
        hashed_password,
        user_create.role
    )
    
    logger.info(f"Created new user: {user_create.username}")
    
    return User(
        id=row['id'],
        username=row['username'],
        email=row['email'],
        role=row['role'],
        is_active=row['is_active']
    )


# ============================================================================
# Dependencies
# ============================================================================

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Database = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user from JWT token.
    
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token_data = decode_access_token(token)
    
    if token_data is None:
        raise credentials_exception
    
    user = await get_user_by_username(db, token_data.username)
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return User(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active
    )


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to ensure current user is an admin.
    
    Raises:
        HTTPException: If user is not an admin
    """
    if current_user.role not in ("admin", "superadmin"):
        logger.warning(f"Non-admin user {current_user.username} attempted admin action")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user


# ============================================================================
# Backward Compatibility - X-Admin-Token Support
# ============================================================================

from fastapi.security import APIKeyHeader

admin_token_header = APIKeyHeader(name="X-Admin-Token", auto_error=False)


async def get_admin_user_or_token(
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_admin_token: Optional[str] = Depends(admin_token_header),
    db: Database = Depends(get_db)
) -> User:
    """
    Dependency that accepts either JWT token or legacy X-Admin-Token.
    
    Priority:
    1. JWT Bearer token (preferred)
    2. X-Admin-Token header (legacy, for backward compatibility)
    """
    # Try JWT first
    if token:
        try:
            return await get_current_user(token, db)
        except HTTPException:
            pass
    
    # Fall back to X-Admin-Token
    if x_admin_token:
        if x_admin_token == settings.admin_token:
            logger.warning("Using legacy X-Admin-Token authentication (deprecated)")
            return User(
                id=0,
                username="legacy_admin",
                email=None,
                role="admin",
                is_active=True
            )
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use Bearer token or X-Admin-Token",
        headers={"WWW-Authenticate": "Bearer"},
    )
