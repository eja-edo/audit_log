"""
Authentication endpoints: login, token refresh, user management.
"""

import logging
from datetime import timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import (
    Token, User, UserCreate, LoginRequest,
    authenticate_user, create_access_token, create_user,
    get_current_user, get_current_admin_user, get_password_hash
)
from app.config import settings
from app.database import Database, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/auth", tags=["authentication"])


@router.post("/login", response_model=Token)
async def login(
    login_request: LoginRequest,
    db: Database = Depends(get_db)
):
    """
    Authenticate user and return JWT access token.
    
    **Request Body:**
    - `username`: Admin username
    - `password`: Admin password
    
    **Returns:**
    - `access_token`: JWT token for authentication
    - `token_type`: "bearer"
    - `expires_in`: Token expiration time in seconds
    
    **Usage:**
    ```
    curl -X POST http://localhost/v1/auth/login \\
      -H "Content-Type: application/json" \\
      -d '{"username": "admin", "password": "your-password"}'
    ```
    
    Then use the token:
    ```
    curl -X GET http://localhost/v1/admin/keys/pending \\
      -H "Authorization: Bearer <your-token>"
    ```
    """
    user = await authenticate_user(db, login_request.username, login_request.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    logger.info(f"User logged in: {user.username}")
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60
    )


@router.post("/login/form", response_model=Token)
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Database = Depends(get_db)
):
    """
    OAuth2 compatible login endpoint (form-based).
    
    Used by Swagger UI and OAuth2 clients.
    """
    user = await authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60
    )


@router.get("/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user information.
    
    **Headers:**
    - `Authorization: Bearer <token>` (required)
    """
    return current_user


@router.post("/users", response_model=User)
async def create_admin_user(
    user_create: UserCreate,
    current_user: User = Depends(get_current_admin_user),
    db: Database = Depends(get_db)
):
    """
    Create a new admin user.
    
    **Requires:** Admin authentication
    
    **Request Body:**
    - `username`: Unique username
    - `password`: Strong password
    - `email`: Optional email
    - `role`: "admin" or "superadmin"
    """
    # Check if username already exists
    existing = await db.fetchrow(
        "SELECT id FROM admin_users WHERE username = $1",
        user_create.username
    )
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Only superadmin can create superadmin
    if user_create.role == "superadmin" and current_user.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin can create superadmin users"
        )
    
    new_user = await create_user(db, user_create)
    
    logger.info(f"Admin user created: {new_user.username} by {current_user.username}")
    
    return new_user


@router.get("/users", response_model=List[User])
async def list_users(
    current_user: User = Depends(get_current_admin_user),
    db: Database = Depends(get_db)
):
    """
    List all admin users.
    
    **Requires:** Admin authentication
    """
    rows = await db.fetch(
        """
        SELECT id, username, email, role, is_active
        FROM admin_users
        ORDER BY id
        """
    )
    
    return [
        User(
            id=row['id'],
            username=row['username'],
            email=row['email'],
            role=row['role'],
            is_active=row['is_active']
        )
        for row in rows
    ]


@router.put("/users/{user_id}/password")
async def change_password(
    user_id: int,
    new_password: str,
    current_user: User = Depends(get_current_admin_user),
    db: Database = Depends(get_db)
):
    """
    Change user password.
    
    **Requires:** Admin authentication
    
    Users can change their own password.
    Superadmin can change any user's password.
    """
    # Check permissions
    if current_user.id != user_id and current_user.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change other user's password"
        )
    
    hashed_password = get_password_hash(new_password)
    
    await db.execute(
        """
        UPDATE admin_users SET hashed_password = $1 WHERE id = $2
        """,
        hashed_password,
        user_id
    )
    
    logger.info(f"Password changed for user ID: {user_id}")
    
    return {"message": "Password changed successfully"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_admin_user),
    db: Database = Depends(get_db)
):
    """
    Disable a user account.
    
    **Requires:** Superadmin authentication
    """
    if current_user.role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin can delete users"
        )
    
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    await db.execute(
        "UPDATE admin_users SET is_active = false WHERE id = $1",
        user_id
    )
    
    logger.info(f"User {user_id} disabled by {current_user.username}")
    
    return {"message": "User disabled successfully"}
