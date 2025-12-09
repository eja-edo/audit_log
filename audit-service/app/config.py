"""
Configuration settings for Audit Log Service.
Uses pydantic-settings for environment variable management.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )
    
    # Application
    app_name: str = "Audit Log Service"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = Field(default="production", description="development/staging/production")
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Database
    database_url: str = Field(
        default="postgresql://audit_user:password@localhost:5432/audit_db",
        description="PostgreSQL connection URL"
    )
    db_pool_min_size: int = 5
    db_pool_max_size: int = 20
    db_command_timeout: int = 60
    
    # Security
    master_key_path: Path = Field(
        default=Path("/keys/master.key"),
        description="Path to master encryption key"
    )
    admin_signing_key_path: Optional[Path] = Field(
        default=None,
        description="Path to admin signing key"
    )
    
    # Admin Authentication
    admin_token: str = Field(
        default="change-me-in-production",
        description="Admin API token for authentication"
    )
    
    # Rate Limiting
    rate_limit_requests: int = 1000
    rate_limit_window_seconds: int = 60
    
    # Meilisearch (Optional)
    meilisearch_url: Optional[str] = None
    meilisearch_api_key: Optional[str] = None
    
    # Monitoring
    enable_metrics: bool = True
    metrics_path: str = "/metrics"
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    @property
    def async_database_url(self) -> str:
        """Convert to async driver URL if needed."""
        url = self.database_url
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
