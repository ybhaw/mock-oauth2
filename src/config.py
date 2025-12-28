"""Centralized configuration for the OAuth2 server.

All configurations can be overridden via environment variables with the same name.
"""

import os
import secrets


def get_env(name: str, default: str) -> str:
    """Get environment variable or return default."""
    return os.getenv(name, default)


def get_env_int(name: str, default: int) -> int:
    """Get environment variable as integer or return default."""
    value = os.getenv(name)
    if value is not None:
        return int(value)
    return default


def get_env_bool(name: str, default: bool) -> bool:
    """Get environment variable as boolean or return default."""
    value = os.getenv(name)
    if value is not None:
        return value.lower() in ("true", "1", "yes")
    return default


# Flask settings
SECRET_KEY = get_env("SECRET_KEY", secrets.token_hex(32))
DEBUG = get_env_bool("DEBUG", True)
HOST = get_env("HOST", "127.0.0.1")
PORT = get_env_int("PORT", 8083)

# Database
DATABASE_PATH = get_env("DATABASE_PATH", "oauth2.db")

# Token expiration times (in seconds)
AUTHORIZATION_CODE_EXPIRES_IN = get_env_int(
    "AUTHORIZATION_CODE_EXPIRES_IN", 600
)  # 10 minutes
ACCESS_TOKEN_EXPIRES_IN = get_env_int("ACCESS_TOKEN_EXPIRES_IN", 3600)  # 1 hour
REFRESH_TOKEN_EXPIRES_IN = get_env_int("REFRESH_TOKEN_EXPIRES_IN", 2592000)  # 30 days

# Test credentials (created on startup)
TEST_USER_USERNAME = get_env("TEST_USER_USERNAME", "testuser")
TEST_USER_PASSWORD = get_env("TEST_USER_PASSWORD", "testpass")
TEST_CLIENT_ID = get_env("TEST_CLIENT_ID", "test-client")
TEST_CLIENT_SECRET = get_env("TEST_CLIENT_SECRET", "test-secret")
TEST_CLIENT_NAME = get_env("TEST_CLIENT_NAME", "Test Application")
TEST_CLIENT_REDIRECT_URIS = get_env(
    "TEST_CLIENT_REDIRECT_URIS",
    "http://localhost:8080/callback http://localhost:3000/callback",
)
TEST_CLIENT_SCOPES = get_env("TEST_CLIENT_SCOPES", "openid profile email read write")
