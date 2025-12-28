"""Pytest configuration and fixtures for the OAuth2 server tests."""

import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest

# Set test environment variables BEFORE any imports from src
os.environ["SECRET_KEY"] = "test-secret-key"

# Create a temp file for the database
_temp_db_fd, _temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(_temp_db_fd)
os.environ["DATABASE_PATH"] = _temp_db_path


@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Set up a fresh database for each test."""
    from src.models import (
        AccessToken,
        AuthorizationCode,
        Client,
        RefreshToken,
        User,
        db,
    )

    MODELS = [User, Client, AuthorizationCode, AccessToken, RefreshToken]

    # Reinitialize db to our test path
    db.init(_temp_db_path)

    # Connect and create tables
    if not db.is_closed():
        db.close()
    db.connect()

    # Drop and recreate tables for each test
    db.drop_tables(MODELS, safe=True)
    db.create_tables(MODELS)

    yield db

    # Cleanup
    db.drop_tables(MODELS, safe=True)
    if not db.is_closed():
        db.close()


@pytest.fixture(scope="function")
def database(setup_database):
    """Alias for setup_database fixture."""
    return setup_database


@pytest.fixture(scope="function")
def client(setup_database):
    """Create a Flask test client with fresh database."""
    from src.server import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as test_client, app.app_context():
        yield test_client


@pytest.fixture
def test_user(setup_database):
    """Create a test user."""
    from src.models import User

    user = User(username="fixture_testuser")
    user.set_password("testpass")
    user.save()
    return user


@pytest.fixture
def test_client_oauth(setup_database):
    """Create a test OAuth2 client."""
    from src.models import Client

    oauth_client = Client.create(
        client_id="fixture-test-client-id",
        client_secret="fixture-test-client-secret",
        name="Test Application",
        redirect_uris="http://localhost:8080/callback http://localhost:3000/callback",
        allowed_scopes="openid profile email read write",
    )
    return oauth_client


@pytest.fixture
def test_access_token(setup_database, test_user, test_client_oauth):
    """Create a test access token."""
    from src.models import AccessToken

    return AccessToken.create_token(
        client=test_client_oauth,
        user=test_user,
        scopes="openid profile email",
    )


@pytest.fixture
def test_refresh_token(setup_database, test_access_token):
    """Create a test refresh token."""
    from src.models import RefreshToken

    return RefreshToken.create_token(test_access_token)


@pytest.fixture
def test_auth_code(setup_database, test_user, test_client_oauth):
    """Create a test authorization code."""
    from src.models import AuthorizationCode

    return AuthorizationCode.create_code(
        client=test_client_oauth,
        user=test_user,
        redirect_uri="http://localhost:8080/callback",
        scopes="openid profile",
    )


@pytest.fixture
def expired_access_token(setup_database, test_user, test_client_oauth):
    """Create an expired access token."""
    from src.models import AccessToken

    token = AccessToken.create(
        token="expired-token",
        client=test_client_oauth,
        user=test_user,
        scopes="openid",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    return token


@pytest.fixture
def revoked_access_token(setup_database, test_user, test_client_oauth):
    """Create a revoked access token."""
    from src.models import AccessToken

    token = AccessToken.create(
        token="revoked-token",
        client=test_client_oauth,
        user=test_user,
        scopes="openid",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        revoked=True,
    )
    return token


@pytest.fixture
def authenticated_client(client, test_user):
    """Create a Flask test client with authenticated session."""
    with client.session_transaction() as sess:
        sess["user_id"] = test_user.id
    return client
