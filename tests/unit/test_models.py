"""Unit tests for src/models.py"""

from datetime import datetime, timedelta, timezone

import peewee
import pytest

from src.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    RefreshToken,
    User,
)


class TestUser:
    """Tests for User model."""

    def test_create_user(self, database):
        """Should create a user successfully."""
        user = User.create(username="newuser", password_hash="hash")
        assert user.id is not None
        assert user.username == "newuser"
        assert user.created_at is not None

    def test_username_uniqueness(self, database):
        """Should enforce unique username constraint."""
        User.create(username="unique", password_hash="hash1")
        with pytest.raises(peewee.IntegrityError):
            User.create(username="unique", password_hash="hash2")

    def test_set_password(self, database):
        """Should hash password correctly."""
        user = User(username="testuser")
        user.set_password("mypassword")
        assert user.password_hash != "mypassword"
        assert len(user.password_hash) > 0

    def test_check_password_correct(self, database):
        """Should return True for correct password."""
        user = User(username="testuser")
        user.set_password("mypassword")
        user.save()
        assert user.check_password("mypassword") is True

    def test_check_password_incorrect(self, database):
        """Should return False for incorrect password."""
        user = User(username="testuser")
        user.set_password("mypassword")
        user.save()
        assert user.check_password("wrongpassword") is False

    def test_check_password_empty(self, database):
        """Should return False for empty password."""
        user = User(username="testuser")
        user.set_password("mypassword")
        user.save()
        assert user.check_password("") is False


class TestClient:
    """Tests for Client model."""

    def test_create_client(self, database):
        """Should create a client successfully."""
        client = Client.create(
            client_id="my-client",
            client_secret="my-secret",
            name="My App",
            redirect_uris="http://localhost/callback",
            allowed_scopes="openid profile",
        )
        assert client.id is not None
        assert client.client_id == "my-client"
        assert client.name == "My App"

    def test_client_id_uniqueness(self, database):
        """Should enforce unique client_id constraint."""
        Client.create(
            client_id="unique-client",
            client_secret="secret1",
            name="App 1",
            redirect_uris="http://localhost/callback",
        )
        with pytest.raises(peewee.IntegrityError):
            Client.create(
                client_id="unique-client",
                client_secret="secret2",
                name="App 2",
                redirect_uris="http://localhost/callback",
            )

    def test_get_redirect_uris(self, database):
        """Should parse space-separated redirect URIs."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://a.com/cb http://b.com/cb",
        )
        uris = client.get_redirect_uris()
        assert uris == ["http://a.com/cb", "http://b.com/cb"]

    def test_get_redirect_uris_empty(self, database):
        """Should return empty list for empty redirect_uris."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="",
        )
        assert client.get_redirect_uris() == []

    def test_get_allowed_scopes(self, database):
        """Should parse space-separated scopes."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
            allowed_scopes="openid profile email",
        )
        scopes = client.get_allowed_scopes()
        assert scopes == ["openid", "profile", "email"]

    def test_get_allowed_scopes_empty(self, database):
        """Should return empty list for empty allowed_scopes."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
            allowed_scopes="",
        )
        assert client.get_allowed_scopes() == []

    def test_validate_redirect_uri_valid(self, database):
        """Should return True for valid redirect URI."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb http://other.com/cb",
        )
        assert client.validate_redirect_uri("http://localhost/cb") is True
        assert client.validate_redirect_uri("http://other.com/cb") is True

    def test_validate_redirect_uri_invalid(self, database):
        """Should return False for invalid redirect URI."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
        )
        assert client.validate_redirect_uri("http://attacker.com/cb") is False

    def test_validate_scopes_valid_string(self, database):
        """Should return True for valid scopes as string."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
            allowed_scopes="openid profile email",
        )
        assert client.validate_scopes("openid profile") is True
        assert client.validate_scopes("openid") is True

    def test_validate_scopes_valid_list(self, database):
        """Should return True for valid scopes as list."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
            allowed_scopes="openid profile email",
        )
        assert client.validate_scopes(["openid", "profile"]) is True

    def test_validate_scopes_invalid(self, database):
        """Should return False for invalid scopes."""
        client = Client.create(
            client_id="test",
            client_secret="secret",
            name="Test",
            redirect_uris="http://localhost/cb",
            allowed_scopes="openid profile",
        )
        assert client.validate_scopes("openid admin") is False
        assert client.validate_scopes(["read", "write"]) is False


class TestAuthorizationCode:
    """Tests for AuthorizationCode model."""

    def test_create_code(self, database, test_user, test_client_oauth):
        """Should create an authorization code successfully."""
        auth_code = AuthorizationCode.create_code(
            client=test_client_oauth,
            user=test_user,
            redirect_uri="http://localhost:8080/callback",
            scopes="openid profile",
        )
        assert auth_code.id is not None
        assert len(auth_code.code) > 0
        assert auth_code.client.id == test_client_oauth.id
        assert auth_code.user.id == test_user.id
        assert auth_code.used is False

    def test_code_uniqueness(self, database, test_user, test_client_oauth):
        """Should generate unique codes."""
        code1 = AuthorizationCode.create_code(
            client=test_client_oauth,
            user=test_user,
            redirect_uri="http://localhost:8080/callback",
            scopes="openid",
        )
        code2 = AuthorizationCode.create_code(
            client=test_client_oauth,
            user=test_user,
            redirect_uri="http://localhost:8080/callback",
            scopes="openid",
        )
        assert code1.code != code2.code

    def test_is_expired_false(self, database, test_auth_code):
        """Should return False for non-expired code."""
        assert test_auth_code.is_expired() is False

    def test_is_expired_true(self, database, test_user, test_client_oauth):
        """Should return True for expired code."""
        auth_code = AuthorizationCode.create(
            code="expired-code",
            client=test_client_oauth,
            user=test_user,
            redirect_uri="http://localhost/cb",
            scopes="openid",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        assert auth_code.is_expired() is True


class TestAccessToken:
    """Tests for AccessToken model."""

    def test_create_token(self, database, test_user, test_client_oauth):
        """Should create an access token successfully."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            user=test_user,
            scopes="openid profile",
        )
        assert token.id is not None
        assert len(token.token) > 0
        assert token.revoked is False
        assert token.user.id == test_user.id

    def test_create_token_without_user(self, database, test_client_oauth):
        """Should create access token without user (client credentials flow)."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            scopes="read write",
            user=None,
        )
        assert token.user is None
        assert token.client.id == test_client_oauth.id

    def test_create_token_custom_expiry(self, database, test_client_oauth):
        """Should create token with custom expiry time."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            scopes="openid",
            expires_in=60,  # 1 minute
        )
        expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=60)
        # Allow 5 second tolerance
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 5

    def test_token_uniqueness(self, database, test_client_oauth):
        """Should generate unique tokens."""
        token1 = AccessToken.create_token(client=test_client_oauth, scopes="openid")
        token2 = AccessToken.create_token(client=test_client_oauth, scopes="openid")
        assert token1.token != token2.token

    def test_is_expired_false(self, database, test_access_token):
        """Should return False for non-expired token."""
        assert test_access_token.is_expired() is False

    def test_is_expired_true(self, database, expired_access_token):
        """Should return True for expired token."""
        assert expired_access_token.is_expired() is True

    def test_is_valid_true(self, database, test_access_token):
        """Should return True for valid token."""
        assert test_access_token.is_valid() is True

    def test_is_valid_false_revoked(self, database, revoked_access_token):
        """Should return False for revoked token."""
        assert revoked_access_token.is_valid() is False

    def test_is_valid_false_expired(self, database, expired_access_token):
        """Should return False for expired token."""
        assert expired_access_token.is_valid() is False


class TestRefreshToken:
    """Tests for RefreshToken model."""

    def test_create_token(self, database, test_access_token):
        """Should create a refresh token successfully."""
        refresh_token = RefreshToken.create_token(test_access_token)
        assert refresh_token.id is not None
        assert len(refresh_token.token) > 0
        assert refresh_token.revoked is False
        assert refresh_token.access_token.id == test_access_token.id

    def test_create_token_custom_expiry(self, database, test_access_token):
        """Should create refresh token with custom expiry time."""
        refresh_token = RefreshToken.create_token(
            test_access_token,
            expires_in=86400,  # 1 day
        )
        expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=86400)
        # Allow 5 second tolerance
        assert abs((refresh_token.expires_at - expected_expiry).total_seconds()) < 5

    def test_token_uniqueness(self, database, test_access_token):
        """Should generate unique refresh tokens."""
        token1 = RefreshToken.create_token(test_access_token)
        token2 = RefreshToken.create_token(test_access_token)
        assert token1.token != token2.token

    def test_is_expired_false(self, database, test_refresh_token):
        """Should return False for non-expired token."""
        assert test_refresh_token.is_expired() is False

    def test_is_expired_true(self, database, test_access_token):
        """Should return True for expired token."""
        refresh_token = RefreshToken.create(
            token="expired-refresh",
            access_token=test_access_token,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        assert refresh_token.is_expired() is True

    def test_is_valid_true(self, database, test_refresh_token):
        """Should return True for valid refresh token."""
        assert test_refresh_token.is_valid() is True

    def test_is_valid_false_revoked(self, database, test_access_token):
        """Should return False for revoked refresh token."""
        refresh_token = RefreshToken.create(
            token="revoked-refresh",
            access_token=test_access_token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            revoked=True,
        )
        assert refresh_token.is_valid() is False

    def test_is_valid_false_expired(self, database, test_access_token):
        """Should return False for expired refresh token."""
        refresh_token = RefreshToken.create(
            token="expired-refresh-2",
            access_token=test_access_token,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        assert refresh_token.is_valid() is False
