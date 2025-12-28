"""Unit tests for src/controllers/oauth_controller.py"""

import base64
from datetime import UTC, datetime, timedelta

from src.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    RefreshToken,
)


class TestAuthorizeEndpoint:
    """Tests for /authorize endpoint."""

    def test_authorize_invalid_response_type(self, client, database):
        """Should reject invalid response_type."""
        response = client.get("/authorize?response_type=token&client_id=test")
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "unsupported_response_type"

    def test_authorize_invalid_client(self, client, database):
        """Should reject invalid client_id."""
        response = client.get(
            "/authorize?response_type=code&client_id=nonexistent&redirect_uri=http://localhost/cb"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_client"

    def test_authorize_invalid_redirect_uri(self, client, test_client_oauth):
        """Should reject invalid redirect_uri."""
        response = client.get(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://attacker.com/cb"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_redirect_uri"

    def test_authorize_redirects_to_login_when_not_authenticated(
        self, client, test_client_oauth
    ):
        """Should redirect to login when user is not authenticated."""
        response = client.get(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid"
        )
        assert response.status_code == 302
        assert "/user/login" in response.location

    def test_authorize_shows_consent_page(
        self, authenticated_client, test_client_oauth
    ):
        """Should show consent page for authenticated user."""
        response = authenticated_client.get(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid%20profile"
        )
        assert response.status_code == 200
        assert (
            b"consent" in response.data.lower() or b"authorize" in response.data.lower()
        )

    def test_authorize_creates_code_on_approval(
        self, authenticated_client, test_client_oauth
    ):
        """Should create authorization code on approval."""
        # First GET to set up session
        authenticated_client.get(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid&state=xyz"
        )
        # POST approval
        response = authenticated_client.post(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid&state=xyz",
            data={"approve": "1"},
        )
        assert response.status_code == 302
        assert "code=" in response.location
        assert "state=xyz" in response.location

    def test_authorize_denial_redirects_with_error(
        self, authenticated_client, test_client_oauth
    ):
        """Should redirect with access_denied error on denial."""
        # First GET to set up session
        authenticated_client.get(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid&state=abc"
        )
        # POST denial
        response = authenticated_client.post(
            f"/authorize?response_type=code&client_id={test_client_oauth.client_id}"
            "&redirect_uri=http://localhost:8080/callback&scope=openid&state=abc",
            data={"deny": "1"},
        )
        assert response.status_code == 302
        assert "error=access_denied" in response.location
        assert "state=abc" in response.location


class TestTokenEndpoint:
    """Tests for /token endpoint."""

    def test_token_unsupported_grant_type(self, client, database):
        """Should reject unsupported grant type."""
        response = client.post("/token", data={"grant_type": "password"})
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "unsupported_grant_type"

    def test_token_missing_grant_type(self, client, database):
        """Should reject missing grant type."""
        response = client.post("/token", data={})
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "unsupported_grant_type"


class TestAuthorizationCodeGrant:
    """Tests for authorization_code grant type."""

    def test_authorization_code_success(
        self, client, test_client_oauth, test_auth_code
    ):
        """Should exchange valid code for tokens."""
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data

    def test_authorization_code_with_basic_auth(
        self, client, test_client_oauth, test_auth_code
    ):
        """Should accept client credentials via Basic auth."""
        credentials = base64.b64encode(
            f"{test_client_oauth.client_id}:{test_client_oauth.client_secret}".encode()
        ).decode()
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://localhost:8080/callback",
            },
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data

    def test_authorization_code_invalid_client(self, client, test_auth_code):
        """Should reject invalid client credentials."""
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": "wrong-client",
                "client_secret": "wrong-secret",
            },
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_client"

    def test_authorization_code_missing_code(self, client, test_client_oauth):
        """Should reject missing code."""
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_request"

    def test_authorization_code_invalid_code(self, client, test_client_oauth):
        """Should reject invalid code."""
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid-code",
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_authorization_code_already_used(
        self, client, test_client_oauth, test_auth_code
    ):
        """Should reject already used code."""
        test_auth_code.used = True
        test_auth_code.save()

        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_authorization_code_expired(
        self, client, test_client_oauth, test_user, database
    ):
        """Should reject expired code."""
        expired_code = AuthorizationCode.create(
            code="expired-test-code",
            client=test_client_oauth,
            user=test_user,
            redirect_uri="http://localhost:8080/callback",
            scopes="openid",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )

        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": expired_code.code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_authorization_code_redirect_uri_mismatch(
        self, client, test_client_oauth, test_auth_code
    ):
        """Should reject mismatched redirect_uri."""
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://different.com/callback",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_authorization_code_wrong_client(self, client, test_auth_code, database):
        """Should reject code issued to different client."""
        other_client = Client.create(
            client_id="other-client",
            client_secret="other-secret",
            name="Other App",
            redirect_uris="http://other.com/cb",
        )

        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": test_auth_code.code,
                "redirect_uri": "http://localhost:8080/callback",
                "client_id": other_client.client_id,
                "client_secret": other_client.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"


class TestClientCredentialsGrant:
    """Tests for client_credentials grant type."""

    def test_client_credentials_success(self, client, test_client_oauth):
        """Should issue token for valid client credentials."""
        response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        # Client credentials should NOT have refresh token typically
        # but implementation may vary

    def test_client_credentials_with_scope(self, client, test_client_oauth):
        """Should issue token with requested scope."""
        response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
                "scope": "read write",
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "scope" in data

    def test_client_credentials_invalid_scope(self, client, test_client_oauth):
        """Should reject invalid scope."""
        response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
                "scope": "admin superuser",  # Not in allowed_scopes
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_scope"

    def test_client_credentials_invalid_client(self, client, database):
        """Should reject invalid client credentials."""
        response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "wrong",
                "client_secret": "wrong",
            },
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_client"


class TestRefreshTokenGrant:
    """Tests for refresh_token grant type."""

    def test_refresh_token_success(self, client, test_client_oauth, test_refresh_token):
        """Should issue new tokens for valid refresh token."""
        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": test_refresh_token.token,
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should be different
        assert data["refresh_token"] != test_refresh_token.token

    def test_refresh_token_revokes_old_tokens(
        self, client, test_client_oauth, test_refresh_token, test_access_token
    ):
        """Should revoke old tokens when refreshing."""
        old_access = test_access_token.token
        old_refresh = test_refresh_token.token

        client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": test_refresh_token.token,
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )

        # Reload tokens from database
        old_access_token = AccessToken.get(AccessToken.token == old_access)
        old_refresh_token = RefreshToken.get(RefreshToken.token == old_refresh)

        assert old_access_token.revoked is True
        assert old_refresh_token.revoked is True

    def test_refresh_token_missing(self, client, test_client_oauth):
        """Should reject missing refresh token."""
        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_request"

    def test_refresh_token_invalid(self, client, test_client_oauth):
        """Should reject invalid refresh token."""
        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "invalid-token",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_refresh_token_revoked(self, client, test_client_oauth, test_refresh_token):
        """Should reject revoked refresh token."""
        test_refresh_token.revoked = True
        test_refresh_token.save()

        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": test_refresh_token.token,
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"

    def test_refresh_token_wrong_client(self, client, test_refresh_token, database):
        """Should reject refresh token from different client."""
        other_client = Client.create(
            client_id="other-client",
            client_secret="other-secret",
            name="Other App",
            redirect_uris="http://other.com/cb",
        )

        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": test_refresh_token.token,
                "client_id": other_client.client_id,
                "client_secret": other_client.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_grant"


class TestRevokeEndpoint:
    """Tests for /revoke endpoint."""

    def test_revoke_access_token(self, client, test_client_oauth, test_access_token):
        """Should revoke access token successfully."""
        response = client.post(
            "/revoke",
            data={
                "token": test_access_token.token,
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 200

        # Verify token is revoked
        token = AccessToken.get(AccessToken.token == test_access_token.token)
        assert token.revoked is True

    def test_revoke_refresh_token(self, client, test_client_oauth, test_refresh_token):
        """Should revoke refresh token and associated access token."""
        response = client.post(
            "/revoke",
            data={
                "token": test_refresh_token.token,
                "token_type_hint": "refresh_token",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 200

        # Verify tokens are revoked
        refresh = RefreshToken.get(RefreshToken.token == test_refresh_token.token)
        assert refresh.revoked is True
        assert refresh.access_token.revoked is True

    def test_revoke_invalid_client(self, client, test_access_token):
        """Should reject invalid client credentials."""
        response = client.post(
            "/revoke",
            data={
                "token": test_access_token.token,
                "client_id": "wrong",
                "client_secret": "wrong",
            },
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_client"

    def test_revoke_missing_token(self, client, test_client_oauth):
        """Should reject missing token."""
        response = client.post(
            "/revoke",
            data={
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_request"

    def test_revoke_nonexistent_token(self, client, test_client_oauth):
        """Should succeed for nonexistent token (RFC 7009)."""
        response = client.post(
            "/revoke",
            data={
                "token": "nonexistent-token",
                "client_id": test_client_oauth.client_id,
                "client_secret": test_client_oauth.client_secret,
            },
        )
        # Per RFC 7009, should return 200 even for invalid tokens
        assert response.status_code == 200


class TestMetadataEndpoints:
    """Tests for OAuth2 metadata endpoints."""

    def test_oauth_metadata(self, client, database):
        """Should return OAuth2 server metadata."""
        response = client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        data = response.get_json()

        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "revocation_endpoint" in data
        assert "response_types_supported" in data
        assert "code" in data["response_types_supported"]
        assert "grant_types_supported" in data
        assert "authorization_code" in data["grant_types_supported"]
        assert "client_credentials" in data["grant_types_supported"]
        assert "refresh_token" in data["grant_types_supported"]

    def test_openid_configuration(self, client, database):
        """Should return OpenID Connect discovery document."""
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        data = response.get_json()

        assert "issuer" in data
        assert "userinfo_endpoint" in data
