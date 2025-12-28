"""Unit tests for src/controllers/user_controller.py"""

from src.models import AccessToken, User


class TestLoginEndpoint:
    """Tests for /user/login endpoint."""

    def test_login_page_renders(self, client, database):
        """Should render login page on GET."""
        response = client.get("/user/login")
        assert response.status_code == 200
        assert b"login" in response.data.lower() or b"username" in response.data.lower()

    def test_login_success(self, client, test_user):
        """Should log in user with valid credentials."""
        response = client.post(
            "/user/login",
            data={"username": "fixture_testuser", "password": "testpass"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        # Should redirect to dashboard
        assert response.location == "/" or "dashboard" in response.location.lower()

    def test_login_sets_session(self, client, test_user):
        """Should set user_id in session on successful login."""
        client.post(
            "/user/login",
            data={"username": "fixture_testuser", "password": "testpass"},
        )
        with client.session_transaction() as sess:
            assert "user_id" in sess
            assert sess["user_id"] == test_user.id

    def test_login_invalid_username(self, client, test_user):
        """Should reject invalid username."""
        response = client.post(
            "/user/login",
            data={"username": "wronguser", "password": "testpass"},
        )
        assert response.status_code == 200
        assert b"invalid" in response.data.lower()

    def test_login_invalid_password(self, client, test_user):
        """Should reject invalid password."""
        response = client.post(
            "/user/login",
            data={"username": "testuser", "password": "wrongpass"},
        )
        assert response.status_code == 200
        assert b"invalid" in response.data.lower()

    def test_login_redirects_to_next(self, client, test_user):
        """Should redirect to 'next' URL after login."""
        response = client.post(
            "/user/login?next=/authorize",
            data={"username": "fixture_testuser", "password": "testpass"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/authorize" in response.location


class TestLogoutEndpoint:
    """Tests for /user/logout endpoint."""

    def test_logout_clears_session(self, authenticated_client):
        """Should clear user_id from session."""
        authenticated_client.get("/user/logout")
        with authenticated_client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_logout_redirects_to_dashboard(self, authenticated_client):
        """Should redirect to dashboard after logout."""
        response = authenticated_client.get("/user/logout", follow_redirects=False)
        assert response.status_code == 302


class TestRegisterEndpoint:
    """Tests for /user/register endpoint."""

    def test_register_page_renders(self, client, database):
        """Should render registration page on GET."""
        response = client.get("/user/register")
        assert response.status_code == 200

    def test_register_success(self, client, database):
        """Should register new user successfully."""
        response = client.post(
            "/user/register",
            data={"username": "newuser", "password": "newpass"},
            follow_redirects=False,
        )
        assert response.status_code == 302

        # Verify user was created
        user = User.get(User.username == "newuser")
        assert user is not None
        assert user.check_password("newpass")

    def test_register_sets_session(self, client, database):
        """Should set user_id in session after registration."""
        client.post(
            "/user/register",
            data={"username": "newuser2", "password": "newpass"},
        )
        with client.session_transaction() as sess:
            assert "user_id" in sess

    def test_register_missing_username(self, client, database):
        """Should reject missing username."""
        response = client.post(
            "/user/register",
            data={"password": "newpass"},
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_register_missing_password(self, client, database):
        """Should reject missing password."""
        response = client.post(
            "/user/register",
            data={"username": "newuser"},
        )
        assert response.status_code == 200
        assert b"required" in response.data.lower()

    def test_register_duplicate_username(self, client, test_user):
        """Should reject duplicate username."""
        response = client.post(
            "/user/register",
            data={"username": "fixture_testuser", "password": "anotherpass"},
        )
        assert response.status_code == 200
        assert b"exists" in response.data.lower()


class TestUserInfoEndpoint:
    """Tests for /user/userinfo endpoint."""

    def test_userinfo_requires_auth(self, client, database):
        """Should reject request without Bearer token."""
        response = client.get("/user/userinfo")
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_token"

    def test_userinfo_rejects_invalid_token(self, client, database):
        """Should reject invalid Bearer token."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_token"

    def test_userinfo_rejects_expired_token(self, client, expired_access_token):
        """Should reject expired token."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {expired_access_token.token}"},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_token"

    def test_userinfo_rejects_revoked_token(self, client, revoked_access_token):
        """Should reject revoked token."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {revoked_access_token.token}"},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_token"

    def test_userinfo_returns_sub(self, client, test_access_token, test_user):
        """Should return user sub (ID) for valid token."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {test_access_token.token}"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "sub" in data
        assert data["sub"] == str(test_user.id)

    def test_userinfo_returns_profile_with_scope(
        self, client, test_user, test_client_oauth, database
    ):
        """Should return username when profile scope is present."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            user=test_user,
            scopes="openid profile",
        )
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {token.token}"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "preferred_username" in data
        assert data["preferred_username"] == test_user.username

    def test_userinfo_returns_email_with_scope(
        self, client, test_user, test_client_oauth, database
    ):
        """Should return email when email scope is present."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            user=test_user,
            scopes="openid email",
        )
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {token.token}"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "email" in data
        assert "email_verified" in data
        assert data["email_verified"] is True

    def test_userinfo_without_profile_scope(
        self, client, test_user, test_client_oauth, database
    ):
        """Should not return username without profile scope."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            user=test_user,
            scopes="openid",
        )
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {token.token}"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "preferred_username" not in data

    def test_userinfo_rejects_client_credentials_token(
        self, client, test_client_oauth, database
    ):
        """Should reject token without user (client credentials flow)."""
        token = AccessToken.create_token(
            client=test_client_oauth,
            user=None,
            scopes="openid profile",
        )
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {token.token}"},
        )
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "invalid_token"

    def test_userinfo_rejects_non_bearer_auth(self, client, test_access_token):
        """Should reject non-Bearer authorization."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Basic {test_access_token.token}"},
        )
        assert response.status_code == 401


class TestRequireAuthDecorator:
    """Tests for require_auth decorator."""

    def test_require_auth_with_valid_token(self, client, test_access_token):
        """Should allow request with valid token."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": f"Bearer {test_access_token.token}"},
        )
        assert response.status_code == 200

    def test_require_auth_without_header(self, client, database):
        """Should reject request without Authorization header."""
        response = client.get("/user/userinfo")
        assert response.status_code == 401

    def test_require_auth_with_empty_header(self, client, database):
        """Should reject request with empty Authorization header."""
        response = client.get(
            "/user/userinfo",
            headers={"Authorization": ""},
        )
        assert response.status_code == 401
