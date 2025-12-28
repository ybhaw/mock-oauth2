"""Unit tests for src/controllers/admin_controller.py"""

from datetime import datetime, timedelta, timezone

import pytest

from src.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    RefreshToken,
    User,
)


class TestClientManagementRoutes:
    """Tests for admin client management endpoints."""

    def test_list_clients_renders(self, client, database):
        """Should render clients list page."""
        response = client.get("/admin/clients")
        assert response.status_code == 200

    def test_list_clients_shows_all_clients(self, client, test_client_oauth):
        """Should list all registered clients."""
        response = client.get("/admin/clients")
        assert response.status_code == 200
        # Page should contain client info
        assert test_client_oauth.name.encode() in response.data

    def test_create_client_success(self, client, database):
        """Should create a new client."""
        response = client.post(
            "/admin/clients",
            data={
                "name": "Admin Created App",
                "redirect_uris": "http://admin.com/cb",
                "scopes": "openid profile",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        assert "client_id" in data
        assert "client_secret" in data
        assert data["name"] == "Admin Created App"

    def test_create_client_missing_name(self, client, database):
        """Should reject client creation without name."""
        response = client.post(
            "/admin/clients",
            data={
                "redirect_uris": "http://admin.com/cb",
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_update_client_success(self, client, test_client_oauth):
        """Should update client details."""
        response = client.put(
            f"/admin/clients/{test_client_oauth.id}",
            json={
                "name": "Updated Name",
                "redirect_uris": "http://updated.com/cb",
                "allowed_scopes": "openid",
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify in database
        updated = Client.get_by_id(test_client_oauth.id)
        assert updated.name == "Updated Name"
        assert updated.redirect_uris == "http://updated.com/cb"
        assert updated.allowed_scopes == "openid"

    def test_update_client_partial(self, client, test_client_oauth):
        """Should allow partial update of client."""
        original_redirect = test_client_oauth.redirect_uris

        response = client.put(
            f"/admin/clients/{test_client_oauth.id}",
            json={"name": "Only Name Changed"},
        )
        assert response.status_code == 200

        updated = Client.get_by_id(test_client_oauth.id)
        assert updated.name == "Only Name Changed"
        assert updated.redirect_uris == original_redirect

    def test_update_client_not_found(self, client, database):
        """Should return 404 for non-existent client."""
        response = client.put(
            "/admin/clients/99999",
            json={"name": "Not Found"},
        )
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_delete_client_success(self, client, test_client_oauth):
        """Should delete client."""
        client_id = test_client_oauth.id

        response = client.delete(f"/admin/clients/{client_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify deleted
        with pytest.raises(Client.DoesNotExist):
            Client.get_by_id(client_id)

    def test_delete_client_cascades_tokens(
        self, client, test_client_oauth, test_access_token, test_auth_code
    ):
        """Should delete associated tokens when deleting client."""
        client_id = test_client_oauth.id
        token_id = test_access_token.id
        code_id = test_auth_code.id

        response = client.delete(f"/admin/clients/{client_id}")
        assert response.status_code == 200

        # Verify tokens deleted
        assert AccessToken.select().where(AccessToken.id == token_id).count() == 0
        assert (
            AuthorizationCode.select().where(AuthorizationCode.id == code_id).count()
            == 0
        )

    def test_delete_client_not_found(self, client, database):
        """Should return 404 for non-existent client."""
        response = client.delete("/admin/clients/99999")
        assert response.status_code == 404


class TestUserManagementRoutes:
    """Tests for admin user management endpoints."""

    def test_list_users_renders(self, client, database):
        """Should render users list page."""
        response = client.get("/admin/users")
        assert response.status_code == 200

    def test_list_users_shows_all_users(self, client, test_user):
        """Should list all registered users."""
        response = client.get("/admin/users")
        assert response.status_code == 200
        assert test_user.username.encode() in response.data

    def test_create_user_success(self, client, database):
        """Should create a new user."""
        response = client.post(
            "/admin/users",
            data={
                "username": "adminuser",
                "password": "adminpass",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        assert "id" in data
        assert data["username"] == "adminuser"

        # Verify in database
        user = User.get(User.username == "adminuser")
        assert user.check_password("adminpass")

    def test_create_user_missing_username(self, client, database):
        """Should reject user creation without username."""
        response = client.post(
            "/admin/users",
            data={"password": "pass"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_create_user_missing_password(self, client, database):
        """Should reject user creation without password."""
        response = client.post(
            "/admin/users",
            data={"username": "nopass"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_create_user_duplicate_username(self, client, test_user):
        """Should reject duplicate username."""
        response = client.post(
            "/admin/users",
            data={
                "username": test_user.username,
                "password": "newpass",
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "exists" in data["error"].lower()

    def test_delete_user_success(self, client, test_user):
        """Should delete user."""
        user_id = test_user.id

        response = client.delete(f"/admin/users/{user_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify deleted
        with pytest.raises(User.DoesNotExist):
            User.get_by_id(user_id)

    def test_delete_user_cascades_tokens(
        self, client, test_user, test_access_token, test_auth_code
    ):
        """Should delete associated tokens when deleting user."""
        user_id = test_user.id
        token_id = test_access_token.id
        code_id = test_auth_code.id

        response = client.delete(f"/admin/users/{user_id}")
        assert response.status_code == 200

        # Verify tokens deleted
        assert AccessToken.select().where(AccessToken.id == token_id).count() == 0
        assert (
            AuthorizationCode.select().where(AuthorizationCode.id == code_id).count()
            == 0
        )

    def test_delete_user_not_found(self, client, database):
        """Should return 404 for non-existent user."""
        response = client.delete("/admin/users/99999")
        assert response.status_code == 404

    def test_reset_password_success(self, client, test_user):
        """Should reset user password."""
        response = client.put(
            f"/admin/users/{test_user.id}/password",
            json={"password": "newpassword"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify new password works
        user = User.get_by_id(test_user.id)
        assert user.check_password("newpassword")
        assert not user.check_password("testpass")

    def test_reset_password_missing_password(self, client, test_user):
        """Should reject password reset without password."""
        response = client.put(
            f"/admin/users/{test_user.id}/password",
            json={},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_reset_password_not_found(self, client, database):
        """Should return 404 for non-existent user."""
        response = client.put(
            "/admin/users/99999/password",
            json={"password": "newpass"},
        )
        assert response.status_code == 404


class TestAuthManagementRoutes:
    """Tests for admin auth/token management endpoints."""

    def test_auth_page_renders(self, client, database):
        """Should render auth management page."""
        response = client.get("/admin/auth")
        assert response.status_code == 200

    def test_auth_page_shows_tokens(
        self, client, test_access_token, test_refresh_token, test_auth_code
    ):
        """Should display tokens and codes."""
        response = client.get("/admin/auth")
        assert response.status_code == 200
        # Page should render without errors

    def test_revoke_access_token_success(self, client, test_access_token):
        """Should revoke specific access token."""
        response = client.delete(f"/admin/auth/access-tokens/{test_access_token.id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify revoked
        token = AccessToken.get_by_id(test_access_token.id)
        assert token.revoked is True

    def test_revoke_access_token_not_found(self, client, database):
        """Should return 404 for non-existent token."""
        response = client.delete("/admin/auth/access-tokens/99999")
        assert response.status_code == 404

    def test_revoke_refresh_token_success(self, client, test_refresh_token):
        """Should revoke specific refresh token."""
        response = client.delete(f"/admin/auth/refresh-tokens/{test_refresh_token.id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify revoked
        token = RefreshToken.get_by_id(test_refresh_token.id)
        assert token.revoked is True

    def test_revoke_refresh_token_not_found(self, client, database):
        """Should return 404 for non-existent token."""
        response = client.delete("/admin/auth/refresh-tokens/99999")
        assert response.status_code == 404

    def test_revoke_expired_tokens(
        self, client, test_client_oauth, test_user, database
    ):
        """Should revoke all expired tokens."""
        # Create expired tokens
        AccessToken.create(
            token="expired-1",
            client=test_client_oauth,
            user=test_user,
            scopes="openid",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        AccessToken.create(
            token="valid-1",
            client=test_client_oauth,
            user=test_user,
            scopes="openid",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        response = client.post("/admin/auth/revoke-expired")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify only expired was revoked
        expired = AccessToken.get(AccessToken.token == "expired-1")
        valid = AccessToken.get(AccessToken.token == "valid-1")
        assert expired.revoked is True
        assert valid.revoked is False

    def test_revoke_all_tokens(self, client, test_access_token, test_refresh_token):
        """Should revoke all tokens."""
        response = client.post("/admin/auth/revoke-all")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        # Verify all revoked
        access = AccessToken.get_by_id(test_access_token.id)
        refresh = RefreshToken.get_by_id(test_refresh_token.id)
        assert access.revoked is True
        assert refresh.revoked is True


class TestAdminGetCurrentUser:
    """Tests for admin controller's get_current_user function."""

    def test_get_current_user_from_session(self, authenticated_client, test_user):
        """Should retrieve user from session."""
        from src.server import app

        with app.test_request_context():
            from flask import session

            session["user_id"] = test_user.id
            from src.controllers.admin_controller import get_current_user

            user = get_current_user()
            assert user is not None
            assert user.id == test_user.id

    def test_get_current_user_no_session(self, client, database):
        """Should return None when no user in session."""
        from src.server import app

        with app.test_request_context():
            from src.controllers.admin_controller import get_current_user

            user = get_current_user()
            assert user is None

    def test_get_current_user_invalid_id(self, client, database):
        """Should return None and clear session for invalid user ID."""
        from src.server import app

        with app.test_request_context():
            from flask import session

            session["user_id"] = 99999
            from src.controllers.admin_controller import get_current_user

            user = get_current_user()
            assert user is None
            assert "user_id" not in session
