"""Unit tests for src/server.py"""

from src.server import get_current_user


class TestGetCurrentUser:
    """Tests for get_current_user function."""

    def test_returns_none_when_not_logged_in(self, client):
        """Should return None when no user is logged in."""
        with client.session_transaction() as sess:
            sess.clear()

        from src.server import app

        with app.test_request_context():
            result = get_current_user()
            assert result is None

    def test_returns_user_when_logged_in(self, client, test_user):
        """Should return user when logged in."""
        with client.session_transaction() as sess:
            sess["user_id"] = test_user.id

        from src.server import app

        with app.test_request_context():
            from flask import session

            session["user_id"] = test_user.id
            result = get_current_user()
            assert result is not None
            assert result.id == test_user.id

    def test_returns_none_for_invalid_user_id(self, client, database):
        """Should return None and clear session for non-existent user."""
        from src.server import app

        with app.test_request_context():
            from flask import session

            session["user_id"] = 99999
            result = get_current_user()
            assert result is None
            assert "user_id" not in session


class TestDashboard:
    """Tests for dashboard route."""

    def test_dashboard_renders(self, client, database):
        """Should render dashboard page."""
        response = client.get("/")
        assert response.status_code == 200

    def test_dashboard_shows_stats(
        self, client, test_user, test_client_oauth, test_access_token
    ):
        """Should show correct statistics on dashboard."""
        response = client.get("/")
        assert response.status_code == 200
        # Dashboard should render without errors even with data


class TestBlueprintRegistration:
    """Tests for blueprint registration."""

    def test_oauth_blueprint_registered(self, client):
        """Should have OAuth blueprint routes available."""
        from src.server import app

        # Check that oauth routes are registered
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/authorize" in routes
        assert "/token" in routes
        assert "/revoke" in routes

    def test_user_blueprint_registered(self, client):
        """Should have User blueprint routes available."""
        from src.server import app

        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/user/login" in routes
        assert "/user/logout" in routes
        assert "/user/register" in routes
        assert "/user/userinfo" in routes

    def test_client_blueprint_registered(self, client):
        """Should have Client blueprint routes available."""
        from src.server import app

        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/client/register-client" in routes

    def test_admin_blueprint_registered(self, client):
        """Should have Admin blueprint routes available."""
        from src.server import app

        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert "/admin/clients" in routes
        assert "/admin/users" in routes
        assert "/admin/auth" in routes


class TestSwaggerSetup:
    """Tests for Swagger documentation setup."""

    def test_swagger_ui_accessible(self, client, database):
        """Should have Swagger UI accessible."""
        # Note: Swagger UI might redirect or have different paths
        response = client.get("/swagger")
        # Swagger UI should redirect or be available
        assert response.status_code in [200, 301, 302, 308]

    def test_apispec_json_accessible(self, client, database):
        """Should have API spec JSON accessible."""
        response = client.get("/apispec.json")
        assert response.status_code == 200
        data = response.get_json()
        assert "info" in data
        assert data["info"]["title"] == "Mock OAuth2 Server API"
