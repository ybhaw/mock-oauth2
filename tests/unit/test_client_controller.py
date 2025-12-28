"""Unit tests for src/controllers/client_controller.py"""

from src.models import Client


class TestRegisterClientEndpoint:
    """Tests for /client/register-client endpoint."""

    def test_register_client_success(self, client, database):
        """Should register a new client successfully."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "My New App",
                "redirect_uris": "http://myapp.com/callback",
                "scopes": "openid profile",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        assert "client_id" in data
        assert "client_secret" in data
        assert data["name"] == "My New App"
        assert len(data["client_id"]) > 0
        assert len(data["client_secret"]) > 0

    def test_register_client_creates_in_database(self, client, database):
        """Should create client record in database."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "Database Test App",
                "redirect_uris": "http://test.com/cb",
            },
        )
        data = response.get_json()

        # Verify in database
        db_client = Client.get(Client.client_id == data["client_id"])
        assert db_client is not None
        assert db_client.name == "Database Test App"
        assert db_client.client_secret == data["client_secret"]
        assert db_client.redirect_uris == "http://test.com/cb"

    def test_register_client_missing_name(self, client, database):
        """Should reject registration without name."""
        response = client.post(
            "/client/register-client",
            data={
                "redirect_uris": "http://myapp.com/callback",
            },
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_register_client_default_scopes(self, client, database):
        """Should use default scopes when not provided."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "Default Scopes App",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        # Verify default scopes in database
        db_client = Client.get(Client.client_id == data["client_id"])
        assert "openid" in db_client.allowed_scopes
        assert "profile" in db_client.allowed_scopes
        assert "email" in db_client.allowed_scopes

    def test_register_client_custom_scopes(self, client, database):
        """Should use custom scopes when provided."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "Custom Scopes App",
                "scopes": "read write admin",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        db_client = Client.get(Client.client_id == data["client_id"])
        assert db_client.allowed_scopes == "read write admin"

    def test_register_client_empty_redirect_uris(self, client, database):
        """Should allow empty redirect_uris."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "No Redirect App",
                "redirect_uris": "",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        db_client = Client.get(Client.client_id == data["client_id"])
        assert db_client.redirect_uris == ""

    def test_register_client_multiple_redirect_uris(self, client, database):
        """Should allow multiple redirect URIs."""
        response = client.post(
            "/client/register-client",
            data={
                "name": "Multi Redirect App",
                "redirect_uris": "http://localhost:8080/cb,http://localhost:3000/cb",
            },
        )
        assert response.status_code == 200
        data = response.get_json()

        db_client = Client.get(Client.client_id == data["client_id"])
        assert "http://localhost:8080/cb" in db_client.redirect_uris

    def test_register_client_unique_ids(self, client, database):
        """Should generate unique client IDs for each registration."""
        response1 = client.post(
            "/client/register-client",
            data={"name": "App 1"},
        )
        response2 = client.post(
            "/client/register-client",
            data={"name": "App 2"},
        )

        data1 = response1.get_json()
        data2 = response2.get_json()

        assert data1["client_id"] != data2["client_id"]
        assert data1["client_secret"] != data2["client_secret"]

    def test_register_client_same_name_allowed(self, client, database):
        """Should allow multiple clients with same name."""
        response1 = client.post(
            "/client/register-client",
            data={"name": "Same Name App"},
        )
        response2 = client.post(
            "/client/register-client",
            data={"name": "Same Name App"},
        )

        assert response1.status_code == 200
        assert response2.status_code == 200

        # Both should have different client IDs
        data1 = response1.get_json()
        data2 = response2.get_json()
        assert data1["client_id"] != data2["client_id"]
