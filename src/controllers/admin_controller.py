import secrets
from datetime import UTC, datetime

from flask import Blueprint, jsonify, render_template, request, session

from src.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    RefreshToken,
    User,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def get_current_user() -> User | None:
    """Get the currently logged-in user from session."""
    user_id = session.get("user_id")
    if user_id:
        try:
            return User.get_by_id(user_id)
        except User.DoesNotExist:
            session.pop("user_id", None)
    return None


# Client Management Routes


@admin_bp.route("/clients")
def clients():
    """Client management page.
    ---
    tags:
      - Admin
    responses:
      200:
        description: HTML page listing all registered clients
    """
    clients = Client.select()
    return render_template("clients.html", clients=clients)


@admin_bp.route("/clients", methods=["POST"])
def create_client():
    """Create a new OAuth2 client.
    ---
    tags:
      - Admin
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: name
        in: formData
        type: string
        required: true
        description: Client application name
      - name: redirect_uris
        in: formData
        type: string
        required: false
        description: Comma-separated list of redirect URIs
      - name: scopes
        in: formData
        type: string
        required: false
        default: "openid profile email"
        description: Space-separated allowed scopes
    responses:
      200:
        description: Client created successfully
        schema:
          type: object
          properties:
            client_id:
              type: string
            client_secret:
              type: string
            name:
              type: string
      400:
        description: Name is required
    """
    name = request.form.get("name")
    redirect_uris = request.form.get("redirect_uris", "")
    scopes = request.form.get("scopes", "openid profile email")

    if not name:
        return jsonify({"error": "Name is required"}), 400

    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)

    Client.create(
        client_id=client_id,
        client_secret=client_secret,
        name=name,
        redirect_uris=redirect_uris,
        allowed_scopes=scopes,
    )

    return jsonify(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name,
        }
    )


@admin_bp.route("/clients/<int:client_id>", methods=["PUT"])
def update_client(client_id: int):
    """Update an existing client.
    ---
    tags:
      - Admin
    consumes:
      - application/json
    parameters:
      - name: client_id
        in: path
        type: integer
        required: true
        description: Client database ID
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            redirect_uris:
              type: string
            allowed_scopes:
              type: string
    responses:
      200:
        description: Client updated successfully
      404:
        description: Client not found
    """
    try:
        client = Client.get_by_id(client_id)
    except Client.DoesNotExist:
        return jsonify({"error": "Client not found"}), 404

    data = request.get_json()
    if "name" in data:
        client.name = data["name"]
    if "redirect_uris" in data:
        client.redirect_uris = data["redirect_uris"]
    if "allowed_scopes" in data:
        client.allowed_scopes = data["allowed_scopes"]

    client.save()
    return jsonify({"success": True})


@admin_bp.route("/clients/<int:client_id>", methods=["DELETE"])
def delete_client(client_id: int):
    """Delete a client.
    ---
    tags:
      - Admin
    parameters:
      - name: client_id
        in: path
        type: integer
        required: true
        description: Client database ID
    responses:
      200:
        description: Client deleted successfully
      404:
        description: Client not found
    """
    try:
        client = Client.get_by_id(client_id)
    except Client.DoesNotExist:
        return jsonify({"error": "Client not found"}), 404

    # Delete associated tokens and codes
    AccessToken.delete().where(AccessToken.client == client).execute()
    AuthorizationCode.delete().where(AuthorizationCode.client == client).execute()
    client.delete_instance()

    return jsonify({"success": True})


# User Management Routes


@admin_bp.route("/users")
def users():
    """User management page.
    ---
    tags:
      - Admin
    responses:
      200:
        description: HTML page listing all users
    """
    users = User.select()
    return render_template("users.html", users=users)


@admin_bp.route("/users", methods=["POST"])
def create_user():
    """Create a new user.
    ---
    tags:
      - Admin
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: username
        in: formData
        type: string
        required: true
        description: Username
      - name: password
        in: formData
        type: string
        required: true
        description: Password
    responses:
      200:
        description: User created successfully
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
      400:
        description: Invalid request or username already exists
    """
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        User.get(User.username == username)
        return jsonify({"error": "Username already exists"}), 400
    except User.DoesNotExist:
        pass

    user = User(username=username)
    user.set_password(password)
    user.save()

    return jsonify({"id": user.id, "username": user.username})


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id: int):
    """Delete a user.
    ---
    tags:
      - Admin
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: User database ID
    responses:
      200:
        description: User deleted successfully
      404:
        description: User not found
    """
    try:
        user = User.get_by_id(user_id)
    except User.DoesNotExist:
        return jsonify({"error": "User not found"}), 404

    # Delete associated tokens and codes
    AccessToken.delete().where(AccessToken.user == user).execute()
    AuthorizationCode.delete().where(AuthorizationCode.user == user).execute()
    user.delete_instance()

    return jsonify({"success": True})


@admin_bp.route("/users/<int:user_id>/password", methods=["PUT"])
def reset_password(user_id: int):
    """Reset a user's password.
    ---
    tags:
      - Admin
    consumes:
      - application/json
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: User database ID
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - password
          properties:
            password:
              type: string
    responses:
      200:
        description: Password reset successfully
      400:
        description: Password is required
      404:
        description: User not found
    """
    try:
        user = User.get_by_id(user_id)
    except User.DoesNotExist:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    password = data.get("password")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    user.set_password(password)
    user.save()

    return jsonify({"success": True})


# Auth Management Routes


@admin_bp.route("/auth")
def auth():
    """Auth management page - view tokens and codes.
    ---
    tags:
      - Admin
    responses:
      200:
        description: HTML page showing all tokens and authorization codes
    """
    access_tokens = AccessToken.select().order_by(AccessToken.created_at.desc())
    refresh_tokens = RefreshToken.select().order_by(RefreshToken.created_at.desc())
    auth_codes = AuthorizationCode.select().order_by(
        AuthorizationCode.created_at.desc()
    )

    return render_template(
        "auth.html",
        access_tokens=access_tokens,
        refresh_tokens=refresh_tokens,
        auth_codes=auth_codes,
    )


@admin_bp.route("/auth/access-tokens/<int:token_id>", methods=["DELETE"])
def revoke_access_token(token_id: int):
    """Revoke an access token.
    ---
    tags:
      - Admin
    parameters:
      - name: token_id
        in: path
        type: integer
        required: true
        description: Access token database ID
    responses:
      200:
        description: Token revoked successfully
      404:
        description: Token not found
    """
    try:
        token = AccessToken.get_by_id(token_id)
    except AccessToken.DoesNotExist:
        return jsonify({"error": "Token not found"}), 404

    token.revoked = True
    token.save()

    return jsonify({"success": True})


@admin_bp.route("/auth/refresh-tokens/<int:token_id>", methods=["DELETE"])
def revoke_refresh_token(token_id: int):
    """Revoke a refresh token.
    ---
    tags:
      - Admin
    parameters:
      - name: token_id
        in: path
        type: integer
        required: true
        description: Refresh token database ID
    responses:
      200:
        description: Token revoked successfully
      404:
        description: Token not found
    """
    try:
        token = RefreshToken.get_by_id(token_id)
    except RefreshToken.DoesNotExist:
        return jsonify({"error": "Token not found"}), 404

    token.revoked = True
    token.save()

    return jsonify({"success": True})


@admin_bp.route("/auth/revoke-expired", methods=["POST"])
def revoke_expired():
    """Revoke all expired tokens.
    ---
    tags:
      - Admin
    responses:
      200:
        description: All expired tokens revoked
    """
    now = datetime.now(UTC)

    # Revoke expired access tokens
    AccessToken.update(revoked=True).where(
        (AccessToken.expires_at < now) & (AccessToken.revoked == False)  # noqa: E712
    ).execute()

    # Revoke expired refresh tokens
    RefreshToken.update(revoked=True).where(
        (RefreshToken.expires_at < now) & (RefreshToken.revoked == False)  # noqa: E712
    ).execute()

    return jsonify({"success": True})


@admin_bp.route("/auth/revoke-all", methods=["POST"])
def revoke_all():
    """Revoke all tokens.
    ---
    tags:
      - Admin
    responses:
      200:
        description: All tokens revoked
    """
    AccessToken.update(revoked=True).execute()
    RefreshToken.update(revoked=True).execute()

    return jsonify({"success": True})
