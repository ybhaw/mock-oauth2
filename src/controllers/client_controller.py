import secrets

from flask import Blueprint, jsonify, request

from src.dto import ClientRegistrationResponse, ErrorResponse
from src.models import Client

client_bp = Blueprint("client", __name__)


@client_bp.route("/register-client", methods=["POST"])
def register_client():
    """Register a new OAuth2 client.
    ---
    tags:
      - Client
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: name
        in: formData
        type: string
        required: true
        description: Name of the client application
      - name: redirect_uris
        in: formData
        type: string
        required: false
        description: Comma-separated list of allowed redirect URIs
      - name: scopes
        in: formData
        type: string
        required: false
        default: "openid profile email"
        description: Space-separated list of allowed scopes
    responses:
      200:
        description: Client registered successfully
        schema:
          type: object
          properties:
            client_id:
              type: string
              example: "abc123def456"
            client_secret:
              type: string
              example: "secret789xyz"
            name:
              type: string
              example: "My App"
      400:
        description: Invalid request (name is required)
    """
    name = request.form.get("name")
    redirect_uris = request.form.get("redirect_uris", "")
    scopes = request.form.get("scopes", "openid profile email")

    if not name:
        return jsonify(ErrorResponse(error="Name is required")), 400

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
        ClientRegistrationResponse(
            client_id=client_id,
            client_secret=client_secret,
            name=name,
        )
    )
