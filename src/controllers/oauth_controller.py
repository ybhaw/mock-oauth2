from urllib.parse import urlencode

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from src import config
from src.dto import (
    ErrorResponse,
    OAuthMetadataResponse,
    TokenResponse,
)
from src.models import (
    AccessToken,
    AuthorizationCode,
    Client,
    RefreshToken,
    User,
)


def get_current_user() -> User | None:
    """Get the currently logged-in user from session."""
    user_id = session.get("user_id")
    if user_id:
        try:
            return User.get_by_id(user_id)
        except User.DoesNotExist:
            session.pop("user_id", None)
    return None


oauth_bp = Blueprint("oauth", __name__)


def authenticate_client():
    """Authenticate client from Basic auth or POST body."""
    auth = request.authorization
    if auth:
        client_id = auth.username
        client_secret = auth.password
    else:
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")

    if not client_id or not client_secret:
        return None

    try:
        client = Client.get(Client.client_id == client_id)
        if client.client_secret == client_secret:
            return client
    except Client.DoesNotExist:
        pass
    return None


@oauth_bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    """OAuth2 authorization endpoint.
    ---
    tags:
      - OAuth2
    parameters:
      - name: response_type
        in: query
        type: string
        required: true
        description: Must be 'code' for authorization code flow
        enum: [code]
      - name: client_id
        in: query
        type: string
        required: true
        description: The client identifier
      - name: redirect_uri
        in: query
        type: string
        required: true
        description: URI to redirect after authorization
      - name: scope
        in: query
        type: string
        required: false
        description: Space-separated list of scopes
      - name: state
        in: query
        type: string
        required: false
        description: Opaque value for CSRF protection
    responses:
      302:
        description: Redirects to login page or consent page,
                     then to redirect_uri with code
      400:
        description: Invalid request parameters
        schema:
          type: object
          properties:
            error:
              type: string
              example: invalid_client
    """
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "")
    state = request.args.get("state", "")

    if response_type != "code":
        return jsonify(ErrorResponse(error="unsupported_response_type")), 400

    try:
        client = Client.get(Client.client_id == client_id)
    except Client.DoesNotExist:
        return jsonify(ErrorResponse(error="invalid_client")), 400

    if not client.validate_redirect_uri(redirect_uri):
        return jsonify(ErrorResponse(error="invalid_redirect_uri")), 400

    session["oauth_params"] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }

    user = get_current_user()
    if not user:
        return redirect(url_for("user.login", next=request.url))

    if request.method == "POST":
        if request.form.get("approve"):
            auth_code = AuthorizationCode.create_code(
                client=client,
                user=user,
                redirect_uri=redirect_uri,
                scopes=scope,
            )
            params = {"code": auth_code.code}
            if state:
                params["state"] = state
            return redirect(f"{redirect_uri}?{urlencode(params)}")
        else:
            params = {"error": "access_denied"}
            if state:
                params["state"] = state
            return redirect(f"{redirect_uri}?{urlencode(params)}")

    scopes = scope.split() if scope else []
    return render_template(
        "consent.html",
        client=client,
        scopes=scopes,
        redirect_uri=redirect_uri,
    )


@oauth_bp.route("/token", methods=["POST"])
def token():
    """OAuth2 token endpoint.
    ---
    tags:
      - OAuth2
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: grant_type
        in: formData
        type: string
        required: true
        description: The grant type
        enum: [authorization_code, client_credentials, refresh_token]
      - name: code
        in: formData
        type: string
        required: false
        description: Authorization code (required for authorization_code grant)
      - name: redirect_uri
        in: formData
        type: string
        required: false
        description: Redirect URI (required for authorization_code grant)
      - name: client_id
        in: formData
        type: string
        required: false
        description: Client ID (if not using Basic auth)
      - name: client_secret
        in: formData
        type: string
        required: false
        description: Client secret (if not using Basic auth)
      - name: refresh_token
        in: formData
        type: string
        required: false
        description: Refresh token (required for refresh_token grant)
      - name: scope
        in: formData
        type: string
        required: false
        description: Requested scopes (for client_credentials grant)
    security:
      - BasicAuth: []
    responses:
      200:
        description: Token response
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: "eyJhbGciOiJIUzI1NiIs..."
            token_type:
              type: string
              example: "Bearer"
            expires_in:
              type: integer
              example: 3600
            refresh_token:
              type: string
            scope:
              type: string
              example: "openid profile"
      400:
        description: Invalid request
        schema:
          type: object
          properties:
            error:
              type: string
              example: "unsupported_grant_type"
      401:
        description: Invalid client credentials
    """
    grant_type = request.form.get("grant_type")

    if grant_type == "authorization_code":
        return _handle_authorization_code_grant()
    elif grant_type == "client_credentials":
        return _handle_client_credentials_grant()
    elif grant_type == "refresh_token":
        return _handle_refresh_token_grant()
    else:
        return jsonify(ErrorResponse(error="unsupported_grant_type")), 400


def _handle_authorization_code_grant():
    """Handle authorization_code grant type."""
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")

    client = authenticate_client()
    if not client:
        return jsonify(ErrorResponse(error="invalid_client")), 401

    if not code:
        return (
            jsonify(
                ErrorResponse(error="invalid_request", error_description="Missing code")
            ),
            400,
        )

    try:
        auth_code = AuthorizationCode.get(AuthorizationCode.code == code)
    except AuthorizationCode.DoesNotExist:
        return jsonify(ErrorResponse(error="invalid_grant")), 400

    if auth_code.client.id != client.id:
        return jsonify(ErrorResponse(error="invalid_grant")), 400

    if auth_code.used:
        return (
            jsonify(
                ErrorResponse(
                    error="invalid_grant", error_description="Code already used"
                )
            ),
            400,
        )

    if auth_code.is_expired():
        return (
            jsonify(
                ErrorResponse(error="invalid_grant", error_description="Code expired")
            ),
            400,
        )

    if auth_code.redirect_uri != redirect_uri:
        return (
            jsonify(
                ErrorResponse(
                    error="invalid_grant", error_description="Redirect URI mismatch"
                )
            ),
            400,
        )

    auth_code.used = True
    auth_code.save()

    access_token = AccessToken.create_token(
        client=client,
        user=auth_code.user,
        scopes=auth_code.scopes,
    )
    refresh_token = RefreshToken.create_token(access_token)

    return jsonify(
        TokenResponse(
            access_token=access_token.token,
            token_type="Bearer",
            expires_in=config.ACCESS_TOKEN_EXPIRES_IN,
            refresh_token=refresh_token.token,
            scope=auth_code.scopes,
        )
    )


def _handle_client_credentials_grant():
    """Handle client_credentials grant type."""
    client = authenticate_client()
    if not client:
        return jsonify(ErrorResponse(error="invalid_client")), 401

    scope = request.form.get("scope", client.allowed_scopes)

    if not client.validate_scopes(scope):
        return jsonify(ErrorResponse(error="invalid_scope")), 400

    access_token = AccessToken.create_token(
        client=client,
        scopes=scope,
        user=None,
    )

    return jsonify(
        TokenResponse(
            access_token=access_token.token,
            token_type="Bearer",
            expires_in=config.ACCESS_TOKEN_EXPIRES_IN,
            scope=scope,
        )
    )


def _handle_refresh_token_grant():
    """Handle refresh_token grant type."""
    refresh_token_value = request.form.get("refresh_token")

    client = authenticate_client()
    if not client:
        return jsonify(ErrorResponse(error="invalid_client")), 401

    if not refresh_token_value:
        return jsonify(ErrorResponse(error="invalid_request")), 400

    try:
        refresh_token = RefreshToken.get(RefreshToken.token == refresh_token_value)
    except RefreshToken.DoesNotExist:
        return jsonify(ErrorResponse(error="invalid_grant")), 400

    if not refresh_token.is_valid():
        return jsonify(ErrorResponse(error="invalid_grant")), 400

    old_access_token = refresh_token.access_token
    if old_access_token.client.id != client.id:
        return jsonify(ErrorResponse(error="invalid_grant")), 400

    old_access_token.revoked = True
    old_access_token.save()
    refresh_token.revoked = True
    refresh_token.save()

    new_access_token = AccessToken.create_token(
        client=client,
        user=old_access_token.user,
        scopes=old_access_token.scopes,
    )
    new_refresh_token = RefreshToken.create_token(new_access_token)

    return jsonify(
        TokenResponse(
            access_token=new_access_token.token,
            token_type="Bearer",
            expires_in=config.ACCESS_TOKEN_EXPIRES_IN,
            refresh_token=new_refresh_token.token,
            scope=old_access_token.scopes,
        )
    )


@oauth_bp.route("/revoke", methods=["POST"])
def revoke():
    """OAuth2 token revocation endpoint.
    ---
    tags:
      - OAuth2
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: token
        in: formData
        type: string
        required: true
        description: The token to revoke
      - name: token_type_hint
        in: formData
        type: string
        required: false
        description: Hint about the token type
        enum: [access_token, refresh_token]
      - name: client_id
        in: formData
        type: string
        required: false
        description: Client ID (if not using Basic auth)
      - name: client_secret
        in: formData
        type: string
        required: false
        description: Client secret (if not using Basic auth)
    security:
      - BasicAuth: []
    responses:
      200:
        description: Token revoked successfully (or token was already invalid)
      400:
        description: Invalid request
      401:
        description: Invalid client credentials
    """
    token_value = request.form.get("token")
    token_type_hint = request.form.get("token_type_hint")

    client = authenticate_client()
    if not client:
        return jsonify(ErrorResponse(error="invalid_client")), 401

    if not token_value:
        return jsonify(ErrorResponse(error="invalid_request")), 400

    if token_type_hint == "refresh_token":
        try:
            refresh_token = RefreshToken.get(RefreshToken.token == token_value)
            if refresh_token.access_token.client.id == client.id:
                refresh_token.revoked = True
                refresh_token.save()
                refresh_token.access_token.revoked = True
                refresh_token.access_token.save()
        except RefreshToken.DoesNotExist:
            pass
    else:
        try:
            access_token = AccessToken.get(AccessToken.token == token_value)
            if access_token.client.id == client.id:
                access_token.revoked = True
                access_token.save()
                for rt in access_token.refresh_tokens:
                    rt.revoked = True
                    rt.save()
        except AccessToken.DoesNotExist:
            pass

    return "", 200


@oauth_bp.route("/.well-known/oauth-authorization-server")
def oauth_metadata():
    """OAuth2 Authorization Server Metadata.
    ---
    tags:
      - OAuth2
    responses:
      200:
        description: OAuth2 server metadata
        schema:
          type: object
          properties:
            issuer:
              type: string
              example: "http://localhost:5000"
            authorization_endpoint:
              type: string
              example: "http://localhost:5000/authorize"
            token_endpoint:
              type: string
              example: "http://localhost:5000/token"
            revocation_endpoint:
              type: string
              example: "http://localhost:5000/revoke"
            userinfo_endpoint:
              type: string
              example: "http://localhost:5000/user/userinfo"
            response_types_supported:
              type: array
              items:
                type: string
              example: ["code"]
            grant_types_supported:
              type: array
              items:
                type: string
              example: ["authorization_code", "client_credentials", "refresh_token"]
    """
    base_url = request.host_url.rstrip("/")
    return jsonify(
        OAuthMetadataResponse(
            issuer=base_url,
            authorization_endpoint=f"{base_url}/authorize",
            token_endpoint=f"{base_url}/token",
            revocation_endpoint=f"{base_url}/revoke",
            userinfo_endpoint=f"{base_url}/user/userinfo",
            response_types_supported=["code"],
            grant_types_supported=[
                "authorization_code",
                "client_credentials",
                "refresh_token",
            ],
            token_endpoint_auth_methods_supported=[
                "client_secret_basic",
                "client_secret_post",
            ],
            scopes_supported=["openid", "profile", "email", "read", "write"],
        )
    )


@oauth_bp.route("/.well-known/openid-configuration")
def openid_configuration():
    """OpenID Connect Discovery document.
    ---
    tags:
      - OAuth2
    responses:
      200:
        description: OpenID Connect discovery document (same as OAuth2 metadata)
    """
    return oauth_metadata()
