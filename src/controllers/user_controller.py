from functools import wraps

from flask import (
    Blueprint,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from src.dto import ErrorResponse, UserInfoResponse
from src.models import AccessToken, User

user_bp = Blueprint("user", __name__)


def get_current_user() -> User | None:
    """Get the currently logged-in user from session."""
    user_id = session.get("user_id")
    if user_id:
        try:
            return User.get_by_id(user_id)
        except User.DoesNotExist:
            session.pop("user_id", None)
    return None


def require_auth(f):
    """Decorator to require valid access token."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(ErrorResponse(error="invalid_token")), 401

        token_value = auth_header[7:]
        try:
            token = AccessToken.get(AccessToken.token == token_value)
            if not token.is_valid():
                return jsonify(ErrorResponse(error="invalid_token")), 401
            g.oauth_token = token
        except AccessToken.DoesNotExist:
            return jsonify(ErrorResponse(error="invalid_token")), 401

        return f(*args, **kwargs)

    return decorated


@user_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login page.
    ---
    tags:
      - User
    parameters:
      - name: username
        in: formData
        type: string
        required: false
        description: Username for login (POST only)
      - name: password
        in: formData
        type: string
        required: false
        description: Password for login (POST only)
      - name: next
        in: query
        type: string
        required: false
        description: URL to redirect after successful login
    responses:
      200:
        description: Login page HTML (GET) or error page (POST with invalid credentials)
      302:
        description: Redirect to dashboard or next URL on successful login
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        try:
            user = User.get(User.username == username)
            if user.check_password(password):
                session["user_id"] = user.id
                # Redirect back to authorize if we came from there
                next_url = request.args.get("next") or url_for("dashboard")
                return redirect(next_url)
        except User.DoesNotExist:
            pass

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@user_bp.route("/logout")
def logout():
    """Log out the current user.
    ---
    tags:
      - User
    responses:
      302:
        description: Redirect to dashboard after logout
    """
    session.pop("user_id", None)
    return redirect(url_for("dashboard"))


@user_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration page.
    ---
    tags:
      - User
    parameters:
      - name: username
        in: formData
        type: string
        required: false
        description: Username for registration (POST only)
      - name: password
        in: formData
        type: string
        required: false
        description: Password for registration (POST only)
    responses:
      200:
        description: Registration page HTML (GET) or error page (POST with invalid data)
      302:
        description: Redirect to dashboard on successful registration
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template(
                "login.html", error="Username and password required", register=True
            )

        try:
            User.get(User.username == username)
            return render_template(
                "login.html", error="Username already exists", register=True
            )
        except User.DoesNotExist:
            user = User(username=username)
            user.set_password(password)
            user.save()
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))

    return render_template("login.html", register=True)


@user_bp.route("/userinfo")
@require_auth
def userinfo():
    """OpenID Connect userinfo endpoint.
    ---
    tags:
      - User
    security:
      - Bearer: []
    responses:
      200:
        description: User information based on token scopes
        schema:
          type: object
          properties:
            sub:
              type: string
              description: Subject identifier (user ID)
              example: "1"
            preferred_username:
              type: string
              description: Username (if profile scope granted)
              example: "testuser"
            email:
              type: string
              description: Email address (if email scope granted)
              example: "testuser@example.com"
            email_verified:
              type: boolean
              description: Email verification status (if email scope granted)
              example: true
      401:
        description: Invalid or missing access token
        schema:
          type: object
          properties:
            error:
              type: string
              example: "invalid_token"
    """
    token: AccessToken = g.oauth_token
    if not token.user:
        return jsonify(ErrorResponse(error="invalid_token")), 401

    scopes = token.scopes.split()
    user = token.user

    response = UserInfoResponse(sub=str(user.id))

    if "profile" in scopes:
        response["preferred_username"] = user.username

    if "email" in scopes:
        response["email"] = f"{user.username}@example.com"
        response["email_verified"] = True

    return jsonify(response)
