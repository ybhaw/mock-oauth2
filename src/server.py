from datetime import UTC, datetime

from dotenv import load_dotenv
from flasgger import Swagger
from flask import Flask, render_template, session

from src import config
from src.controllers.admin_controller import admin_bp
from src.controllers.client_controller import client_bp
from src.controllers.oauth_controller import oauth_bp
from src.controllers.user_controller import user_bp
from src.models import AccessToken, Client, User, create_test_data, init_db

load_dotenv()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(client_bp, url_prefix="/client")
app.register_blueprint(user_bp, url_prefix="/user")
app.register_blueprint(oauth_bp)

# Configure Swagger
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger",
}

swagger_template = {
    "info": {
        "title": "Mock OAuth2 Server API",
        "description": "Mock OAuth2 server for testing OAuth2 flows. "
        "Supports Authorization Code and Client Credentials grants.",
        "version": "1.0.0",
        "contact": {
            "name": "API Support",
        },
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. "
            "Example: 'Bearer {token}'",
        },
        "BasicAuth": {
            "type": "basic",
            "description": "Basic authentication with client_id:client_secret",
        },
    },
    "tags": [
        {"name": "OAuth2", "description": "OAuth2 authorization and token endpoints"},
        {"name": "User", "description": "User management and authentication"},
        {"name": "Client", "description": "OAuth2 client registration"},
        {"name": "Admin", "description": "Admin management endpoints"},
    ],
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)


def get_current_user() -> User | None:
    """Get the currently logged-in user from session."""
    user_id = session.get("user_id")
    if user_id:
        try:
            return User.get_by_id(user_id)
        except User.DoesNotExist:
            session.pop("user_id", None)
    return None


@app.route("/")
def dashboard():
    """Dashboard home page."""
    user = get_current_user()
    client_count = Client.select().count()
    user_count = User.select().count()
    now = datetime.now(UTC)
    active_token_count = (
        AccessToken.select()
        .where((AccessToken.revoked is False) & (AccessToken.expires_at > now))
        .count()
    )
    return render_template(
        "dashboard.html",
        user=user,
        client_count=client_count,
        user_count=user_count,
        active_token_count=active_token_count,
    )


# Initialize database on startup
with app.app_context():
    init_db()
    create_test_data()

if __name__ == "__main__":
    app.run(host=config.HOST, debug=config.DEBUG, port=config.PORT)
