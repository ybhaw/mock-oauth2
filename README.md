# Mock OAuth2 Server

A lightweight mock OAuth2 server for testing OAuth2 flows in development and CI environments. Built with Flask and SQLite.

## Features

- **Authorization Code Grant** - Full OAuth2 authorization code flow with login and consent UI
- **Client Credentials Grant** - Machine-to-machine authentication
- **Refresh Token Grant** - Token refresh support
- **Token Revocation** - Revoke access and refresh tokens
- **OpenID Connect Discovery** - Standard `.well-known` endpoints
- **Swagger UI** - Interactive API documentation at `/swagger`
- **SQLite Persistence** - Data persists across restarts
- **Docker Support** - Ready-to-use Docker image

## Quick Start

### Local Development

```bash
# Clone and setup
git clone <repository-url>
cd mockOAuth2

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run the server
python run.py
```

Server starts at http://localhost:8083

### Docker

```bash
# Start with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Test Credentials

Created automatically on startup:

| Type | Value |
|------|-------|
| **Username** | `testuser` |
| **Password** | `testpass` |
| **Client ID** | `test-client` |
| **Client Secret** | `test-secret` |
| **Redirect URIs** | `http://localhost:8080/callback`, `http://localhost:3000/callback` |
| **Allowed Scopes** | `openid`, `profile`, `email`, `read`, `write` |

## OAuth2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET/POST | Authorization endpoint with login/consent UI |
| `/token` | POST | Token endpoint |
| `/revoke` | POST | Token revocation |
| `/user/userinfo` | GET | Protected userinfo resource |
| `/.well-known/oauth-authorization-server` | GET | OAuth2 server metadata |
| `/.well-known/openid-configuration` | GET | OpenID Connect discovery |
| `/swagger` | GET | Interactive API documentation |

## Usage Examples

### Authorization Code Flow

1. Redirect user to authorization endpoint:
```
GET /authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=xyz
```

2. User logs in and consents

3. Exchange code for tokens:
```bash
curl -X POST http://localhost:8083/token \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret"
```

### Client Credentials Flow

```bash
curl -X POST http://localhost:8083/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret" \
  -d "scope=read write"
```

### Refresh Token

```bash
curl -X POST http://localhost:8083/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<refresh_token>" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret"
```

### Token Revocation

```bash
curl -X POST http://localhost:8083/revoke \
  -d "token=<access_token>" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret"
```

### Access Protected Resource

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8083/user/userinfo
```

## Configuration

Environment variables (can be set in `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `8083` | Server port |
| `DEBUG` | `true` | Enable debug mode |
| `SECRET_KEY` | Auto-generated | Flask secret key |
| `DATABASE_PATH` | `oauth2.db` | SQLite database path |
| `ACCESS_TOKEN_EXPIRES_IN` | `3600` | Access token lifetime (seconds) |
| `REFRESH_TOKEN_EXPIRES_IN` | `2592000` | Refresh token lifetime (seconds) |
| `AUTHORIZATION_CODE_EXPIRES_IN` | `600` | Auth code lifetime (seconds) |
| `TEST_USER_USERNAME` | `testuser` | Test user username |
| `TEST_USER_PASSWORD` | `testpass` | Test user password |
| `TEST_CLIENT_ID` | `test-client` | Test client ID |
| `TEST_CLIENT_SECRET` | `test-secret` | Test client secret |

## Project Structure

```
mockOAuth2/
├── run.py                 # Entry point (Waitress server)
├── pyproject.toml         # Project configuration
├── Dockerfile             # Container image
├── docker-compose.yml     # Docker compose setup
└── src/
    ├── server.py          # Flask app initialization
    ├── config.py          # Configuration management
    ├── models.py          # Database models (Peewee ORM)
    ├── dto.py             # Data transfer objects
    ├── controllers/
    │   ├── oauth_controller.py   # OAuth2 endpoints
    │   ├── user_controller.py    # User management
    │   ├── client_controller.py  # Client registration
    │   └── admin_controller.py   # Admin endpoints
    └── templates/         # Jinja2 templates
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src/ tests/
isort src/ tests/

# Lint
ruff check src/ tests/

# Run pre-commit hooks
pre-commit run --all-files
```

## License

MIT License - see [LICENSE](LICENSE) for details.
