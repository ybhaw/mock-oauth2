# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mock OAuth2 server for testing OAuth2 flows. Supports Authorization Code and Client Credentials grants with SQLite persistence.

## Development Commands

```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -e .

# Run the server (port 8083)
python run.py

# Docker
docker-compose up -d        # Start server in background
docker-compose down         # Stop server
docker-compose logs -f      # View logs
```

## Architecture

```
run.py              # Entry point
Dockerfile          # Container image definition
docker-compose.yml  # Local development with Docker
src/
  server.py         # Flask app with all OAuth2 endpoints
  models.py         # Peewee ORM models (User, Client, tokens)
  templates/        # Jinja2 templates (login, consent, home)
tests/              # Test directory (to be added)
```

## OAuth2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET/POST | Authorization endpoint with login/consent UI |
| `/token` | POST | Token endpoint (authorization_code, client_credentials, refresh_token) |
| `/revoke` | POST | Token revocation |
| `/userinfo` | GET | Protected resource (requires Bearer token) |
| `/.well-known/oauth-authorization-server` | GET | Server metadata |

## Test Credentials

Created automatically on startup:
- **User:** `testuser` / `testpass`
- **Client:** `test-client` / `test-secret`
- **Redirect URIs:** `http://localhost:8080/callback`, `http://localhost:3000/callback`

## Database Models

- `User` - username, password_hash
- `Client` - client_id, client_secret, redirect_uris, allowed_scopes
- `AuthorizationCode` - code, client, user, expires_at (10 min)
- `AccessToken` - token, client, user, expires_at (1 hour)
- `RefreshToken` - token, access_token, expires_at (30 days)

## Testing OAuth2 Flows

**Authorization Code:**
```
GET /authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=xyz
```

**Client Credentials:**
```bash
curl -X POST http://localhost:8083/token \
  -d "grant_type=client_credentials&client_id=test-client&client_secret=test-secret"
```
