#!/usr/bin/env python
"""Entry point for running the OAuth2 server."""

from waitress import serve

from src import config
from src.server import app

if __name__ == "__main__":
    print(f"Starting OAuth2 server on http://{config.HOST}:{config.PORT}")
    serve(app, host=config.HOST, port=config.PORT)
