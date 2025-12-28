FROM python:3.14-slim

WORKDIR /app

# Create and activate virtual environment
RUN python -m venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application code
COPY src/ src/
COPY run.py .

# Create data directory for SQLite
RUN mkdir -p /data

# Expose port
EXPOSE 8083

# Environment variables
ENV DATABASE_PATH=/data/oauth2.db
ENV DEBUG=false
ENV HOST=0.0.0.0

CMD ["python", "run.py"]
