FROM python:3.11-slim

WORKDIR /app

# Install dependencies first — separate layer so rebuilds are fast when only code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as non-root
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Cloud Run sets PORT; default to 8080
ENV PORT=8080
EXPOSE 8080

# Single worker — Cloud Run scales horizontally via multiple container instances
CMD exec uvicorn claven.server:app --host 0.0.0.0 --port "$PORT" --workers 1
