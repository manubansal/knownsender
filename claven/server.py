"""
Claven web server — thin HTTP entry point over claven/core/.

Endpoints implemented here so far:
  GET  /healthz              — liveness probe for Cloud Run
  POST /webhook/gmail        — Pub/Sub push handler (incoming Gmail notifications)
  POST /internal/poll        — Cloud Scheduler trigger: poll Gmail history for all users
  POST /internal/pull        — Cloud Scheduler trigger: drain Pub/Sub pull subscription
  POST /internal/renew-watches — Cloud Scheduler trigger: renew expiring watch subscriptions
  GET  /oauth/start          — begin OAuth flow
  GET  /oauth/callback       — exchange OAuth code for tokens
"""

from fastapi import FastAPI

app = FastAPI(title="Claven")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
