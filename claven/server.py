"""
Claven web server — thin HTTP entry point over claven/core/.

Endpoints:
  GET  /health                  — liveness probe for Cloud Run
  GET  /oauth/start             — begin OAuth flow, redirect to Google consent
  GET  /oauth/callback          — exchange OAuth code for tokens, store in DB
  POST /internal/poll           — Cloud Scheduler trigger: poll Gmail history for all users
  POST /webhook/gmail           — Pub/Sub push handler: incoming Gmail notifications
"""

import base64
import json
import logging
import os
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

import claven.core.auth as auth
import claven.core.db as db
from claven.core.gmail import get_profile
from claven.core.process import poll_new_messages
from claven.core.rules import load_config
from claven.core.watch import start_watch

logger = logging.getLogger(__name__)

app = FastAPI(title="Claven")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_internal_auth(request: Request) -> None:
    expected = f"Bearer {os.environ['INTERNAL_API_SECRET']}"
    if request.headers.get("Authorization") != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _verify_pubsub_token(request: Request) -> None:
    """Verify the OIDC bearer token Google attaches to Pub/Sub push deliveries.

    Rejects requests that don't carry a token signed by Google whose email
    claim identifies a Pub/Sub service account.  If PUBSUB_AUDIENCE is set,
    the token's 'aud' claim must also match — recommended in production.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Pub/Sub auth token")

    token = auth_header[len("Bearer "):]
    audience = os.environ.get("PUBSUB_AUDIENCE")  # None → skip audience check

    try:
        id_info = google_id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=audience,
        )
    except Exception as exc:
        logger.warning("Pub/Sub token verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid Pub/Sub token")

    email = id_info.get("email", "")
    if not email.endswith(".gserviceaccount.com"):
        logger.warning("Pub/Sub token email is not a GCP service account: %s", email)
        raise HTTPException(status_code=401, detail="Unexpected Pub/Sub service account")


def _make_flow() -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": os.environ["OAUTH_CLIENT_ID"],
                "client_secret": os.environ["OAUTH_CLIENT_SECRET"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [os.environ["OAUTH_REDIRECT_URI"]],
            }
        },
        scopes=SCOPES,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/oauth/start")
def oauth_start():
    flow = _make_flow()
    flow.redirect_uri = os.environ["OAUTH_REDIRECT_URI"]
    state = secrets.token_urlsafe(32)
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=state,
    )
    response = RedirectResponse(url=auth_url)
    response.set_cookie("oauth_state", state, httponly=True, max_age=600, samesite="lax", secure=True)
    return response


def _error_redirect(frontend_url: str, reason: str) -> RedirectResponse:
    response = RedirectResponse(url=f"{frontend_url}/?error={reason}", status_code=302)
    response.delete_cookie("oauth_state")
    return response


@app.get("/oauth/callback")
def oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    frontend_url = os.environ.get("FRONTEND_URL", "https://claven.app")

    if error:
        logger.warning("OAuth error from Google: %s", error)
        return _error_redirect(frontend_url, "oauth_denied")
    if not code or not state:
        return _error_redirect(frontend_url, "invalid_request")

    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        logger.warning("State mismatch: stored=%r param=%r", stored_state, state)
        return _error_redirect(frontend_url, "invalid_state")

    # State verified — delete the cookie immediately so it can't be replayed
    flow = _make_flow()
    flow.redirect_uri = os.environ["OAUTH_REDIRECT_URI"]
    try:
        flow.fetch_token(code=code)
    except Exception as exc:
        logger.warning("Token exchange failed: %s", exc)
        return _error_redirect(frontend_url, "token_exchange_failed")
    creds = flow.credentials

    try:
        id_info = google_id_token.verify_oauth2_token(
            creds.id_token,
            google_requests.Request(),
            os.environ["OAUTH_CLIENT_ID"],
        )
    except Exception as exc:
        logger.warning("ID token verification failed: %s", exc)
        return _error_redirect(frontend_url, "token_verification_failed")
    email = id_info["email"]

    try:
        with db.get_connection() as conn:
            user_id = db.upsert_user(conn, email)
            auth.store_credentials(conn, user_id, creds, os.environ["TOKEN_ENCRYPTION_KEY"])

            # Use the freshly-issued creds directly — no need to reload from DB
            service = build("gmail", "v1", credentials=creds)
            watch_response = start_watch(service, os.environ["PUBSUB_TOPIC"])
            db.set_history_id(conn, user_id, int(watch_response["historyId"]))
    except Exception as exc:
        logger.exception("Signup failed for %s: %s", email, exc)
        return _error_redirect(frontend_url, "signup_failed")

    logger.info("OAuth complete for %s (user_id=%s)", email, user_id)
    response = RedirectResponse(url=f"{frontend_url}/connected?email={email}", status_code=302)
    response.delete_cookie("oauth_state")
    return response


@app.post("/internal/poll")
def internal_poll(request: Request):
    _require_internal_auth(request)

    label_configs = load_config().get("labels", [])
    results = []

    with db.get_connection() as conn:
        users = db.get_all_users(conn)

    for user in users:
        user_id = user["id"]
        with db.get_connection() as conn:
            try:
                history_id = db.get_history_id(conn, user_id)
                if not history_id:
                    continue

                service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
                known_senders = db.get_known_senders(conn, user_id)

                profile = get_profile(service)
                latest_history_id = int(profile["historyId"])

                poll_new_messages(service, history_id, label_configs, {}, known_senders)
                db.set_history_id(conn, user_id, latest_history_id)
                results.append({"user_id": user_id, "status": "ok"})
            except Exception as exc:
                logger.exception("Error processing user %s", user_id, exc_info=exc)
                results.append({"user_id": user_id, "status": "error", "detail": str(exc)})

    return {"processed": len(results), "results": results}


@app.post("/webhook/gmail")
async def webhook_gmail(request: Request):
    _verify_pubsub_token(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    message = body.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="Missing 'message' field")

    try:
        data = base64.b64decode(message.get("data", ""))
        notification = json.loads(data)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed message data")

    email = notification.get("emailAddress")
    history_id_str = notification.get("historyId")
    if not email or not history_id_str:
        raise HTTPException(status_code=400, detail="Missing emailAddress or historyId")

    notification_history_id = int(history_id_str)
    label_configs = load_config().get("labels", [])

    with db.get_connection() as conn:
        user = db.get_user_by_email(conn, email)
        if not user:
            logger.info("Webhook for unknown user %s — acknowledging", email)
            return {"status": "ok", "detail": "unknown user"}

        stored_history_id = db.get_history_id(conn, user["id"])
        if not stored_history_id:
            logger.info("No history_id for %s — skipping", email)
            return {"status": "ok", "detail": "no history_id"}

        service = auth.get_service(conn, user["id"], os.environ["TOKEN_ENCRYPTION_KEY"])
        known_senders = db.get_known_senders(conn, user["id"])
        poll_new_messages(service, stored_history_id, label_configs, {}, known_senders)
        db.set_history_id(conn, user["id"], notification_history_id)

    return {"status": "ok"}
