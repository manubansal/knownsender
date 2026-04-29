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
from urllib.parse import urlencode

import jwt as pyjwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from google_auth_oauthlib.flow import Flow
import claven.core.auth as auth
import claven.core.db as db
from claven.core.gmail import build_label_id_cache, get_profile
from claven.core.process import poll_new_messages
from claven.core.rules import load_config
from claven.core.watch import start_watch, stop_watch

logger = logging.getLogger(__name__)

app = FastAPI(title="Claven")

def _allowed_origins() -> list[str]:
    origins = [os.environ.get("FRONTEND_URL", "https://claven.app")]
    if extra := os.environ.get("CORS_EXTRA_ORIGINS", ""):
        origins += [o.strip() for o in extra.split(",") if o.strip()]
    return origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

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


def _issue_session(user_id: str, email: str) -> str:
    """Return a signed JWT encoding the user's identity.

    Accepted by all authenticated endpoints as either a 'session' cookie
    (browser) or an Authorization: Bearer token (CLI).  No expiry is set
    for now — rotate SESSION_SECRET to invalidate all sessions.
    """
    return pyjwt.encode(
        {"user_id": user_id, "email": email},
        os.environ["SESSION_SECRET"],
        algorithm="HS256",
    )


def _get_session(request: Request) -> dict:
    """Extract and verify the session JWT from cookie or Bearer header.

    Checks the 'session' cookie first (browser path), then falls back to
    the Authorization: Bearer header (CLI path).  Raises 401 if missing
    or invalid so callers can treat the result as trusted.
    """
    token = request.cookies.get("session")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return pyjwt.decode(token, os.environ["SESSION_SECRET"], algorithms=["HS256"])
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid session")


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
def oauth_start(return_to: str | None = None, force_consent: bool = False):
    if return_to and return_to not in _allowed_origins():
        raise HTTPException(status_code=400, detail="Invalid return_to")
    flow = _make_flow()
    flow.redirect_uri = os.environ["OAUTH_REDIRECT_URI"]
    state = secrets.token_urlsafe(32)
    # Use consent prompt only when forced (e.g. reconnecting after disconnect
    # where Google won't return a refresh token without explicit re-consent).
    prompt = "consent" if force_consent else "select_account"
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt=prompt,
        state=state,
    )
    response = RedirectResponse(url=auth_url)
    response.set_cookie("oauth_state", state, httponly=True, max_age=600, samesite="lax", secure=True)
    if return_to:
        response.set_cookie("oauth_return_to", return_to, httponly=True, max_age=600, samesite="lax", secure=True)
    return response


def _redirect_base(request: Request) -> str:
    """Return the frontend origin to redirect to after OAuth.

    Uses the oauth_return_to cookie (set by oauth/start) if present and
    in the allowed-origins list; otherwise falls back to FRONTEND_URL.
    """
    frontend_url = os.environ.get("FRONTEND_URL", "https://claven.app")
    return_to = request.cookies.get("oauth_return_to")
    if return_to and return_to in _allowed_origins():
        return return_to
    return frontend_url


def _error_redirect(base: str, reason: str) -> RedirectResponse:
    response = RedirectResponse(url=f"{base}/?error={reason}", status_code=302)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_return_to")
    return response


@app.get("/oauth/callback")
def oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    base = _redirect_base(request)

    if error:
        logger.warning("OAuth error from Google: %s", error)
        return _error_redirect(base, "oauth_denied")
    if not code or not state:
        return _error_redirect(base, "invalid_request")

    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        logger.warning("State mismatch: stored=%r param=%r", stored_state, state)
        return _error_redirect(base, "invalid_state")

    # State verified — delete the cookie immediately so it can't be replayed
    flow = _make_flow()
    flow.redirect_uri = os.environ["OAUTH_REDIRECT_URI"]
    try:
        flow.fetch_token(code=code)
    except Exception as exc:
        logger.warning("Token exchange failed: %s", exc)
        return _error_redirect(base, "token_exchange_failed")
    creds = flow.credentials

    try:
        id_info = google_id_token.verify_oauth2_token(
            creds.id_token,
            google_requests.Request(),
            os.environ["OAUTH_CLIENT_ID"],
        )
    except Exception as exc:
        logger.warning("ID token verification failed: %s", exc)
        return _error_redirect(base, "token_verification_failed")
    email = id_info["email"]

    try:
        with db.get_connection() as conn:
            user_id = db.upsert_user(conn, email)
            existing_tokens = db.load_tokens(conn, user_id)
            if not existing_tokens:
                if not creds.refresh_token:
                    # User previously authorized the app but Google didn't
                    # return a refresh token (happens when reconnecting after
                    # disconnect). Redirect back to force re-consent.
                    api_base = os.environ["OAUTH_REDIRECT_URI"].rsplit("/oauth/callback", 1)[0]
                    params: dict = {"force_consent": "true"}
                    if base != os.environ.get("FRONTEND_URL", "https://claven.app"):
                        params["return_to"] = base
                    response = RedirectResponse(
                        url=f"{api_base}/oauth/start?{urlencode(params)}",
                        status_code=302,
                    )
                    response.delete_cookie("oauth_state")
                    response.delete_cookie("oauth_return_to")
                    return response
                # New user — store credentials only.
                # Starting the Gmail watch is an explicit user step via /api/connect.
                auth.store_credentials(conn, user_id, creds, os.environ["TOKEN_ENCRYPTION_KEY"])
    except Exception as exc:
        logger.exception("Signup failed for %s: %s", email, exc)
        return _error_redirect(base, "signup_failed")

    logger.info("OAuth complete for %s (user_id=%s)", email, user_id)
    session_token = _issue_session(user_id, email)
    response = RedirectResponse(url=f"{base}/dashboard", status_code=302)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_return_to")
    response.set_cookie("session", session_token, httponly=True, secure=True, samesite="none")
    return response


def _label_id_cache_for_config(service, label_configs: list[dict]) -> dict[str, str]:
    """Build a Gmail label ID cache for all labels referenced in the config."""
    names = []
    for lc in label_configs:
        names.append(lc["id"])
        if unknown := lc.get("unknown_label"):
            names.append(unknown)
    return build_label_id_cache(service, names)


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

                label_id_cache = _label_id_cache_for_config(service, label_configs)
                count = poll_new_messages(service, history_id, label_configs, label_id_cache, known_senders)
                db.set_history_id(conn, user_id, latest_history_id)
                if count is not None:
                    db.increment_processed_count(conn, user_id, count)
                results.append({"user_id": user_id, "status": "ok"})
            except Exception as exc:
                logger.exception("Error processing user %s", user_id, exc_info=exc)
                results.append({"user_id": user_id, "status": "error", "detail": str(exc)})

    return {"processed": len(results), "results": results}


@app.get("/api/me")
def api_me(request: Request):
    session = _get_session(request)
    with db.get_connection() as conn:
        user = db.get_user_by_id(conn, session["user_id"])
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        history_id = db.get_history_id(conn, session["user_id"])
        known_senders = db.count_known_senders(conn, session["user_id"])
        processed_count = db.get_processed_count(conn, session["user_id"])

        unread_count = None
        read_count = None
        inbox_count = None
        filtered_in_count = None
        filtered_out_count = None
        unlabeled_count = None
        try:
            service = auth.get_service(conn, session["user_id"], os.environ["TOKEN_ENCRYPTION_KEY"])
            inbox = service.users().labels().get(userId="me", id="INBOX").execute()
            unread_count = inbox.get("messagesUnread")
            inbox_count = inbox.get("messagesTotal")
            read_result = service.users().messages().list(
                userId="me", labelIds=["INBOX"], q="is:read", maxResults=1
            ).execute()
            read_count = read_result.get("resultSizeEstimate")

            label_configs = load_config().get("labels", [])
            all_gmail_labels = service.users().labels().list(userId="me").execute().get("labels", [])
            label_id_by_name = {l["name"]: l["id"] for l in all_gmail_labels}

            filtered_in_count = 0
            filtered_out_count = 0
            for lc in label_configs:
                if lid := label_id_by_name.get(lc["id"]):
                    r = service.users().messages().list(
                        userId="me", labelIds=["INBOX", lid], maxResults=1
                    ).execute()
                    filtered_in_count += r.get("resultSizeEstimate", 0)
                if (unknown := lc.get("unknown_label")) and (uid := label_id_by_name.get(unknown)):
                    r = service.users().messages().list(
                        userId="me", labelIds=["INBOX", uid], maxResults=1
                    ).execute()
                    filtered_out_count += r.get("resultSizeEstimate", 0)

            if inbox_count is not None:
                unlabeled_count = max(0, inbox_count - filtered_in_count - filtered_out_count)
        except Exception as exc:
            logger.warning("Gmail API unavailable for /api/me (%s): %s", session["email"], exc)

        pending_count = (
            max(0, inbox_count - processed_count) if inbox_count is not None else None
        )

    return {
        "email": user["email"],
        "connected": history_id is not None,
        "history_id": history_id,
        "known_senders": known_senders,
        "processed_count": processed_count,
        "pending_count": pending_count,
        "filtered_in_count": filtered_in_count,
        "filtered_out_count": filtered_out_count,
        "unlabeled_count": unlabeled_count,
        "unread_count": unread_count,
        "read_count": read_count,
        "inbox_count": inbox_count,
    }


@app.get("/api/config")
def api_config():
    config = load_config()
    return {"labels": config.get("labels", [])}


@app.post("/api/connect")
def api_connect(request: Request):
    """Start the Gmail push watch for the authenticated user.

    This is the explicit user-initiated step that begins inbox filtering.
    Credentials must already be stored (via the OAuth sign-in flow).
    """
    session = _get_session(request)
    with db.get_connection() as conn:
        try:
            service = auth.get_service(conn, session["user_id"], os.environ["TOKEN_ENCRYPTION_KEY"])
            watch_response = start_watch(service, os.environ["PUBSUB_TOPIC"])
            history_id = int(watch_response["historyId"])
            db.set_history_id(conn, session["user_id"], history_id)
        except Exception as exc:
            logger.exception("Connect failed for %s: %s", session["email"], exc)
            raise HTTPException(status_code=500, detail="Failed to start Gmail watch")
    return JSONResponse({"ok": True, "history_id": history_id})


@app.post("/api/disconnect")
def api_disconnect(request: Request):
    """Stop the Gmail push watch and clear scan state.

    Keeps OAuth credentials intact so the user can reconnect with a single
    click (no OAuth round-trip required).
    """
    session = _get_session(request)
    with db.get_connection() as conn:
        try:
            service = auth.get_service(conn, session["user_id"], os.environ["TOKEN_ENCRYPTION_KEY"])
            stop_watch(service)
        except Exception as exc:
            logger.warning("stop_watch failed during disconnect for %s: %s", session["email"], exc)
        db.clear_watch_state(conn, session["user_id"])
    return JSONResponse({"ok": True})


@app.post("/api/logout")
def api_logout(request: Request):
    _get_session(request)
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response


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
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        count = poll_new_messages(service, stored_history_id, label_configs, label_id_cache, known_senders)
        db.set_history_id(conn, user["id"], notification_history_id)
        if count is not None:
            db.increment_processed_count(conn, user["id"], count)

    return {"status": "ok"}
