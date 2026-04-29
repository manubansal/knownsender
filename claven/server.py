"""
Claven web server — thin HTTP entry point over claven/core/.

Endpoints:
  GET  /health                  — liveness probe for Cloud Run
  GET  /oauth/start             — begin OAuth flow, redirect to Google consent
  GET  /oauth/callback          — exchange OAuth code for tokens, store in DB
  POST /internal/poll           — Cloud Scheduler trigger: poll Gmail history for all users
  POST /internal/build-known-senders — build/update known senders list for all users
  POST /webhook/gmail           — Pub/Sub push handler: incoming Gmail notifications
"""

import base64
import json
import logging
import os
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, quote

import jwt as pyjwt
import threading

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
from claven.core.scan import build_known_senders, scan_inbox
from claven.core.watch import start_watch, stop_watch

_LOG_FILE = os.environ.get("CLAVEN_LOG_FILE", "")
if _LOG_FILE:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(_LOG_FILE), logging.StreamHandler()],
    )
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

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


def _error_redirect(base: str, reason: str, detail: str | None = None) -> RedirectResponse:
    url = f"{base}/?error={reason}"
    if detail:
        url += f"&error_detail={quote(detail)}"
    response = RedirectResponse(url=url, status_code=302)
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
        return _error_redirect(base, "token_exchange_failed", str(exc))
    creds = flow.credentials

    try:
        id_info = google_id_token.verify_oauth2_token(
            creds.id_token,
            google_requests.Request(),
            os.environ["OAUTH_CLIENT_ID"],
        )
    except Exception as exc:
        logger.warning("ID token verification failed: %s", exc)
        return _error_redirect(base, "token_verification_failed", str(exc))
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
        return _error_redirect(base, "signup_failed", str(exc))

    logger.info("OAuth complete for %s (user_id=%s)", email, user_id)
    session_token = _issue_session(user_id, email)
    response = RedirectResponse(url=f"{base}/dashboard", status_code=302)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_return_to")
    response.set_cookie("session", session_token, httponly=True, secure=True, samesite="none")
    return response


_STALE_SCAN_THRESHOLD = timedelta(minutes=5)


def _needs_sent_scan(scan_progress: dict) -> bool:
    """Return True if the sent scan should be (re-)triggered."""
    status = scan_progress["status"]
    if status == "complete":
        return False
    if status == "in_progress":
        updated_at = scan_progress.get("updated_at")
        if updated_at and datetime.now(timezone.utc) - updated_at < _STALE_SCAN_THRESHOLD:
            return False
        # Stale in_progress — treat as failed
        return True
    # None, "error", or anything else
    return True


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

                # Reconcile: if sent scan never completed, run it now
                scan_progress = db.get_sent_scan_progress(conn, user_id)
                if _needs_sent_scan(scan_progress):
                    logger.info("Reconciling sent scan for user %s (status=%s)", user_id, scan_progress["status"])
                    db.set_sent_scan_status(conn, user_id, "in_progress")
                    try:
                        build_known_senders(service, conn, user_id)
                        db.set_sent_scan_status(conn, user_id, "complete")
                    except Exception as exc:
                        logger.exception("Reconcile sent scan failed for %s", user_id)
                        db.set_sent_scan_status(conn, user_id, "error")

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


@app.post("/internal/build-known-senders")
def internal_build_known_senders(request: Request):
    """Build or update the known senders list for all connected users.

    Scans each user's Sent mail and populates their sent_recipients rows.
    Uses a per-user cursor (sent_scan_cursor) for incremental updates —
    only new sent messages are processed on subsequent runs.

    Intended to be triggered by a Cloud Scheduler job or by /api/connect.
    """
    _require_internal_auth(request)
    results = []

    with db.get_connection() as conn:
        users = db.get_all_users(conn)

    for user in users:
        user_id = user["id"]
        with db.get_connection() as conn:
            try:
                service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
                result = build_known_senders(service, conn, user_id)
                results.append({"user_id": user_id, "status": "ok", **result})
            except Exception as exc:
                logger.exception("Known senders scan failed for user %s", user_id, exc_info=exc)
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
        sent_scan_progress = db.get_sent_scan_progress(conn, session["user_id"])
        processed_count = db.get_processed_count(conn, session["user_id"])

        # Auto-trigger sent scan if it has never run for this user
        if _needs_sent_scan(sent_scan_progress):
            has_tokens = db.load_tokens(conn, session["user_id"]) is not None
            if has_tokens:
                db.set_sent_scan_status(conn, session["user_id"], "in_progress")
                sent_scan_progress["status"] = "in_progress"
                threading.Thread(target=_run_sent_scan, args=(session["user_id"],), daemon=True).start()

        unread_count = None
        read_count = None
        inbox_count = None
        all_mail_count = None
        sent_total_live = None
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

            profile_data = service.users().getProfile(userId="me").execute()
            all_mail_count = profile_data.get("messagesTotal")

            sent_label = service.users().labels().get(userId="me", id="SENT").execute()
            sent_total_live = sent_label.get("messagesTotal")

            label_configs = load_config().get("labels", [])
            all_gmail_labels = service.users().labels().list(userId="me").execute().get("labels", [])
            label_id_by_name = {l["name"]: l["id"] for l in all_gmail_labels}

            filtered_in_count = 0
            filtered_out_count = 0
            for lc in label_configs:
                if lid := label_id_by_name.get(lc["id"]):
                    label_info = service.users().labels().get(userId="me", id=lid).execute()
                    filtered_in_count += label_info.get("messagesTotal", 0)
                if (unknown := lc.get("unknown_label")) and (uid := label_id_by_name.get(unknown)):
                    label_info = service.users().labels().get(userId="me", id=uid).execute()
                    filtered_out_count += label_info.get("messagesTotal", 0)

            if inbox_count is not None:
                unlabeled_count = max(0, inbox_count - filtered_in_count - filtered_out_count)
        except Exception as exc:
            logger.warning("Gmail API unavailable for /api/me (%s): %s", session["email"], exc)

        pending_count = (
            max(0, inbox_count - processed_count) if inbox_count is not None else None
        )

        # Auto-trigger inbox scan if sent scan is done and inbox hasn't been fully scanned
        if (sent_scan_progress["status"] == "complete"
                and history_id is not None
                and inbox_count is not None
                and processed_count < inbox_count
                and session["user_id"] not in _inbox_scan_running):
            threading.Thread(target=_run_inbox_scan, args=(session["user_id"],), daemon=True).start()

    return {
        "email": user["email"],
        "connected": history_id is not None,
        "history_id": history_id,
        "known_senders": known_senders,
        "sent_messages_scanned": sent_scan_progress["messages_scanned"],
        "sent_messages_total": sent_total_live if sent_total_live is not None else sent_scan_progress["messages_total"],
        "sent_scan_status": sent_scan_progress["status"],
        "inbox_scan_in_progress": session["user_id"] in _inbox_scan_running,
        "processed_count": processed_count,
        "pending_count": pending_count,
        "filtered_in_count": filtered_in_count,
        "filtered_out_count": filtered_out_count,
        "unlabeled_count": unlabeled_count,
        "unread_count": unread_count,
        "read_count": read_count,
        "inbox_count": inbox_count,
        "all_mail_count": all_mail_count,
    }


@app.get("/api/config")
def api_config():
    config = load_config()
    return {"labels": config.get("labels", [])}


_inbox_scan_running: set[str] = set()

def _run_inbox_scan(user_id: str):
    """Background task: scan all inbox messages and apply labels."""
    if user_id in _inbox_scan_running:
        return
    _inbox_scan_running.add(user_id)
    label_configs = load_config().get("labels", [])
    try:
        with db.get_connection() as conn:
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            known_senders = db.get_known_senders(conn, user_id)
            label_id_cache = _label_id_cache_for_config(service, label_configs)
            count = scan_inbox(service, conn, user_id, label_configs, label_id_cache, known_senders)
            logger.info("Inbox scan for %s: processed %d message(s)", user_id, count)
    except Exception as exc:
        logger.exception("Inbox scan failed for user %s: %s", user_id, exc)
    finally:
        _inbox_scan_running.discard(user_id)


def _run_sent_scan(user_id: str):
    """Background task: build the known senders list, then poll inbox.

    After the sent scan completes, immediately processes any inbox messages
    that arrived since the history_id was set at connect time. This ensures
    labeling starts without waiting for an external trigger (Pub/Sub or
    Cloud Scheduler).
    """
    with db.get_connection() as conn:
        try:
            db.set_sent_scan_status(conn, user_id, "in_progress")
        except Exception:
            logger.exception("Failed to set sent scan status for %s", user_id)
            return
    try:
        with db.get_connection() as conn:
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            build_known_senders(service, conn, user_id)
        with db.get_connection() as conn:
            db.set_sent_scan_status(conn, user_id, "complete")
    except Exception as exc:
        logger.exception("Sent scan failed for user %s: %s", user_id, exc)
        try:
            with db.get_connection() as conn:
                db.set_sent_scan_status(conn, user_id, "error")
        except Exception:
            logger.exception("Failed to set error status for %s", user_id)
        return

    # Sent scan done — scan the full inbox to apply labels to all existing messages
    _inbox_scan_running.add(user_id)
    label_configs = load_config().get("labels", [])
    try:
        with db.get_connection() as conn:
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            known_senders = db.get_known_senders(conn, user_id)
            label_id_cache = _label_id_cache_for_config(service, label_configs)
            count = scan_inbox(service, conn, user_id, label_configs, label_id_cache, known_senders)
            logger.info("Post-scan inbox scan for %s: processed %d message(s)", user_id, count)
    except Exception as exc:
        logger.exception("Post-scan inbox scan failed for user %s: %s", user_id, exc)
    finally:
        _inbox_scan_running.discard(user_id)


@app.post("/api/connect")
def api_connect(request: Request):
    """Start the Gmail push watch for the authenticated user.

    This is the explicit user-initiated step that begins inbox filtering.
    Credentials must already be stored (via the OAuth sign-in flow).
    Also kicks off a background scan of Sent mail to build the known senders list.
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
    threading.Thread(target=_run_sent_scan, args=(session["user_id"],), daemon=True).start()
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

        # Incremental known senders update — cheap with cursor (one list_history call).
        # Also serves as reconciliation: if the initial scan never completed,
        # build_known_senders falls through to a full scan.
        scan_progress = db.get_sent_scan_progress(conn, user["id"])
        if _needs_sent_scan(scan_progress):
            db.set_sent_scan_status(conn, user["id"], "in_progress")
        try:
            build_known_senders(service, conn, user["id"])
            if scan_progress["status"] != "complete":
                db.set_sent_scan_status(conn, user["id"], "complete")
        except Exception as exc:
            logger.warning("Known senders update failed for %s: %s", user["id"], exc)

        known_senders = db.get_known_senders(conn, user["id"])
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        count = poll_new_messages(service, stored_history_id, label_configs, label_id_cache, known_senders)
        db.set_history_id(conn, user["id"], notification_history_id)
        if count is not None:
            db.increment_processed_count(conn, user["id"], count)

    return {"status": "ok"}
