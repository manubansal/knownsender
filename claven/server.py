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
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
import secrets
from contextlib import asynccontextmanager
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

class _CloudJsonFormatter(logging.Formatter):
    """Emit structured JSON for Cloud Logging. Maps Python levels to Cloud severity.

    Extra fields (user_id, event) are included when passed via logger.info("msg", extra={...}).
    """
    _SEVERITY = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARNING",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "CRITICAL",
    }

    def format(self, record):
        import json as _json
        entry = {
            "severity": self._SEVERITY.get(record.levelno, "DEFAULT"),
            "message": record.getMessage(),
            "logger": record.name,
        }
        for field in ("user_id", "event", "email"):
            if val := getattr(record, field, None):
                entry[field] = val
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return _json.dumps(entry)


_LOG_FILE = os.environ.get("CLAVEN_LOG_FILE", "")
_ON_CLOUD_RUN = bool(os.environ.get("K_SERVICE"))

if _LOG_FILE:
    # Local dev with file logging — human-readable + file
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(_LOG_FILE), logging.StreamHandler()],
        force=True,
    )
elif _ON_CLOUD_RUN:
    # Production on Cloud Run — structured JSON to stdout for Cloud Logging
    _handler = logging.StreamHandler()
    _handler.setFormatter(_CloudJsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[_handler], force=True)

logging.getLogger("googleapiclient.discovery").setLevel(logging.WARNING)
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Worker generation ID — unique per process. Background scan threads check this
# per batch and exit if it changes (means --reload spawned a new worker).
_worker_id = os.getpid()

# Shutdown event — replaces a plain boolean flag. threading.Event lets
# background threads use event.wait(timeout) instead of time.sleep(),
# so they wake up instantly when shutdown is signalled instead of
# blocking for the full sleep duration.
_shutdown_event = threading.Event()

# Registry of active scan threads — joined during lifespan shutdown
# so the process exits cleanly instead of leaving orphans.
_active_threads: list[threading.Thread] = []
_threads_lock = threading.Lock()


def _shutdown_handler(signum, frame):
    _shutdown_event.set()
    # Don't log here — signal handlers can interrupt mid-flush, causing
    # "reentrant call inside BufferedWriter" on shutdown.


import signal
signal.signal(signal.SIGINT, _shutdown_handler)
signal.signal(signal.SIGTERM, _shutdown_handler)


def _spawn_scan_thread(target, args):
    """Start a daemon thread and track it for graceful shutdown."""
    t = threading.Thread(target=target, args=args, daemon=True)
    with _threads_lock:
        _active_threads.append(t)
    t.start()
    return t


@asynccontextmanager
async def lifespan(app):
    # Reset shutdown state — needed for test isolation since TestClient
    # enters/exits lifespan for every test.
    _shutdown_event.clear()
    with _threads_lock:
        _active_threads.clear()
    logger.info("Worker started (pid=%d)", _worker_id)
    yield
    # Shutdown: signal all threads to stop, then wait for them.
    _shutdown_event.set()
    with _threads_lock:
        threads = list(_active_threads)
    for t in threads:
        t.join(timeout=5)
    still_alive = sum(1 for t in threads if t.is_alive())
    if still_alive:
        logger.warning("Shutdown: %d scan thread(s) still alive after timeout", still_alive)
    with _threads_lock:
        _active_threads.clear()
    logger.info("Worker shutdown complete (pid=%d)", _worker_id)

app = FastAPI(title="Claven", lifespan=lifespan)

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
    """Liveness probe — always returns 200 if the process is running."""
    return {"status": "ok"}


@app.get("/healthz")
def healthz():
    """Readiness probe — checks DB connectivity. Returns 503 if DB is unreachable."""
    try:
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return {"status": "ok", "db": "connected"}
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "error", "db": "unreachable", "detail": str(exc)},
        )


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

    # Google's granular permissions lets users uncheck individual scopes.
    # Verify the required gmail.modify scope was granted.
    granted = set(creds.scopes or [])
    if "https://www.googleapis.com/auth/gmail.modify" not in granted:
        logger.warning("Gmail scope not granted (got: %s)", granted)
        return _error_redirect(base, "gmail_scope_missing")

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

    logger.info("OAuth complete for %s (user_id=%s)", email, user_id,
                extra={"event": "oauth_complete", "user_id": user_id, "email": email})

    # Kick off sent scan immediately — user is now eligible (has tokens).
    # Don't wait for dashboard load. The scan runs in a background thread
    # and the dashboard will show progress when the user arrives.
    _spawn_scan_thread(_run_sent_scan, (user_id,))

    session_token = _issue_session(user_id, email)
    response = RedirectResponse(url=f"{base}/dashboard", status_code=302)
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_return_to")
    response.set_cookie("session", session_token, httponly=True, secure=True, samesite="none")
    return response


_STALE_SCAN_THRESHOLD = timedelta(minutes=1)


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
                if not db.try_lock_user_scan(conn, user_id):
                    results.append({"user_id": user_id, "status": "skipped", "detail": "locked"})
                    continue

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
                if count is not None and count > 0:
                    db.increment_processed_count(conn, user_id, count)
                    db.touch_last_processed(conn, user_id)
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
        # processed_count no longer used — progress derived from live Gmail label counts
        last_processed_at = db.get_last_processed_at(conn, session["user_id"])
        newest_labeled_at = db.get_newest_labeled_at(conn, session["user_id"])

        unread_count = None
        read_count = None
        inbox_count = None
        all_mail_count = None
        sent_total_live = None
        sent_scanned_count = 0
        newest_mail_at = None
        allmail_labeled_known_count = None
        allmail_labeled_unknown_count = None
        allmail_labeled_total_count = None
        inbox_unlabeled_first_page_count = None
        inbox_unlabeled_deep_count = None
        try:
            service = auth.get_service(conn, session["user_id"], os.environ["TOKEN_ENCRYPTION_KEY"])
            inbox = service.users().labels().get(userId="me", id="INBOX").execute()
            unread_count = inbox.get("messagesUnread")
            inbox_count = inbox.get("messagesTotal")
            read_result = service.users().messages().list(
                userId="me", labelIds=["INBOX"], q="is:read", maxResults=1
            ).execute()
            read_count = read_result.get("resultSizeEstimate")

            # Newest inbox message timestamp
            newest_result = service.users().messages().list(
                userId="me", labelIds=["INBOX"], maxResults=1
            ).execute()
            newest_msgs = newest_result.get("messages", [])
            if newest_msgs:
                newest_msg = service.users().messages().get(
                    userId="me", id=newest_msgs[0]["id"], format="minimal"
                ).execute()
                newest_mail_ms = newest_msg.get("internalDate")
                if newest_mail_ms:
                    newest_mail_at = datetime.fromtimestamp(int(newest_mail_ms) / 1000, tz=timezone.utc)

            profile_data = service.users().getProfile(userId="me").execute()
            all_mail_count = profile_data.get("messagesTotal")

            sent_label = service.users().labels().get(userId="me", id="SENT").execute()
            sent_total_live = sent_label.get("messagesTotal")

            # Sent scan progress from mailbox state
            from claven.core.scan import SENT_SCANNED_LABEL
            all_gmail_labels = service.users().labels().list(userId="me").execute().get("labels", [])
            sent_scanned_label_id = next((l["id"] for l in all_gmail_labels if l["name"] == SENT_SCANNED_LABEL), None)
            if sent_scanned_label_id:
                sent_scanned_info = service.users().labels().get(userId="me", id=sent_scanned_label_id).execute()
                sent_scanned_count = sent_scanned_info.get("messagesTotal", 0)
            else:
                sent_scanned_count = 0

            label_configs = load_config().get("labels", [])
            all_gmail_labels = service.users().labels().list(userId="me").execute().get("labels", [])
            label_id_by_name = {l["name"]: l["id"] for l in all_gmail_labels}

            # Exact per-label counts via labels.get().messagesTotal
            allmail_labeled_known_count = 0
            allmail_labeled_unknown_count = 0
            for lc in label_configs:
                if lid := label_id_by_name.get(lc["id"]):
                    info = service.users().labels().get(userId="me", id=lid).execute()
                    allmail_labeled_known_count += info.get("messagesTotal", 0)
                if (unknown := lc.get("unknown_label")) and (uid := label_id_by_name.get(unknown)):
                    info = service.users().labels().get(userId="me", id=uid).execute()
                    allmail_labeled_unknown_count += info.get("messagesTotal", 0)
            allmail_labeled_total_count = allmail_labeled_known_count + allmail_labeled_unknown_count

            # Unlabeled inbox messages — same query the scan uses.
            # First page gives exact count (up to 500) for quick retrigger check.
            # Full pagination gives exact total.
            from claven.core.scan import _unlabeled_query
            unlabeled_q = _unlabeled_query(label_configs)
            first_page = service.users().messages().list(
                userId="me", q=unlabeled_q, maxResults=500
            ).execute()
            first_page_messages = first_page.get("messages", [])
            inbox_unlabeled_first_page_count = len(first_page_messages)

            total_unlabeled = inbox_unlabeled_first_page_count
            page_token = first_page.get("nextPageToken")
            while page_token:
                page = service.users().messages().list(
                    userId="me", q=unlabeled_q, maxResults=500,
                    pageToken=page_token,
                ).execute()
                total_unlabeled += len(page.get("messages", []))
                page_token = page.get("nextPageToken")
            inbox_unlabeled_deep_count = total_unlabeled
        except Exception as exc:
            logger.warning("Gmail API unavailable for /api/me (%s): %s", session["email"], exc)

        inbox_scan_status = db.get_inbox_scan_status(conn, session["user_id"])

    # Reconciliation: if the inbox scan completed but the first page
    # finds unlabeled messages, retrigger. Row lock makes this idempotent.
    if (inbox_unlabeled_first_page_count is not None
            and inbox_unlabeled_first_page_count > 0
            and inbox_scan_status == "complete"
            and history_id is not None):
        inbox_scan_status = "in_progress"
        threading.Thread(target=_run_inbox_scan, args=(session["user_id"],), daemon=True).start()

    return {
        "email": user["email"],
        "connected": history_id is not None,
        "history_id": history_id,
        "known_senders": known_senders,
        "sent_scanned_count": sent_scanned_count,
        "sent_total_count": sent_total_live,
        "sent_scan_status": sent_scan_progress["status"],
        "inbox_scan_in_progress": inbox_scan_status == "in_progress",
        "last_processed_at": last_processed_at.isoformat() if last_processed_at else None,
        "newest_mail_at": newest_mail_at.isoformat() if newest_mail_at else None,
        "newest_labeled_at": newest_labeled_at.isoformat() if newest_labeled_at else None,
        "allmail_labeled_known_count": allmail_labeled_known_count,
        "allmail_labeled_unknown_count": allmail_labeled_unknown_count,
        "allmail_labeled_total_count": allmail_labeled_total_count,
        "inbox_unlabeled_first_page_count": inbox_unlabeled_first_page_count,
        "inbox_unlabeled_deep_count": inbox_unlabeled_deep_count,
        "unread_count": unread_count,
        "read_count": read_count,
        "inbox_count": inbox_count,
        "all_mail_count": all_mail_count,
    }


@app.get("/api/config")
def api_config():
    config = load_config()
    return {"labels": config.get("labels", [])}


@app.get("/api/events")
async def api_events(request: Request):
    """Server-Sent Events endpoint for live scan progress.

    Listens on Postgres NOTIFY 'scan_progress' and forwards events
    matching the authenticated user's ID. Workers send NOTIFY after
    each batch commit, so the dashboard updates in real-time without
    polling.

    The connection stays open until the client disconnects. Sends a
    heartbeat comment every 30s to keep the connection alive through
    load balancers (Cloud Run, Cloudflare).

    Cost: one Postgres LISTEN connection per SSE client. No CPU while
    idle — select() blocks in a thread without burning cycles.
    """
    import asyncio
    import select
    import psycopg2
    import psycopg2.extensions as pg_ext

    session = _get_session(request)
    user_id = session["user_id"]

    listen_conn = None
    try:
        listen_conn = psycopg2.connect(os.environ["DATABASE_URL"])
        listen_conn.set_isolation_level(pg_ext.ISOLATION_LEVEL_AUTOCOMMIT)
        with listen_conn.cursor() as cur:
            cur.execute("LISTEN scan_progress")
    except Exception as exc:
        if listen_conn:
            listen_conn.close()
        logger.warning("SSE: failed to open LISTEN connection: %s", exc)
        raise HTTPException(status_code=503, detail="Event stream unavailable")

    _HEARTBEAT_INTERVAL = 30  # seconds
    _SELECT_TIMEOUT = 5       # seconds — check disconnect + heartbeat periodically

    async def event_stream():
        last_heartbeat = asyncio.get_event_loop().time()
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                # Poll Postgres for notifications (non-blocking via asyncio)
                ready = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: select.select([listen_conn], [], [], _SELECT_TIMEOUT)
                )
                if ready[0]:
                    listen_conn.poll()
                    while listen_conn.notifies:
                        notify = listen_conn.notifies.pop(0)
                        try:
                            payload = json.loads(notify.payload)
                        except Exception:
                            continue
                        if payload.get("user_id") != user_id:
                            continue
                        yield f"data: {notify.payload}\n\n"

                # Heartbeat — keeps connection alive through load balancers
                now = asyncio.get_event_loop().time()
                if now - last_heartbeat >= _HEARTBEAT_INTERVAL:
                    yield ": keepalive\n\n"
                    last_heartbeat = now
        except (GeneratorExit, asyncio.CancelledError):
            pass
        finally:
            try:
                listen_conn.close()
            except Exception:
                pass

    from starlette.responses import StreamingResponse
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _is_current_worker() -> bool:
    """Check if this thread should keep running.

    Returns False if:
    - --reload spawned a new worker (PID changed)
    - Ctrl+C / SIGTERM received (shutdown event set)
    """
    if _shutdown_event.is_set():
        return False
    return os.getpid() == _worker_id


def _run_inbox_scan(user_id: str):
    """Background task: scan all inbox messages and apply labels."""
    my_pid = os.getpid()
    logger.info("Inbox scan thread started for %s (worker pid=%d)", user_id, my_pid)
    label_configs = load_config().get("labels", [])
    try:
        with db.get_connection() as conn:
            if not db.try_lock_user_scan(conn, user_id):
                logger.info("Inbox scan skipped for %s — locked by another instance", user_id)
                return
            db.set_inbox_scan_status(conn, user_id, "in_progress")
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            known_senders = db.get_known_senders(conn, user_id)
            label_id_cache = _label_id_cache_for_config(service, label_configs)
            count = scan_inbox(service, conn, user_id, label_configs, label_id_cache, known_senders, should_continue=_is_current_worker, shutdown_event=_shutdown_event)
            db.set_inbox_scan_status(conn, user_id, "complete")
            logger.info("Inbox scan for %s: processed %d message(s)", user_id, count,
                        extra={"event": "inbox_scan_complete", "user_id": user_id})
    except Exception as exc:
        logger.exception("Inbox scan failed for user %s: %s", user_id, exc)
        try:
            with db.get_connection() as conn:
                db.set_inbox_scan_status(conn, user_id, "error")
        except Exception:
            logger.exception("Failed to set inbox scan error status for %s", user_id)


def _run_sent_scan(user_id: str):
    """Background task: build the known senders list, then scan inbox.

    Acquires a row-level lock on scan_state so only one instance processes
    a user at a time. After the sent scan completes, immediately labels
    all inbox messages.
    """
    logger.info("Sent scan thread started for %s (worker pid=%d)", user_id, os.getpid())
    with db.get_connection() as conn:
        if not db.try_lock_user_scan(conn, user_id):
            logger.info("Sent scan skipped for %s — locked by another instance", user_id)
            return
        try:
            db.set_sent_scan_status(conn, user_id, "in_progress")
        except Exception:
            logger.exception("Failed to set sent scan status for %s", user_id)
            return
    try:
        with db.get_connection() as conn:
            if not db.try_lock_user_scan(conn, user_id):
                logger.info("Sent scan skipped for %s — locked by another instance", user_id)
                return
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            build_known_senders(service, conn, user_id, should_continue=_is_current_worker, shutdown_event=_shutdown_event)
            if not _is_current_worker():
                logger.info("Sent scan stopped — worker replaced (pid=%d, current=%d)", _worker_id, os.getpid())
                return
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
    _run_inbox_scan(user_id)


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
    # Kick off both scans — sent scan may already be complete (from sign-in),
    # in which case _run_sent_scan is a no-op and inbox scan starts immediately.
    # If sent scan is still running, _run_sent_scan chains into inbox scan on completion.
    _spawn_scan_thread(_run_sent_scan, (session["user_id"],))
    _spawn_scan_thread(_run_inbox_scan, (session["user_id"],))
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

        if not db.try_lock_user_scan(conn, user["id"]):
            logger.info("Webhook for %s skipped — locked by another instance", email)
            return {"status": "ok", "detail": "locked"}

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
        if count is not None and count > 0:
            db.increment_processed_count(conn, user["id"], count)
            db.touch_last_processed(conn, user["id"])

    return {"status": "ok"}
