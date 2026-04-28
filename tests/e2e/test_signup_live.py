"""
Live e2e test: full OAuth signup flow with real Gmail API calls.

Difference from test_signup.py (mocked e2e):
  - Builds real Google credentials from TEST_GMAIL_REFRESH_TOKEN
  - Does NOT mock start_watch or build() — real Gmail API calls are made
  - Verifies the historyId stored in the DB came from an actual Gmail response
  - Calls stop_watch in teardown to deregister the push subscription

What is still mocked (unavoidable):
  - flow.fetch_token — auth codes require a live browser session; we inject
    the real credentials instead
  - google_id_token.verify_oauth2_token — ID tokens are only issued on the
    initial code exchange, not when refreshing

Requires env vars (all available as GitHub secrets):
  TEST_GMAIL_REFRESH_TOKEN  — refresh token for claven.test.inbox@gmail.com
  TEST_GMAIL_EMAIL          — claven.test.inbox@gmail.com
  PYTEST_DATABASE_URL       — CI Postgres connection string
  PUBSUB_TOPIC              — projects/<project>/topics/<topic>
  OAUTH_CLIENT_ID           — GCP OAuth client ID
  OAUTH_CLIENT_SECRET       — GCP OAuth client secret
  TOKEN_ENCRYPTION_KEY      — 64-char hex token encryption key

Run with: pytest -m live
"""

import os
from unittest.mock import MagicMock, patch

import psycopg2
import psycopg2.extras
import pytest
from fastapi.testclient import TestClient
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials as GoogleCredentials
from googleapiclient.discovery import build as gmail_build

from claven.core.watch import stop_watch
from claven.server import app

pytestmark = pytest.mark.live

_REFRESH_TOKEN = os.environ.get("TEST_GMAIL_REFRESH_TOKEN")
_EMAIL = os.environ.get("TEST_GMAIL_EMAIL", "claven.test.inbox@gmail.com")
_DB_URL = os.environ.get("PYTEST_DATABASE_URL")
_PUBSUB_TOPIC = os.environ.get("PUBSUB_TOPIC")
_OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
_OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET")
_TOKEN_ENCRYPTION_KEY = os.environ.get("TOKEN_ENCRYPTION_KEY")

_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]

_ENV = {
    "OAUTH_CLIENT_ID": _OAUTH_CLIENT_ID or "",
    "OAUTH_CLIENT_SECRET": _OAUTH_CLIENT_SECRET or "",
    "OAUTH_REDIRECT_URI": "http://localhost/oauth/callback",
    "INTERNAL_API_SECRET": "test-internal-secret",
    "TOKEN_ENCRYPTION_KEY": _TOKEN_ENCRYPTION_KEY or "",
    "PUBSUB_TOPIC": _PUBSUB_TOPIC or "",
    "FRONTEND_URL": "https://claven.app",
    "DATABASE_URL": _DB_URL or "",
}

_REQUIRED = {
    "TEST_GMAIL_REFRESH_TOKEN": _REFRESH_TOKEN,
    "TEST_GMAIL_EMAIL": _EMAIL,
    "PYTEST_DATABASE_URL": _DB_URL,
    "PUBSUB_TOPIC": _PUBSUB_TOPIC,
    "OAUTH_CLIENT_ID": _OAUTH_CLIENT_ID,
    "OAUTH_CLIENT_SECRET": _OAUTH_CLIENT_SECRET,
    "TOKEN_ENCRYPTION_KEY": _TOKEN_ENCRYPTION_KEY,
}


def _build_real_creds() -> GoogleCredentials:
    """Exchange the stored refresh token for a live access token."""
    creds = GoogleCredentials(
        token=None,
        refresh_token=_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=_OAUTH_CLIENT_ID,
        client_secret=_OAUTH_CLIENT_SECRET,
        scopes=_SCOPES,
    )
    creds.refresh(GoogleRequest())
    return creds


@pytest.fixture(autouse=True)
def require_live_secrets():
    missing = [k for k, v in _REQUIRED.items() if not v]
    if missing:
        pytest.skip(f"Live secrets not set: {', '.join(missing)}")


@pytest.fixture(autouse=True)
def clean_test_user():
    """Wipe the test account before and after each test.

    Also attempts to stop any active Gmail push watch so we don't leave
    orphaned Pub/Sub subscriptions after the test runs.
    """
    def _delete_db():
        if not _DB_URL:
            return
        conn = psycopg2.connect(_DB_URL)
        psycopg2.extras.register_uuid(conn_or_curs=conn)
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE email = %s", (_EMAIL,))
            conn.commit()
        finally:
            conn.close()

    def _stop_gmail_watch():
        try:
            creds = _build_real_creds()
            service = gmail_build("gmail", "v1", credentials=creds)
            stop_watch(service)
        except Exception:
            pass  # no active watch or API error — both are fine in teardown

    _delete_db()
    try:
        yield
    finally:
        _stop_gmail_watch()
        _delete_db()


class TestSignupLive:
    def test_oauth_callback_with_real_gmail_api(self):
        """
        Full OAuth callback path with real Gmail API calls.

        Mocked: flow.fetch_token (injected with real credentials),
                google_id_token.verify_oauth2_token (ID token unavailable on refresh).
        Real:   google.oauth2 token refresh, build(), start_watch(), DB writes.

        Verifies:
          - The test account credentials are still valid
          - start_watch() succeeds against the live Gmail API and Pub/Sub topic
          - The historyId stored in the DB is a real value from Gmail (>0)
          - The server redirects to /connected?email=...
        """
        real_creds = _build_real_creds()

        mock_flow = MagicMock()
        mock_flow.credentials = real_creds
        mock_flow.authorization_url.return_value = (
            "https://accounts.google.com/o/oauth2/auth",
            "ignored",
        )

        with patch.dict("os.environ", _ENV):
            with (
                patch("claven.server.Flow") as mock_flow_cls,
                patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
            ):
                mock_flow_cls.from_client_config.return_value = mock_flow
                mock_verify.return_value = {"email": _EMAIL}

                with TestClient(app) as client:
                    start = client.get("/oauth/start", follow_redirects=False)
                    state = start.cookies.get("oauth_state")
                    assert state, "oauth_state cookie missing from /oauth/start"
                    client.cookies.set("oauth_state", state)

                    response = client.get(
                        f"/oauth/callback?code=fake-auth-code&state={state}",
                        follow_redirects=False,
                    )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert "/connected" in location, f"Expected /connected in redirect, got: {location}"
        assert _EMAIL in location, f"Expected email in redirect, got: {location}"

        # Verify DB: user row and tokens exist
        conn = psycopg2.connect(_DB_URL)
        psycopg2.extras.register_uuid(conn_or_curs=conn)
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id FROM users WHERE email = %s", (_EMAIL,))
                user = cur.fetchone()
            assert user is not None, f"User {_EMAIL} not found in DB after signup"

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT access_token_enc, refresh_token_enc FROM gmail_tokens WHERE user_id = %s",
                    (user["id"],),
                )
                tokens = cur.fetchone()
            assert tokens is not None, "Tokens not stored in DB after signup"

            # historyId must be a real value from Gmail (not the mocked 99999)
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT history_id FROM scan_state WHERE user_id = %s",
                    (user["id"],),
                )
                state_row = cur.fetchone()
            assert state_row is not None, "scan_state row not found after signup"
            assert state_row["history_id"] > 0, "historyId should be a real Gmail value"
        finally:
            conn.close()
