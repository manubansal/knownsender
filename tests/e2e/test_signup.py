"""
E2e test: full OAuth signup flow.

Uses a pre-obtained refresh token for the test Gmail account to simulate
a real OAuth callback. Only the parts that require a browser session are
mocked (flow.fetch_token, ID token verification); the DB writes and
redirect logic run for real against the CI Postgres instance.

Requires env vars:
  TEST_GMAIL_REFRESH_TOKEN — refresh token for claven.test.inbox@gmail.com
  TEST_GMAIL_EMAIL         — claven.test.inbox@gmail.com
  PYTEST_DATABASE_URL      — connection string for the test database

Run with: pytest -m e2e
"""

import os
from unittest.mock import MagicMock, patch

import psycopg2
import psycopg2.extras
import pytest
from fastapi.testclient import TestClient

from claven.server import app

pytestmark = pytest.mark.e2e

_REFRESH_TOKEN = os.environ.get("TEST_GMAIL_REFRESH_TOKEN")
_EMAIL = os.environ.get("TEST_GMAIL_EMAIL", "claven.test.inbox@gmail.com")
_DB_URL = os.environ.get("PYTEST_DATABASE_URL")

_ENV = {
    "OAUTH_CLIENT_ID": "test-client-id",
    "OAUTH_CLIENT_SECRET": "test-client-secret",
    "OAUTH_REDIRECT_URI": "http://localhost/oauth/callback",
    "INTERNAL_API_SECRET": "test-internal-secret",
    "TOKEN_ENCRYPTION_KEY": "aa" * 32,
    "SESSION_SECRET": "test-session-secret-must-be-at-least-32-bytes!",
    "PUBSUB_TOPIC": "projects/test/topics/test",
    "FRONTEND_URL": "https://claven.app",
    "DATABASE_URL": _DB_URL or "",
}


@pytest.fixture(autouse=True)
def require_e2e_secrets():
    if not _REFRESH_TOKEN:
        pytest.skip("TEST_GMAIL_REFRESH_TOKEN not set")
    if not _DB_URL:
        pytest.skip("PYTEST_DATABASE_URL not set")


@pytest.fixture(autouse=True)
def clean_test_user():
    """Guarantee the test account is absent before and after every test.

    Deleting from users cascades to gmail_tokens, scan_state, and
    sent_recipients, so no related rows are left behind.
    """
    def _delete():
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

    _delete()
    try:
        yield
    finally:
        _delete()


class TestSignupFlow:
    def test_oauth_callback_creates_user_and_redirects(self):
        """
        Full OAuth callback path:
          - state cookie roundtrip works
          - user is created in the DB
          - tokens are stored (encrypted)
          - response redirects to /connected?email=...

        Mocked: Flow.fetch_token (we hold a refresh token, not an auth code),
                google_id_token.verify_oauth2_token (ID token only issued on
                initial code exchange, not on refresh), start_watch (no Pub/Sub
                topic in CI).
        Real:   DB writes via claven/core/db.py.
        """
        mock_creds = MagicMock()
        mock_creds.token = "fake-access-token"
        mock_creds.refresh_token = _REFRESH_TOKEN
        mock_creds.id_token = "fake-id-token"
        mock_creds.expiry = None
        mock_creds.scopes = [
            "https://www.googleapis.com/auth/gmail.modify",
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
        ]

        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        # authorization_url() must return a 2-tuple; the server discards the
        # second value (state) because it generates its own via secrets.token_urlsafe
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", _ENV):
            with (
                patch("claven.server.Flow") as mock_flow_cls,
                patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
                patch("claven.server.start_watch") as mock_watch,
            ):
                mock_flow_cls.from_client_config.return_value = mock_flow
                mock_verify.return_value = {"email": _EMAIL}
                mock_watch.return_value = {"historyId": "99999"}

                with TestClient(app) as client:
                    # Step 1: start flow — sets oauth_state cookie
                    start = client.get("/oauth/start", follow_redirects=False)
                    state = start.cookies.get("oauth_state")
                    assert state, "oauth_state cookie missing from /oauth/start"

                    # secure=True cookies are not forwarded over plain HTTP in
                    # TestClient — inject manually so the callback can verify it
                    client.cookies.set("oauth_state", state)

                    # Step 2: simulate Google's redirect back to us
                    response = client.get(
                        f"/oauth/callback?code=fake-auth-code&state={state}",
                        follow_redirects=False,
                    )

        # Redirect to the connected page
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert "/connected" in location, f"Expected /connected in redirect, got: {location}"
        assert _EMAIL in location, f"Expected email in redirect, got: {location}"

        # State cookie must be cleared
        assert response.cookies.get("oauth_state") in (None, ""), \
            "oauth_state cookie should be cleared after callback"

        # User must exist in DB
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
            assert tokens["access_token_enc"], "access_token_enc is empty"
            assert tokens["refresh_token_enc"], "refresh_token_enc is empty"
        finally:
            conn.close()

        mock_watch.assert_called_once()
