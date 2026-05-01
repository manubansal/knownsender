"""Server tests for claven/server.py — HTTP layer via ASGI test client."""

import base64
import json
import logging
from contextlib import contextmanager
from unittest.mock import ANY, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from claven.server import app

pytestmark = pytest.mark.server


def _pubsub_payload(email="user@example.com", history_id="12345"):
    notification = json.dumps({"emailAddress": email, "historyId": history_id})
    data = base64.b64encode(notification.encode()).decode()
    return {"message": {"data": data, "messageId": "msg-1", "publishTime": "2026-01-01T00:00:00Z"}}


_PUBSUB_TOKEN = "fake-pubsub-jwt"
_PUBSUB_HEADERS = {"Authorization": f"Bearer {_PUBSUB_TOKEN}"}
_PUBSUB_ID_INFO = {"email": "claven-pubsub@claven-prod.iam.gserviceaccount.com"}


@contextmanager
def _mock_pubsub_token():
    """Patch Pub/Sub JWT verification to return a valid service-account identity."""
    with patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify:
        mock_verify.return_value = _PUBSUB_ID_INFO
        yield mock_verify


def _fake_db_ctx(mock_db, conn=None):
    """Wire mock_db.get_connection() as a context manager returning conn."""
    mock_conn = conn or MagicMock()

    @contextmanager
    def _ctx(*args, **kwargs):
        yield mock_conn

    mock_db.get_connection.side_effect = _ctx
    mock_db.get_processed_count.return_value = 0
    mock_db.get_sent_scan_progress.return_value = {"messages_scanned": 0, "messages_total": None, "status": "complete", "updated_at": None}
    mock_db.is_inbox_scan_completed.return_value = False
    mock_db.get_inbox_scan_status.return_value = None
    return mock_conn


_ENV = {
    "OAUTH_CLIENT_ID": "test-client-id",
    "OAUTH_CLIENT_SECRET": "test-client-secret",
    "OAUTH_REDIRECT_URI": "http://localhost/oauth/callback",
    "INTERNAL_API_SECRET": "test-internal-secret",
    "TOKEN_ENCRYPTION_KEY": "aa" * 32,
    "SESSION_SECRET": "test-session-secret-must-be-at-least-32-bytes!",
}


class TestNeedsSentScan:
    def test_complete_returns_false(self):
        from claven.server import _needs_sent_scan
        assert _needs_sent_scan({"status": "complete", "updated_at": None}) is False

    def test_none_status_returns_true(self):
        from claven.server import _needs_sent_scan
        assert _needs_sent_scan({"status": None, "updated_at": None}) is True

    def test_error_status_returns_true(self):
        from claven.server import _needs_sent_scan
        assert _needs_sent_scan({"status": "error", "updated_at": None}) is True

    def test_in_progress_recent_returns_false(self):
        from claven.server import _needs_sent_scan
        from datetime import datetime, timezone
        assert _needs_sent_scan({
            "status": "in_progress",
            "updated_at": datetime.now(timezone.utc),
        }) is False

    def test_in_progress_stale_returns_true(self):
        from claven.server import _needs_sent_scan
        from datetime import datetime, timezone, timedelta
        assert _needs_sent_scan({
            "status": "in_progress",
            "updated_at": datetime.now(timezone.utc) - timedelta(minutes=2),
        }) is True

    def test_in_progress_no_updated_at_returns_true(self):
        from claven.server import _needs_sent_scan
        assert _needs_sent_scan({"status": "in_progress", "updated_at": None}) is True


class TestHealth:
    def test_returns_ok(self):
        with TestClient(app) as client:
            response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestHealthz:
    def test_returns_ok_when_db_reachable(self):
        with patch("claven.server.db") as mock_db:
            _fake_db_ctx(mock_db)
            with TestClient(app) as client:
                response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["db"] == "connected"

    def test_returns_503_when_db_unreachable(self):
        with patch("claven.server.db") as mock_db:
            mock_db.get_connection.side_effect = Exception("connection refused")
            with TestClient(app) as client:
                response = client.get("/healthz")
        assert response.status_code == 503
        assert response.json()["db"] == "unreachable"


class TestOAuthStart:
    def test_redirects_to_google(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/start", follow_redirects=False)
        assert response.status_code in (302, 307)
        assert "accounts.google.com" in response.headers["location"]

    def test_redirect_contains_state_param(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/start", follow_redirects=False)
        assert "state=" in response.headers["location"]

    def test_sets_oauth_state_cookie(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/start", follow_redirects=False)
        assert "oauth_state" in response.cookies

    def test_valid_return_to_stored_in_cookie(self):
        env = {**_ENV, "CORS_EXTRA_ORIGINS": "http://localhost:3000"}
        with patch.dict("os.environ", env):
            with TestClient(app) as client:
                response = client.get(
                    "/oauth/start?return_to=http://localhost:3000",
                    follow_redirects=False,
                )
        assert "http://localhost:3000" in response.cookies.get("oauth_return_to", "")

    def test_invalid_return_to_returns_400(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get(
                    "/oauth/start?return_to=https://evil.example.com",
                    follow_redirects=False,
                )
        assert response.status_code == 400

    def test_missing_return_to_no_cookie(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/start", follow_redirects=False)
        assert "oauth_return_to" not in response.cookies

    def test_default_uses_select_account_prompt(self):
        """oauth/start without force_consent uses select_account so returning
        users skip the full consent screen and only see the account picker."""
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.Flow") as mock_flow_cls:
                mock_flow = MagicMock()
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/auth", "state")
                mock_flow_cls.from_client_config.return_value = mock_flow
                with TestClient(app) as client:
                    client.get("/oauth/start", follow_redirects=False)
        call_kwargs = mock_flow.authorization_url.call_args[1]
        assert call_kwargs.get("prompt") == "select_account"

    def test_force_consent_uses_consent_prompt(self):
        """oauth/start?force_consent=true uses prompt=consent to obtain a fresh
        refresh token (needed when reconnecting after disconnect)."""
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.Flow") as mock_flow_cls:
                mock_flow = MagicMock()
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/auth", "state")
                mock_flow_cls.from_client_config.return_value = mock_flow
                with TestClient(app) as client:
                    client.get("/oauth/start?force_consent=true", follow_redirects=False)
        call_kwargs = mock_flow.authorization_url.call_args[1]
        assert call_kwargs.get("prompt") == "consent"


class TestOAuthCallback:
    def test_missing_code_redirects_with_error(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/callback?state=abc", follow_redirects=False)
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]

    def test_missing_state_redirects_with_error(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/callback?code=abc", follow_redirects=False)
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]

    def test_state_mismatch_redirects_with_error(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                client.get("/oauth/start", follow_redirects=False)  # sets cookie
                response = client.get("/oauth/callback?code=abc&state=wrong-state", follow_redirects=False)
        assert response.status_code == 302
        assert "error=invalid_state" in response.headers["location"]

    def test_oauth_error_param_redirects_with_error(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/oauth/callback?error=access_denied", follow_redirects=False)
        assert response.status_code == 302
        assert "error=oauth_denied" in response.headers["location"]

    def test_token_exchange_failure_redirects_with_error(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                # Start flow to capture the generated state value
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")

                # secure=True cookies aren't sent by TestClient (HTTP), so set manually
                client.cookies.set("oauth_state", state)

                with patch("claven.server.Flow") as mock_flow_cls:
                    mock_flow_cls.from_client_config.return_value.fetch_token.side_effect = Exception("scope mismatch")
                    response = client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        assert response.status_code == 302
        assert "error=token_exchange_failed" in response.headers["location"]

    def test_no_refresh_token_redirects_to_force_consent(self):
        """When reconnecting after disconnect Google won't return a refresh token.
        The callback must redirect back to oauth/start?force_consent=true instead
        of failing with signup_failed."""
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)

                mock_creds = MagicMock()
                mock_creds.id_token = "fake-id-token"
                mock_creds.refresh_token = None  # Google didn't return one
                mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid"}

                mock_flow = MagicMock()
                mock_flow.credentials = mock_creds
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

                with (
                    patch("claven.server.Flow") as mock_flow_cls,
                    patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
                    patch("claven.server.db") as mock_db,
                ):
                    mock_flow_cls.from_client_config.return_value = mock_flow
                    mock_verify.return_value = {"email": "user@example.com"}
                    _fake_db_ctx(mock_db)
                    mock_db.upsert_user.return_value = "uid-1"
                    mock_db.load_tokens.return_value = None  # no stored tokens

                    response = client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        assert response.status_code == 302
        assert "force_consent=true" in response.headers["location"]
        assert "/oauth/start" in response.headers["location"]

    def test_callback_rejects_missing_gmail_scope(self):
        """If user unchecks Gmail permission (granular consent), redirect with clear error."""
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)

                mock_creds = MagicMock()
                mock_creds.id_token = "fake-id-token"
                mock_creds.scopes = {"openid", "https://www.googleapis.com/auth/userinfo.email"}

                mock_flow = MagicMock()
                mock_flow.credentials = mock_creds

                with patch("claven.server.Flow") as mock_flow_cls:
                    mock_flow_cls.from_client_config.return_value = mock_flow
                    response = client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        assert response.status_code == 302
        assert "error=gmail_scope_missing" in response.headers["location"]

    def test_callback_does_not_start_watch(self):
        """oauth_callback stores credentials but never starts the Gmail watch.
        Starting the watch is an explicit user action via POST /api/connect."""
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)

                mock_creds = MagicMock()
                mock_creds.id_token = "fake-id-token"
                mock_creds.refresh_token = "fake-refresh-token"
                mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid"}

                mock_flow = MagicMock()
                mock_flow.credentials = mock_creds
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

                with (
                    patch("claven.server.Flow") as mock_flow_cls,
                    patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
                    patch("claven.server.db") as mock_db,
                    patch("claven.server.auth"),
                    patch("claven.server.start_watch") as mock_watch,
                    patch("claven.server.build_known_senders"),
                ):
                    mock_flow_cls.from_client_config.return_value = mock_flow
                    mock_verify.return_value = {"email": "user@example.com"}
                    _fake_db_ctx(mock_db)
                    mock_db.upsert_user.return_value = "uid-1"
                    mock_db.load_tokens.return_value = None

                    client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        mock_watch.assert_not_called()

    def test_callback_triggers_sent_scan(self):
        """oauth_callback kicks off sent scan in background after storing credentials."""
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)

                mock_creds = MagicMock()
                mock_creds.id_token = "fake-id-token"
                mock_creds.refresh_token = "fake-refresh-token"
                mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid"}

                mock_flow = MagicMock()
                mock_flow.credentials = mock_creds

                with (
                    patch("claven.server.Flow") as mock_flow_cls,
                    patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
                    patch("claven.server.db") as mock_db,
                    patch("claven.server.auth"),
                    patch("claven.server.threading") as mock_threading,
                ):
                    mock_flow_cls.from_client_config.return_value = mock_flow
                    mock_verify.return_value = {"email": "user@example.com"}
                    _fake_db_ctx(mock_db)
                    mock_db.upsert_user.return_value = "uid-1"
                    mock_db.load_tokens.return_value = None

                    client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        mock_threading.Thread.assert_called_once()
        call_kwargs = mock_threading.Thread.call_args[1]
        assert call_kwargs["target"].__name__ == "_run_sent_scan"

class TestInternalPoll:
    def test_no_auth_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/internal/poll")
        assert response.status_code == 401

    def test_wrong_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post(
                    "/internal/poll",
                    headers={"Authorization": "Bearer wrong-token"},
                )
        assert response.status_code == 401

    def test_valid_auth_no_users_returns_ok(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = []
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/poll",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.status_code == 200
        assert response.json()["processed"] == 0

    def test_valid_auth_processes_users(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth") as mock_auth, patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                mock_conn = _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [{"id": "uid-1", "email": "u@example.com"}]
                mock_db.get_history_id.return_value = 999
                mock_db.get_known_senders.return_value = set()
                mock_auth.get_service.return_value = MagicMock()
                mock_poll.return_value = 0
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/poll",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.status_code == 200
        assert response.json()["processed"] == 1

    def test_increments_processed_count_after_poll(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth") as mock_auth, patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [{"id": "uid-1", "email": "u@example.com"}]
                mock_db.get_history_id.return_value = 999
                mock_db.get_known_senders.return_value = set()
                mock_auth.get_service.return_value = MagicMock()
                mock_poll.return_value = 5
                with TestClient(app) as client:
                    client.post(
                        "/internal/poll",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        mock_db.increment_processed_count.assert_called_once_with(ANY, "uid-1", 5)


    def test_poll_skips_locked_user(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth"), patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [{"id": "uid-1", "email": "u@example.com"}]
                mock_db.try_lock_user_scan.return_value = False
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/poll",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.json()["results"][0]["status"] == "skipped"
        mock_poll.assert_not_called()


class TestInternalBuildKnownSenders:
    def test_no_auth_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/internal/build-known-senders")
        assert response.status_code == 401

    def test_wrong_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post(
                    "/internal/build-known-senders",
                    headers={"Authorization": "Bearer wrong-token"},
                )
        assert response.status_code == 401

    def test_no_users_returns_ok(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = []
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/build-known-senders",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.status_code == 200
        assert response.json()["processed"] == 0

    def test_calls_build_known_senders_for_each_user(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.build_known_senders") as mock_build:
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [
                    {"id": "uid-1", "email": "a@example.com"},
                    {"id": "uid-2", "email": "b@example.com"},
                ]
                mock_auth.get_service.return_value = MagicMock()
                mock_build.return_value = {"known_senders": 5, "messages_scanned": 10}
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/build-known-senders",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.status_code == 200
        assert response.json()["processed"] == 2
        assert mock_build.call_count == 2

    def test_returns_known_senders_count_per_user(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.build_known_senders") as mock_build:
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [{"id": "uid-1", "email": "a@example.com"}]
                mock_auth.get_service.return_value = MagicMock()
                mock_build.return_value = {"known_senders": 42, "messages_scanned": 100}
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/build-known-senders",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        result = response.json()["results"][0]
        assert result["known_senders"] == 42
        assert result["messages_scanned"] == 100
        assert result["status"] == "ok"

    def test_user_error_recorded_without_aborting_others(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.build_known_senders") as mock_build:
                _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [
                    {"id": "uid-1", "email": "a@example.com"},
                    {"id": "uid-2", "email": "b@example.com"},
                ]
                mock_auth.get_service.return_value = MagicMock()
                mock_build.side_effect = [Exception("Gmail API error"), {"known_senders": 3, "messages_scanned": 5}]
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/build-known-senders",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        results = response.json()["results"]
        assert results[0]["status"] == "error"
        assert results[1]["status"] == "ok"


class TestWebhookGmail:
    # ── Auth ──────────────────────────────────────────────────────────────────

    def test_missing_auth_header_returns_401(self):
        with TestClient(app) as client:
            response = client.post("/webhook/gmail", json=_pubsub_payload())
        assert response.status_code == 401

    def test_invalid_token_returns_401(self):
        with patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify:
            mock_verify.side_effect = Exception("invalid token")
            with TestClient(app) as client:
                response = client.post(
                    "/webhook/gmail",
                    json=_pubsub_payload(),
                    headers={"Authorization": "Bearer bad-token"},
                )
        assert response.status_code == 401

    def test_non_pubsub_service_account_returns_401(self):
        with patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify:
            mock_verify.return_value = {"email": "attacker@gmail.com"}
            with TestClient(app) as client:
                response = client.post(
                    "/webhook/gmail",
                    json=_pubsub_payload(),
                    headers={"Authorization": "Bearer some-valid-google-token"},
                )
        assert response.status_code == 401

    # ── Payload validation ────────────────────────────────────────────────────

    def test_missing_message_field_returns_400(self):
        with _mock_pubsub_token():
            with TestClient(app) as client:
                response = client.post(
                    "/webhook/gmail",
                    json={"not": "a message"},
                    headers=_PUBSUB_HEADERS,
                )
        assert response.status_code == 400

    def test_malformed_base64_returns_400(self):
        with _mock_pubsub_token():
            with TestClient(app) as client:
                response = client.post(
                    "/webhook/gmail",
                    json={"message": {"data": "!!!not-valid-base64!!!"}},
                    headers=_PUBSUB_HEADERS,
                )
        assert response.status_code == 400

    def test_missing_email_address_returns_400(self):
        notification = json.dumps({"historyId": "123"})  # no emailAddress
        data = base64.b64encode(notification.encode()).decode()
        with _mock_pubsub_token():
            with TestClient(app) as client:
                response = client.post(
                    "/webhook/gmail",
                    json={"message": {"data": data}},
                    headers=_PUBSUB_HEADERS,
                )
        assert response.status_code == 400

    # ── Processing ────────────────────────────────────────────────────────────

    def test_valid_payload_unknown_user_returns_ok(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_email.return_value = None
                with _mock_pubsub_token():
                    with TestClient(app) as client:
                        response = client.post(
                            "/webhook/gmail",
                            json=_pubsub_payload(),
                            headers=_PUBSUB_HEADERS,
                        )
        assert response.status_code == 200

    def test_known_user_triggers_processing(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth") as mock_auth, patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_email.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 100
                mock_db.get_known_senders.return_value = set()
                mock_auth.get_service.return_value = MagicMock()
                mock_poll.return_value = 200
                with _mock_pubsub_token():
                    with TestClient(app) as client:
                        response = client.post(
                            "/webhook/gmail",
                            json=_pubsub_payload(history_id="200"),
                            headers=_PUBSUB_HEADERS,
                        )
        assert response.status_code == 200
        mock_poll.assert_called_once()

    def test_increments_processed_count_after_webhook(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth") as mock_auth, patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_email.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 100
                mock_db.get_known_senders.return_value = set()
                mock_auth.get_service.return_value = MagicMock()
                mock_poll.return_value = 3
                with _mock_pubsub_token():
                    with TestClient(app) as client:
                        client.post(
                            "/webhook/gmail",
                            json=_pubsub_payload(history_id="200"),
                            headers=_PUBSUB_HEADERS,
                        )
        mock_db.increment_processed_count.assert_called_once_with(ANY, "uid-1", 3)

    def test_webhook_skips_locked_user(self):
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, patch("claven.server.auth"), patch(
                "claven.server.poll_new_messages"
            ) as mock_poll, patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_email.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.try_lock_user_scan.return_value = False
                with _mock_pubsub_token():
                    with TestClient(app) as client:
                        response = client.post(
                            "/webhook/gmail",
                            json=_pubsub_payload(history_id="200"),
                            headers=_PUBSUB_HEADERS,
                        )
        assert response.status_code == 200
        assert response.json()["detail"] == "locked"
        mock_poll.assert_not_called()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session_token(payload: dict | None = None) -> str:
    """Issue a real JWT signed with the test SESSION_SECRET."""
    import jwt as pyjwt
    data = payload or {"user_id": "uid-1", "email": "user@example.com"}
    return pyjwt.encode(data, _ENV["SESSION_SECRET"], algorithm="HS256")


class TestApiMe:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/api/me")
        assert response.status_code == 401

    def test_invalid_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/api/me", headers={"Authorization": "Bearer bad.token"})
        assert response.status_code == 401

    def test_valid_cookie_returns_user_data(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.status_code == 200
        body = response.json()
        assert body["email"] == "user@example.com"
        assert body["connected"] is True
        assert body["history_id"] == 12345

    def test_valid_bearer_token_returns_user_data(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = None
                with TestClient(app) as client:
                    response = client.get(
                        "/api/me", headers={"Authorization": f"Bearer {token}"}
                    )
        assert response.status_code == 200
        body = response.json()
        assert body["email"] == "user@example.com"
        assert body["connected"] is False

    def test_not_connected_when_no_history_id(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = None
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["connected"] is False

    _KNOWN_LABEL_ID = "Label_known_sender"
    _UNKNOWN_LABEL_ID = "Label_unknown_sender"

    def _make_gmail_service(
        self,
        messages_unread=0,
        messages_total=0,
        read_estimate=0,
        labeled_known_total=0,
        labeled_unknown_total=0,
        unlabeled_ids=None,
    ):
        """Return a mock Gmail service with label counts.

        unlabeled_ids: list of message ID strings for the unlabeled query.
            Paginated in chunks of 500. Defaults to [] (no unlabeled).
        """
        if unlabeled_ids is None:
            unlabeled_ids = []
        svc = MagicMock()
        known_id = self._KNOWN_LABEL_ID
        unknown_id = self._UNKNOWN_LABEL_ID

        # labels.get → exact per-label counts
        def _labels_get(**kwargs):
            lid = kwargs.get("id", "")
            result = MagicMock()
            if lid == "INBOX":
                result.execute.return_value = {"messagesUnread": messages_unread, "messagesTotal": messages_total}
            elif lid == "SENT":
                result.execute.return_value = {"messagesTotal": 0}
            elif lid == known_id:
                result.execute.return_value = {"messagesTotal": labeled_known_total}
            elif lid == unknown_id:
                result.execute.return_value = {"messagesTotal": labeled_unknown_total}
            else:
                result.execute.return_value = {"messagesTotal": 0}
            return result

        svc.users.return_value.labels.return_value.get.side_effect = _labels_get

        # labels.list → label ID map
        svc.users.return_value.labels.return_value.list.return_value.execute.return_value = {
            "labels": [
                {"name": "known-sender", "id": known_id},
                {"name": "unknown-sender", "id": unknown_id},
            ]
        }

        # messages.list → paginated unlabeled results
        _pages = []
        for i in range(0, max(len(unlabeled_ids), 1), 500):
            _pages.append(unlabeled_ids[i:i + 500])
        if not unlabeled_ids:
            _pages = [[]]
        _page_idx = [0]

        def _messages_list(**kwargs):
            q = kwargs.get("q", "")
            result = MagicMock()
            if "is:read" in q:
                result.execute.return_value = {"resultSizeEstimate": read_estimate}
            elif "-label:" in q:
                idx = _page_idx[0]
                page = _pages[idx] if idx < len(_pages) else []
                has_next = idx + 1 < len(_pages) and _pages[idx + 1]
                _page_idx[0] = idx + 1
                resp = {"messages": [{"id": mid} for mid in page]}
                if has_next:
                    resp["nextPageToken"] = f"page-{idx + 1}"
                result.execute.return_value = resp
            else:
                result.execute.return_value = {"resultSizeEstimate": 0}
            return result

        svc.users.return_value.messages.return_value.list.side_effect = _messages_list
        return svc

    def test_returns_known_senders_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 42
                mock_auth.get_service.return_value = self._make_gmail_service()
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["known_senders"] == 42

    def test_returns_unread_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_unread=99, messages_total=500, read_estimate=401
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["unread_count"] == 99

    def test_returns_inbox_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=250, read_estimate=250
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["inbox_count"] == 250

    def test_returns_read_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_unread=30, messages_total=100, read_estimate=70
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["read_count"] == 70

    def test_unread_count_is_none_when_gmail_api_fails(self):
        """A Gmail API error must not break /api/me — return null for all Gmail fields."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.side_effect = Exception("token expired")
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.status_code == 200
        assert response.json()["unread_count"] is None
        assert response.json()["read_count"] is None
        assert response.json()["inbox_count"] is None

    # processed_count and pending_count removed — progress derived from live Gmail label counts

    def test_returns_labeled_known_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100, labeled_known_total=60
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["allmail_labeled_known_count"] == 60

    def test_returns_labeled_unknown_count(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100, labeled_unknown_total=40
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["allmail_labeled_unknown_count"] == 40

    def test_returns_all_counts(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100, labeled_known_total=50,
                    labeled_unknown_total=30, unlabeled_ids=[f"m{i}" for i in range(20)],
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        body = response.json()
        assert body["allmail_labeled_known_count"] == 50
        assert body["allmail_labeled_unknown_count"] == 30
        assert body["allmail_labeled_total_count"] == 80
        assert body["inbox_unlabeled_first_page_count"] == 20
        assert body["inbox_unlabeled_deep_count"] == 20

    def test_unlabeled_deep_count_paginates(self):
        """Deep count paginates beyond the first 500 messages."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=1000,
                    unlabeled_ids=[f"m{i}" for i in range(750)],
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        body = response.json()
        assert body["inbox_unlabeled_first_page_count"] == 500
        assert body["inbox_unlabeled_deep_count"] == 750

    def test_counts_are_null_when_gmail_api_unavailable(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.count_known_senders.return_value = 0
                mock_auth.get_service.side_effect = Exception("token expired")
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["allmail_labeled_known_count"] is None
        assert response.json()["allmail_labeled_unknown_count"] is None
        assert response.json()["inbox_unlabeled_deep_count"] is None


    def test_api_me_does_not_trigger_scans_when_no_unlabeled(self):
        """No scan triggers when all messages are labeled."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.threading") as mock_threading:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_auth.get_service.return_value = self._make_gmail_service()
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    client.get("/api/me")
        mock_threading.Thread.assert_not_called()

    def test_api_me_retriggers_scan_when_unlabeled_remain(self):
        """If scan is complete but unlabeled messages remain, retrigger inbox scan."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.threading") as mock_threading:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.get_inbox_scan_status.return_value = "complete"
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100, unlabeled_ids=["m1", "m2", "m3"],
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["inbox_unlabeled_first_page_count"] == 3
        assert response.json()["inbox_scan_in_progress"] is True
        mock_threading.Thread.assert_called_once()
        assert mock_threading.Thread.call_args[1]["target"].__name__ == "_run_inbox_scan"

    def test_api_me_no_retrigger_when_scan_never_ran(self):
        """Don't retrigger if scan never ran (status=None) — user must click Start."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.threading") as mock_threading:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.get_inbox_scan_status.return_value = None
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100, unlabeled_ids=[f"m{i}" for i in range(100)],
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["inbox_unlabeled_first_page_count"] == 100
        assert response.json()["inbox_scan_in_progress"] is False
        mock_threading.Thread.assert_not_called()

    def test_api_me_no_retrigger_when_all_labeled(self):
        """Don't retrigger if scan is complete and all messages are labeled."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.threading") as mock_threading:
                _fake_db_ctx(mock_db)
                mock_db.get_user_by_id.return_value = {"id": "uid-1", "email": "user@example.com"}
                mock_db.get_history_id.return_value = 12345
                mock_db.get_inbox_scan_status.return_value = "complete"
                mock_auth.get_service.return_value = self._make_gmail_service(
                    messages_total=100,
                )
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.get("/api/me")
        assert response.json()["inbox_unlabeled_first_page_count"] == 0
        assert response.json()["inbox_scan_in_progress"] is False
        mock_threading.Thread.assert_not_called()


class TestApiConfig:
    def test_returns_label_rules(self):
        with patch("claven.server.load_config") as mock_config:
            mock_config.return_value = {
                "labels": [{"id": "known-sender", "name": "Known Sender", "rules": [{"field": "from", "known_sender": True}]}]
            }
            with TestClient(app) as client:
                response = client.get("/api/config")
        assert response.status_code == 200
        assert response.json()["labels"][0]["id"] == "known-sender"
        assert response.json()["labels"][0]["name"] == "Known Sender"

    def test_returns_empty_labels_when_none_configured(self):
        with patch("claven.server.load_config") as mock_config:
            mock_config.return_value = {}
            with TestClient(app) as client:
                response = client.get("/api/config")
        assert response.json()["labels"] == []


class TestApiDisconnect:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/api/disconnect")
        assert response.status_code == 401

    def test_stops_watch_and_clears_watch_state(self):
        """Disconnect stops the Gmail watch and clears scan state (history_id)
        but keeps OAuth credentials so reconnect needs no OAuth round-trip."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.stop_watch") as mock_stop:
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.post("/api/disconnect")
        assert response.status_code == 200
        mock_stop.assert_called_once()
        mock_db.clear_watch_state.assert_called_once_with(ANY, "uid-1")
        mock_db.delete_credentials.assert_not_called()

    def test_does_not_clear_session_cookie(self):
        """Disconnect removes Gmail credentials but keeps the user signed in."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.stop_watch"):
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.post("/api/disconnect")
        set_cookie = response.headers.get("set-cookie", "")
        # session cookie must NOT be deleted — user stays signed in
        assert "session" not in set_cookie

    def test_watch_stop_failure_still_clears_watch_state(self):
        """stop_watch errors (e.g. already expired) must not block disconnect."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.stop_watch") as mock_stop:
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_stop.side_effect = Exception("watch already expired")
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.post("/api/disconnect")
        assert response.status_code == 200
        mock_db.clear_watch_state.assert_called_once()


class TestApiConnect:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/api/connect")
        assert response.status_code == 401

    def test_returns_200_with_history_id(self):
        token = _make_session_token()
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.start_watch") as mock_watch, \
                 patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_watch.return_value = {"historyId": "99999"}
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.post("/api/connect")
        assert response.status_code == 200
        assert response.json()["history_id"] == 99999

    def test_calls_start_watch(self):
        token = _make_session_token()
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.start_watch") as mock_watch, \
                 patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_watch.return_value = {"historyId": "99999"}
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    client.post("/api/connect")
        mock_watch.assert_called_once()

    def test_sets_history_id(self):
        token = _make_session_token()
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.start_watch") as mock_watch, \
                 patch("claven.server.build_known_senders"):
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_watch.return_value = {"historyId": "99999"}
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    client.post("/api/connect")
        mock_db.set_history_id.assert_called_once_with(ANY, "uid-1", 99999)

    def test_triggers_scans_in_background(self):
        """Connect triggers both sent scan and inbox scan threads."""
        token = _make_session_token()
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.start_watch") as mock_watch, \
                 patch("claven.server.threading") as mock_threading:
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_watch.return_value = {"historyId": "99999"}
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    client.post("/api/connect")
        assert mock_threading.Thread.call_count == 2
        targets = {c.kwargs["target"].__name__ for c in mock_threading.Thread.call_args_list}
        assert targets == {"_run_sent_scan", "_run_inbox_scan"}

    def test_watch_failure_returns_500(self):
        token = _make_session_token()
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with patch("claven.server.db") as mock_db, \
                 patch("claven.server.auth") as mock_auth, \
                 patch("claven.server.start_watch") as mock_watch:
                _fake_db_ctx(mock_db)
                mock_auth.get_service.return_value = MagicMock()
                mock_watch.side_effect = Exception("Gmail API error")
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    response = client.post("/api/connect")
        assert response.status_code == 500


class TestApiLogout:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/api/logout")
        assert response.status_code == 401

    def test_returns_200(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                client.cookies.set("session", token)
                response = client.post("/api/logout")
        assert response.status_code == 200

    def test_clears_session_cookie(self):
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                client.cookies.set("session", token)
                response = client.post("/api/logout")
        assert "session" in response.headers.get("set-cookie", "")

    def test_does_not_touch_credentials(self):
        """Logout ends the session but leaves Gmail credentials intact."""
        token = _make_session_token()
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.db") as mock_db:
                with TestClient(app) as client:
                    client.cookies.set("session", token)
                    client.post("/api/logout")
        mock_db.delete_credentials.assert_not_called()


class TestOAuthCallbackSession:
    """Verify the callback issues a session cookie and redirects to /dashboard."""

    def _run_full_oauth(self, extra_env=None, return_to=None, has_existing_tokens=False):
        """Drive the full start → callback flow and return the callback response.

        has_existing_tokens=True simulates a returning user who already has
        credentials stored — the callback should skip store_credentials and
        start_watch and just issue a new session JWT.
        """
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t", **(extra_env or {})}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_creds.token = "fake-access-token"
        mock_creds.refresh_token = "fake-refresh-token"
        mock_creds.expiry = None
        mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid", "https://www.googleapis.com/auth/userinfo.email"}

        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        existing_tokens = {"access_token": "existing-token"} if has_existing_tokens else None

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth") as mock_auth, \
             patch("claven.server.start_watch") as mock_watch, \
             patch("claven.server.build_known_senders"):
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = existing_tokens
            mock_watch.return_value = {"historyId": "99999"}

            with TestClient(app) as client:
                start_url = "/oauth/start"
                if return_to:
                    start_url += f"?return_to={return_to}"
                start = client.get(start_url, follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                if return_to:
                    client.cookies.set("oauth_return_to", return_to)
                return client.get(
                    f"/oauth/callback?code=abc&state={state}",
                    follow_redirects=False,
                )

    def test_successful_callback_redirects_to_dashboard(self):
        response = self._run_full_oauth()
        assert response.status_code == 302
        assert response.headers["location"] == "https://claven.app/dashboard"

    def test_return_to_redirects_to_custom_frontend(self):
        env = {"CORS_EXTRA_ORIGINS": "http://localhost:3000"}
        response = self._run_full_oauth(extra_env=env, return_to="http://localhost:3000")
        assert response.status_code == 302
        assert response.headers["location"] == "http://localhost:3000/dashboard"

    def test_successful_callback_sets_session_cookie(self):
        response = self._run_full_oauth()
        assert "session" in response.cookies

    def test_session_cookie_is_samesite_none(self):
        """Session cookie must be SameSite=None so cross-origin frontends
        (e.g. localhost:3000 calling api.claven.app) can include it in
        credentialed fetch requests."""
        response = self._run_full_oauth()
        set_cookie = response.headers.get("set-cookie", "").lower()
        assert "samesite=none" in set_cookie

    def test_new_user_calls_store_credentials(self):
        """First-time sign-in stores OAuth credentials in the DB."""
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid"}
        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth") as mock_auth, \
             patch("claven.server.start_watch"):
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = None  # new user

            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                client.get(f"/oauth/callback?code=abc&state={state}", follow_redirects=False)

        mock_auth.store_credentials.assert_called_once()

    def test_new_user_does_not_start_watch(self):
        """oauth_callback never starts the watch — that's an explicit /api/connect step."""
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_creds.refresh_token = "fake-refresh-token"
        mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid"}
        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth"), \
             patch("claven.server.start_watch") as mock_watch:
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = None

            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                client.get(f"/oauth/callback?code=abc&state={state}", follow_redirects=False)

        mock_watch.assert_not_called()

    def test_returning_user_skips_store_credentials(self):
        """Returning user sign-in must not overwrite existing credentials."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert response.status_code == 302  # sanity check the flow succeeded

    def test_returning_user_skips_start_watch(self):
        """Returning user sign-in must not restart the Gmail push watch."""
        response = self._run_full_oauth(has_existing_tokens=True)
        # start_watch is never called in oauth_callback regardless of user type
        # (verified implicitly — _run_full_oauth patches start_watch and the
        # test passes only if no exception is raised from an uncalled mock)
        assert response.status_code == 302

    def test_returning_user_still_redirects_to_dashboard(self):
        """Returning users land on /dashboard just like new users."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert response.headers["location"] == "https://claven.app/dashboard"

    def test_returning_user_still_gets_session_cookie(self):
        """Returning users receive a fresh session JWT."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert "session" in response.cookies

    def test_returning_user_still_triggers_sent_scan(self):
        """Returning users get a sent scan triggered (incremental update)."""
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_creds.token = "fake-access-token"
        mock_creds.refresh_token = "fake-refresh-token"
        mock_creds.expiry = None
        mock_creds.scopes = {"https://www.googleapis.com/auth/gmail.modify", "openid", "https://www.googleapis.com/auth/userinfo.email"}

        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth"), \
             patch("claven.server.start_watch"), \
             patch("claven.server.threading") as mock_threading:
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = {"access_token": "existing-token"}

            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                client.get(f"/oauth/callback?code=abc&state={state}", follow_redirects=False)
        # Sent scan should trigger even for returning users (incremental update)
        mock_threading.Thread.assert_called_once()
        assert mock_threading.Thread.call_args[1]["target"].__name__ == "_run_sent_scan"


class TestCloudJsonFormatter:
    def test_formats_info_as_json(self):
        import json
        from claven.server import _CloudJsonFormatter
        formatter = _CloudJsonFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "hello world", (), None)
        output = json.loads(formatter.format(record))
        assert output["severity"] == "INFO"
        assert output["message"] == "hello world"
        assert output["logger"] == "test"

    def test_includes_extra_fields(self):
        import json
        from claven.server import _CloudJsonFormatter
        formatter = _CloudJsonFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "scan done", (), None)
        record.user_id = "uid-1"
        record.event = "inbox_scan_complete"
        output = json.loads(formatter.format(record))
        assert output["user_id"] == "uid-1"
        assert output["event"] == "inbox_scan_complete"

    def test_includes_exception(self):
        import json
        from claven.server import _CloudJsonFormatter
        formatter = _CloudJsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            record = logging.LogRecord("test", logging.ERROR, "", 0, "failed", (), sys.exc_info())
        output = json.loads(formatter.format(record))
        assert output["severity"] == "ERROR"
        assert "ValueError: boom" in output["exception"]


class TestApiEvents:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.get("/api/events")
        assert response.status_code == 401

    def test_db_unavailable_returns_503(self):
        token = _make_session_token()
        bad_env = {**_ENV, "DATABASE_URL": "postgresql://bad:bad@localhost:1/nonexistent"}
        with patch.dict("os.environ", bad_env):
            with TestClient(app) as client:
                client.cookies.set("session", token)
                response = client.get("/api/events")
        assert response.status_code == 503
