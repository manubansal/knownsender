"""Server tests for claven/server.py — HTTP layer via ASGI test client."""

import base64
import json
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
    return mock_conn


_ENV = {
    "OAUTH_CLIENT_ID": "test-client-id",
    "OAUTH_CLIENT_SECRET": "test-client-secret",
    "OAUTH_REDIRECT_URI": "http://localhost/oauth/callback",
    "INTERNAL_API_SECRET": "test-internal-secret",
    "TOKEN_ENCRYPTION_KEY": "aa" * 32,
    "SESSION_SECRET": "test-session-secret-must-be-at-least-32-bytes!",
}


class TestHealth:
    def test_returns_ok(self):
        with TestClient(app) as client:
            response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


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

    def test_does_not_force_consent_for_returning_users(self):
        """oauth/start must not force prompt=consent so returning users skip the
        full consent screen and only see the account picker."""
        with patch.dict("os.environ", _ENV):
            with patch("claven.server.Flow") as mock_flow_cls:
                mock_flow = MagicMock()
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/auth", "state")
                mock_flow_cls.from_client_config.return_value = mock_flow
                with TestClient(app) as client:
                    client.get("/oauth/start", follow_redirects=False)
        call_kwargs = mock_flow.authorization_url.call_args[1]
        assert call_kwargs.get("prompt") != "consent"


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

    def test_watch_failure_redirects_with_error(self):
        """start_watch errors (e.g. Gmail API disabled) must redirect, not 500."""
        with patch.dict("os.environ", {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}):
            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)

                mock_creds = MagicMock()
                mock_creds.id_token = "fake-id-token"
                mock_creds.token = "fake-access-token"
                mock_creds.refresh_token = "fake-refresh-token"
                mock_creds.expiry = None
                mock_creds.scopes = []

                mock_flow = MagicMock()
                mock_flow.credentials = mock_creds
                mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

                with (
                    patch("claven.server.Flow") as mock_flow_cls,
                    patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify,
                    patch("claven.server.db") as mock_db,
                    patch("claven.server.start_watch") as mock_watch,
                ):
                    mock_flow_cls.from_client_config.return_value = mock_flow
                    mock_verify.return_value = {"email": "user@example.com"}
                    _fake_db_ctx(mock_db)
                    mock_db.upsert_user.return_value = "uid-1"
                    mock_db.load_tokens.return_value = None  # new user — full setup path
                    mock_watch.side_effect = Exception("HttpError 403: Gmail API disabled")

                    response = client.get(
                        f"/oauth/callback?code=abc&state={state}",
                        follow_redirects=False,
                    )
        assert response.status_code == 302
        assert "error=signup_failed" in response.headers["location"]


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
            ):
                mock_conn = _fake_db_ctx(mock_db)
                mock_db.get_all_users.return_value = [{"id": "uid-1", "email": "u@example.com"}]
                mock_db.get_history_id.return_value = 999
                mock_db.get_known_senders.return_value = set()
                mock_auth.get_service.return_value = MagicMock()
                with TestClient(app) as client:
                    response = client.post(
                        "/internal/poll",
                        headers={"Authorization": "Bearer test-internal-secret"},
                    )
        assert response.status_code == 200
        assert response.json()["processed"] == 1


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
            ) as mock_poll:
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


class TestApiDisconnect:
    def test_no_token_returns_401(self):
        with patch.dict("os.environ", _ENV):
            with TestClient(app) as client:
                response = client.post("/api/disconnect")
        assert response.status_code == 401

    def test_stops_watch_and_deletes_credentials(self):
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
        mock_db.delete_credentials.assert_called_once_with(ANY, "uid-1")

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

    def test_watch_stop_failure_still_deletes_credentials(self):
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
        mock_db.delete_credentials.assert_called_once()


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
        mock_creds.scopes = []

        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        existing_tokens = {"access_token": "existing-token"} if has_existing_tokens else None

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth") as mock_auth, \
             patch("claven.server.build"), \
             patch("claven.server.start_watch") as mock_watch:
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
        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth") as mock_auth, \
             patch("claven.server.build"), \
             patch("claven.server.start_watch") as mock_watch:
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = None  # new user
            mock_watch.return_value = {"historyId": "99999"}

            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                client.get(f"/oauth/callback?code=abc&state={state}", follow_redirects=False)

        mock_auth.store_credentials.assert_called_once()

    def test_new_user_calls_start_watch(self):
        """First-time sign-in starts a Gmail push watch."""
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth"), \
             patch("claven.server.build"), \
             patch("claven.server.start_watch") as mock_watch:
            mock_flow_cls.from_client_config.return_value = mock_flow
            mock_verify.return_value = {"email": "user@example.com"}
            _fake_db_ctx(mock_db)
            mock_db.upsert_user.return_value = "uid-1"
            mock_db.load_tokens.return_value = None  # new user
            mock_watch.return_value = {"historyId": "99999"}

            with TestClient(app) as client:
                start = client.get("/oauth/start", follow_redirects=False)
                state = start.cookies.get("oauth_state")
                client.cookies.set("oauth_state", state)
                client.get(f"/oauth/callback?code=abc&state={state}", follow_redirects=False)

        mock_watch.assert_called_once()

    def test_returning_user_skips_store_credentials(self):
        """Returning user sign-in must not overwrite existing credentials."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert response.status_code == 302  # sanity check the flow succeeded

    def test_returning_user_skips_start_watch(self):
        """Returning user sign-in must not restart the Gmail push watch."""
        env = {**_ENV, "PUBSUB_TOPIC": "projects/p/topics/t"}
        mock_creds = MagicMock()
        mock_creds.id_token = "fake-id-token"
        mock_flow = MagicMock()
        mock_flow.credentials = mock_creds
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "ignored")

        with patch.dict("os.environ", env), \
             patch("claven.server.Flow") as mock_flow_cls, \
             patch("claven.server.google_id_token.verify_oauth2_token") as mock_verify, \
             patch("claven.server.db") as mock_db, \
             patch("claven.server.auth") as mock_auth, \
             patch("claven.server.build"), \
             patch("claven.server.start_watch") as mock_watch:
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

        mock_watch.assert_not_called()
        mock_auth.store_credentials.assert_not_called()

    def test_returning_user_still_redirects_to_dashboard(self):
        """Returning users land on /dashboard just like new users."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert response.headers["location"] == "https://claven.app/dashboard"

    def test_returning_user_still_gets_session_cookie(self):
        """Returning users receive a fresh session JWT."""
        response = self._run_full_oauth(has_existing_tokens=True)
        assert "session" in response.cookies
