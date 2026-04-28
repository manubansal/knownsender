"""
Obtain a refresh token for a test Gmail account via a local OAuth flow.

Usage:
    OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... python scripts/get_test_token.py

Opens the browser to Google's consent page. After you approve, the script
prints the refresh token to stdout. Store it as the TEST_GMAIL_REFRESH_TOKEN
GitHub secret.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from google_auth_oauthlib.flow import Flow

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]
REDIRECT_URI = "http://localhost:8765/callback"

captured = {}


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/callback":
            params = parse_qs(parsed.query)
            captured["code"] = params.get("code", [None])[0]
            captured["state"] = params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Done. You can close this tab.</h1>")

    def log_message(self, *args):
        pass  # silence request logs


def main():
    client_id = os.environ.get("OAUTH_CLIENT_ID")
    client_secret = os.environ.get("OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("Set OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET env vars first.")

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )
    flow.redirect_uri = REDIRECT_URI

    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="select_account consent",
        login_hint="claven.test.inbox@gmail.com",
    )

    print(f"\nOpen this URL in an incognito window (sign in as claven.test.inbox@gmail.com):\n")
    print(auth_url)
    print()

    server = HTTPServer(("localhost", 8765), CallbackHandler)
    print("Waiting for callback on http://localhost:8765 ...")
    while "code" not in captured:
        server.handle_request()

    flow.fetch_token(code=captured["code"])
    creds = flow.credentials

    print("\n--- REFRESH TOKEN ---")
    print(creds.refresh_token)
    print("--- EMAIL ---")
    from google.auth.transport.requests import Request as GRequest
    from google.oauth2 import id_token as google_id_token
    id_info = google_id_token.verify_oauth2_token(
        creds.id_token, GRequest(), client_id
    )
    print(id_info["email"])
    print("\nStore the refresh token as GitHub secret: TEST_GMAIL_REFRESH_TOKEN")
    print(f"Store the email as GitHub secret: TEST_GMAIL_EMAIL")


if __name__ == "__main__":
    main()
