import os
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "token.json"
CREDENTIALS_PATH = "credentials.json"


def get_service():
    """Authenticate and return a Gmail API service instance."""
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_PATH):
                raise FileNotFoundError(
                    f"{CREDENTIALS_PATH} not found. Download it from "
                    "Google Cloud Console (APIs & Services > Credentials)."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as token_file:
            token_file.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def get_profile(service):
    """Get the user's Gmail profile (includes historyId)."""
    return service.users().getProfile(userId="me").execute()


def list_messages(service, query="in:inbox", max_results=100):
    """List message IDs matching a query."""
    results = (
        service.users()
        .messages()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )
    return results.get("messages", [])


def list_history(service, start_history_id, label_id="INBOX"):
    """List history records since a given history ID."""
    records = []
    request = (
        service.users()
        .history()
        .list(userId="me", startHistoryId=start_history_id, labelId=label_id)
    )
    while request:
        response = request.execute()
        records.extend(response.get("history", []))
        request = (
            service.users()
            .history()
            .list_next(previous_request=request, previous_response=response)
        )
    return records


def get_message(service, message_id, format="metadata", metadata_headers=None):
    """Get a single message. Returns metadata by default."""
    kwargs = {"userId": "me", "id": message_id, "format": format}
    if metadata_headers:
        kwargs["metadataHeaders"] = metadata_headers
    return service.users().messages().get(**kwargs).execute()


def get_message_headers(service, message_id):
    """Get From, Subject, and To headers for a message."""
    msg = get_message(
        service,
        message_id,
        format="metadata",
        metadata_headers=["From", "Subject", "To"],
    )
    headers = {}
    for header in msg.get("payload", {}).get("headers", []):
        name = header["name"].lower()
        if name in ("from", "subject", "to"):
            headers[name] = header["value"]
    return headers, msg.get("labelIds", [])


def ensure_label_exists(service, label_name):
    """Create a label if it doesn't exist. Returns the label ID."""
    results = service.users().labels().list(userId="me").execute()
    for label in results.get("labels", []):
        if label["name"].lower() == label_name.lower():
            return label["id"]
    created = (
        service.users()
        .labels()
        .create(
            userId="me",
            body={
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        .execute()
    )
    logger.info("Created label: %s (id: %s)", label_name, created["id"])
    return created["id"]


def list_sent_recipients(service):
    """Return a sorted set of all email addresses the user has ever sent to."""
    recipients = set()
    page_token = None
    while True:
        results = (
            service.users()
            .messages()
            .list(userId="me", q="in:sent", maxResults=500, pageToken=page_token)
            .execute()
        )
        messages = results.get("messages", [])
        if not messages:
            break
        for msg_meta in messages:
            msg = get_message(
                service, msg_meta["id"], format="metadata", metadata_headers=["To", "Cc", "Bcc"]
            )
            for header in msg.get("payload", {}).get("headers", []):
                if header["name"].lower() in ("to", "cc", "bcc"):
                    for addr in _parse_addresses(header["value"]):
                        recipients.add(addr.lower())
        page_token = results.get("nextPageToken")
        if not page_token:
            break
    return sorted(recipients)


def _parse_addresses(header_value):
    """Extract email addresses from a header value like 'Name <email>, ...'."""
    import re
    return re.findall(r"[\w.+-]+@[\w.-]+\.\w+", header_value)


def apply_label(service, message_id, label_id):
    """Apply a label to a message."""
    service.users().messages().modify(
        userId="me", id=message_id, body={"addLabelIds": [label_id]}
    ).execute()
    logger.debug("Applied label %s to message %s", label_id, message_id)
