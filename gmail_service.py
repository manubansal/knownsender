import json
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
RECIPIENTS_CACHE_PATH = "sent_recipients_cache.json"
SCAN_CHECKPOINT_PATH = "scan_checkpoint.json"


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
    """List message IDs matching a query, paginating as needed.

    Pass max_results=None to fetch all matching messages.
    """
    messages = []
    page_token = None
    while max_results is None or len(messages) < max_results:
        batch_size = 500 if max_results is None else min(max_results - len(messages), 500)
        results = (
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=batch_size, pageToken=page_token)
            .execute()
        )
        messages.extend(results.get("messages", []))
        page_token = results.get("nextPageToken")
        if not page_token:
            break
    return messages


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


def load_scan_checkpoint():
    """Load the set of already-processed message IDs from disk."""
    if os.path.exists(SCAN_CHECKPOINT_PATH):
        with open(SCAN_CHECKPOINT_PATH) as f:
            return set(json.load(f).get("processed_ids", []))
    return set()


def save_scan_checkpoint(processed_ids):
    """Persist the set of processed message IDs to disk."""
    with open(SCAN_CHECKPOINT_PATH, "w") as f:
        json.dump({"processed_ids": sorted(processed_ids)}, f)


def _load_recipients_cache():
    """Load cached recipients and history ID from disk."""
    if os.path.exists(RECIPIENTS_CACHE_PATH):
        with open(RECIPIENTS_CACHE_PATH) as f:
            data = json.load(f)
            return set(data.get("recipients", [])), data.get("history_id")
    return set(), None


def _save_recipients_cache(recipients, history_id):
    """Save recipients and history ID to disk."""
    with open(RECIPIENTS_CACHE_PATH, "w") as f:
        json.dump({"recipients": sorted(recipients), "history_id": history_id}, f)


def _extract_recipients_from_messages(service, messages):
    """Extract recipient addresses from a list of message metadata."""
    recipients = set()
    total = len(messages)
    log_every = max(1, total // 10)
    for i, msg_meta in enumerate(messages, 1):
        msg = get_message(
            service, msg_meta["id"], format="metadata", metadata_headers=["To", "Cc", "Bcc"]
        )
        for header in msg.get("payload", {}).get("headers", []):
            if header["name"].lower() in ("to", "cc", "bcc"):
                for addr in _parse_addresses(header["value"]):
                    recipients.add(addr.lower())
        if total > 10 and (i % log_every == 0 or i == total):
            logger.info("Extracting recipients: %d/%d (%.0f%%)", i, total, 100 * i / total)
    return recipients


def list_sent_recipients(service):
    """Return a sorted set of all email addresses the user has ever sent to.

    Uses incremental caching: on first run, scans all sent messages and saves
    the results. On subsequent runs, only processes new messages since the last
    cached history ID.
    """
    cached_recipients, cached_history_id = _load_recipients_cache()

    if cached_history_id:
        # Incremental update: only fetch new sent messages since last run
        logger.info("Loading cached recipients, checking for new sent messages...")
        try:
            records = list_history(service, cached_history_id, label_id="SENT")
            new_message_ids = set()
            for record in records:
                for added in record.get("messagesAdded", []):
                    msg = added["message"]
                    if "SENT" in msg.get("labelIds", []):
                        new_message_ids.add(msg["id"])
            if new_message_ids:
                logger.info("Found %d new sent message(s)", len(new_message_ids))
                new_msgs = [{"id": mid} for mid in new_message_ids]
                new_recipients = _extract_recipients_from_messages(service, new_msgs)
                cached_recipients.update(new_recipients)
            else:
                logger.info("No new sent messages since last run")
        except Exception as e:
            if "404" in str(e):
                logger.warning("History ID expired, doing full scan")
                cached_recipients = set()
                cached_history_id = None
            else:
                raise

    if not cached_history_id:
        # Full scan: paginate through all sent messages
        logger.info("Running full scan of sent messages...")
        page_token = None
        total_scanned = 0
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
            cached_recipients.update(
                _extract_recipients_from_messages(service, messages)
            )
            total_scanned += len(messages)
            logger.info("Scanned %d sent messages so far...", total_scanned)
            _save_recipients_cache(cached_recipients, None)
            page_token = results.get("nextPageToken")
            if not page_token:
                break
        logger.info("Sent messages scan complete: %d total", total_scanned)

    # Save final cache with current history ID
    profile = get_profile(service)
    _save_recipients_cache(cached_recipients, profile["historyId"])

    return sorted(cached_recipients)


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
