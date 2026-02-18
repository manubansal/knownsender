import argparse
import logging
import os
import signal
import sys
import time

from gmail_service import (
    get_service,
    get_profile,
    list_history,
    list_messages,
    get_message_headers,
    ensure_label_exists,
    apply_label,
    list_sent_recipients,
    load_scan_checkpoint,
    save_scan_checkpoint,
)
from labeler import load_config, get_matching_labels

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

running = True


def handle_shutdown(signum, frame):
    global running
    logger.info("Shutting down...")
    running = False


def process_message(service, message_id, label_configs, label_id_cache, known_senders=None):
    """Evaluate rules against a message and apply matching labels."""
    headers, existing_labels = get_message_headers(service, message_id)
    if not headers:
        return

    matching_labels = get_matching_labels(headers, label_configs, known_senders)
    for label_name in matching_labels:
        label_id = label_id_cache.get(label_name)
        if label_id and label_id not in existing_labels:
            apply_label(service, message_id, label_id)
            logger.info(
                "Labeled message %s (%s) as '%s'",
                message_id,
                headers.get("subject", ""),
                label_name,
            )


def initial_scan(service, data_dir, label_configs, label_id_cache, known_senders=None, max_messages=None):
    """Scan existing inbox messages and apply labels, skipping already-processed ones."""
    limit_str = str(max_messages) if max_messages else "all"
    logger.info("Running initial inbox scan (%s messages)...", limit_str)
    messages = list_messages(service, query="in:inbox", max_results=max_messages)

    processed_ids = load_scan_checkpoint(data_dir)
    pending = [m for m in messages if m["id"] not in processed_ids]
    skipped = len(messages) - len(pending)
    if skipped:
        logger.info("Skipping %d already-processed messages from checkpoint", skipped)

    total = len(pending)
    logger.info("Processing %d messages", total)
    if total == 0:
        return

    for i, msg in enumerate(pending, 1):
        if not running:
            logger.info("Scan interrupted at %d/%d messages, progress saved", i - 1, total)
            save_scan_checkpoint(processed_ids, data_dir)
            return
        process_message(service, msg["id"], label_configs, label_id_cache, known_senders)
        processed_ids.add(msg["id"])
        if i % 10 == 0 or i == total:
            logger.info("Progress: %d/%d messages processed (%.0f%%)", i, total, 100 * i / total)
            save_scan_checkpoint(processed_ids, data_dir)


def poll_new_messages(service, history_id, label_configs, label_id_cache, known_senders=None):
    """Check for new messages since the last history ID."""
    try:
        records = list_history(service, history_id)
    except Exception as e:
        if "404" in str(e):
            logger.warning("History ID expired, falling back to inbox scan")
            return None
        raise

    message_ids = set()
    for record in records:
        for added in record.get("messagesAdded", []):
            msg = added["message"]
            if "INBOX" in msg.get("labelIds", []):
                message_ids.add(msg["id"])

    if message_ids:
        logger.info("Processing %d new message(s)", len(message_ids))
        for message_id in message_ids:
            process_message(service, message_id, label_configs, label_id_cache, known_senders)

    return history_id


def main():
    parser = argparse.ArgumentParser(description="Gmail email labeling service")
    parser.add_argument(
        "--account", required=True,
        help="Account name to use (state is stored under accounts/<account>/)",
    )
    parser.add_argument(
        "--max-messages", type=int, default=None,
        help="Max number of messages to process on initial scan (default: all)",
    )
    args = parser.parse_args()

    data_dir = os.path.join("accounts", args.account)
    os.makedirs(data_dir, exist_ok=True)
    logger.info("Using account '%s' (data dir: %s)", args.account, data_dir)

    credentials_path = os.path.join(data_dir, "credentials.json")
    if not os.path.exists(credentials_path):
        print(f"""
Account '{args.account}' is not set up yet.

To get started:
  1. Go to https://console.cloud.google.com/ and create a project (or select an existing one)
  2. Enable the Gmail API: APIs & Services > Enable APIs > search "Gmail API"
  3. Create OAuth credentials: APIs & Services > Credentials > Create Credentials > OAuth client ID
     - Application type: Desktop app
  4. Download the credentials JSON and save it to:
       {credentials_path}
  5. Re-run this command — a browser window will open to authorize Gmail access.
""")
        sys.exit(1)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    config = load_config()
    label_configs = config["labels"]
    interval = config.get("polling_interval_seconds", 60)

    logger.info("Authenticating with Gmail API...")
    service = get_service(data_dir)

    # Ensure all labels exist and cache their IDs
    label_id_cache = {}
    for label_config in label_configs:
        name = label_config["name"]
        label_id_cache[name] = ensure_label_exists(service, name)
    logger.info("Labels ready: %s", list(label_id_cache.keys()))

    # Build/update known senders cache
    known_senders = set(list_sent_recipients(service, data_dir, should_continue=lambda: running))
    logger.info("Loaded %d known senders", len(known_senders))

    # Initial scan of existing inbox
    initial_scan(service, data_dir, label_configs, label_id_cache, known_senders, args.max_messages)

    # Get current history ID for incremental polling
    profile = get_profile(service)
    history_id = profile["historyId"]
    logger.info("Starting continuous polling (every %ds)...", interval)

    while running:
        time.sleep(interval)
        if not running:
            break

        logger.info("Polling for new messages...")
        profile = get_profile(service)
        new_history_id = profile["historyId"]

        if new_history_id != history_id:
            # Refresh known senders each polling cycle
            known_senders = set(list_sent_recipients(service, data_dir, should_continue=lambda: running))
            result = poll_new_messages(
                service, history_id, label_configs, label_id_cache, known_senders
            )
            if result is None:
                # History expired, do a full scan
                initial_scan(service, data_dir, label_configs, label_id_cache, known_senders)
            history_id = new_history_id

    logger.info("Service stopped.")


if __name__ == "__main__":
    main()
