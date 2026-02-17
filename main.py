import logging
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


def process_message(service, message_id, label_configs, label_id_cache):
    """Evaluate rules against a message and apply matching labels."""
    headers, existing_labels = get_message_headers(service, message_id)
    if not headers:
        return

    matching_labels = get_matching_labels(headers, label_configs)
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


def initial_scan(service, label_configs, label_id_cache):
    """Scan existing inbox messages and apply labels."""
    logger.info("Running initial inbox scan...")
    messages = list_messages(service, query="in:inbox")
    logger.info("Found %d messages in inbox", len(messages))
    for msg in messages:
        process_message(service, msg["id"], label_configs, label_id_cache)


def poll_new_messages(service, history_id, label_configs, label_id_cache):
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
            process_message(service, message_id, label_configs, label_id_cache)

    return history_id


def main():
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    config = load_config()
    label_configs = config["labels"]
    interval = config.get("polling_interval_seconds", 60)

    logger.info("Authenticating with Gmail API...")
    service = get_service()

    # Ensure all labels exist and cache their IDs
    label_id_cache = {}
    for label_config in label_configs:
        name = label_config["name"]
        label_id_cache[name] = ensure_label_exists(service, name)
    logger.info("Labels ready: %s", list(label_id_cache.keys()))

    # Initial scan of existing inbox
    initial_scan(service, label_configs, label_id_cache)

    # Get current history ID for incremental polling
    profile = get_profile(service)
    history_id = profile["historyId"]
    logger.info("Starting continuous polling (every %ds)...", interval)

    while running:
        time.sleep(interval)
        if not running:
            break

        profile = get_profile(service)
        new_history_id = profile["historyId"]

        if new_history_id != history_id:
            result = poll_new_messages(
                service, history_id, label_configs, label_id_cache
            )
            if result is None:
                # History expired, do a full scan
                initial_scan(service, label_configs, label_id_cache)
            history_id = new_history_id

    logger.info("Service stopped.")


if __name__ == "__main__":
    main()
