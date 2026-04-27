import logging

from claven.core.gmail import get_message_headers, apply_label, list_history
from claven.core.rules import get_matching_labels

logger = logging.getLogger(__name__)


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
