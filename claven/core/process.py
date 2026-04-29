import logging

from claven.core.gmail import get_message_headers, apply_label, list_history
from claven.core.rules import matches_rule

logger = logging.getLogger(__name__)


def process_message(service, message_id, label_configs, label_id_cache, known_senders=None):
    """Evaluate each label config against a message.

    For each label config:
    - If any rule matches, apply that label's Gmail label (keyed by id).
    - If no rule matches and the config has an unknown_label, apply that instead.

    This ensures every processed message lands in exactly one state per label
    config: matched, unmatched, or (if no unknown_label configured) unchanged.

    Returns True if at least one label was newly applied, False otherwise.
    """
    headers, existing_labels = get_message_headers(service, message_id)
    if not headers:
        return False

    applied = False
    for label_config in label_configs:
        matched = any(
            matches_rule(headers, rule, known_senders)
            for rule in label_config["rules"]
        )
        apply_id = label_config["id"] if matched else label_config.get("unknown_label")
        if apply_id:
            gmail_label_id = label_id_cache.get(apply_id)
            if not gmail_label_id:
                logger.debug("Label '%s' not in cache (cache keys: %s)", apply_id, list(label_id_cache.keys()))
            elif gmail_label_id in existing_labels:
                logger.debug("Label '%s' already on message %s", apply_id, message_id)
            else:
                apply_label(service, message_id, gmail_label_id)
                logger.info(
                    "Labeled message %s (%s) as '%s'",
                    message_id,
                    headers.get("subject", ""),
                    apply_id,
                )
                applied = True
    return applied


def poll_new_messages(service, history_id, label_configs, label_id_cache, known_senders=None):
    """Check for new messages since the last history ID.

    Returns the number of messages processed, or None if the history ID had
    expired (404) and the caller should fall back to a full inbox scan.
    """
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

    return len(message_ids)
