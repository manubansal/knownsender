import json
import logging
import random

import claven.core.db as db
from claven.core.gmail import (
    batch_apply_labels,
    batch_get_message_headers,
    batch_get_message_metadata,
    ensure_label_exists,
    get_message,
    get_profile,
    list_history,
    list_messages,
    load_scan_checkpoint,
    save_scan_checkpoint,
    _parse_addresses,
)
from claven.core.process import process_message
import time

from claven.core.rules import matches_rule

logger = logging.getLogger(__name__)

running = True


def _interruptible_sleep(seconds, shutdown_event=None):
    """Sleep that wakes immediately if shutdown_event is set."""
    if shutdown_event is not None:
        shutdown_event.wait(seconds)
    else:
        time.sleep(seconds)

_BATCH_SIZE = 50

# Fetch more candidates than needed and randomly sample from them.
# This desynchronizes concurrent workers so they process different messages
# instead of always picking the same batch (Gmail returns newest-first by
# default, so without sampling two workers would grab identical batches).
_SAMPLE_POOL_MULTIPLIER = 5


def _sample_batch(candidates, batch_size):
    """Randomly sample a batch from a larger candidate pool.

    If the pool is larger than the batch size, pick randomly to reduce
    overlap between concurrent workers scanning the same mailbox.
    If the pool is smaller or equal, use all candidates.
    """
    if len(candidates) > batch_size:
        return random.sample(candidates, batch_size)
    return candidates


def _notify_progress(conn, user_id, event, **data):
    """Send a Postgres NOTIFY with scan progress for SSE clients.

    NOTIFY fires on the next commit, so call this before conn.commit().
    Payload is JSON with user_id, event type, and any extra data.
    """
    payload = json.dumps({"user_id": user_id, "event": event, **data})
    with conn.cursor() as cur:
        cur.execute("SELECT pg_notify('scan_progress', %s)", (payload,))


SENT_SCANNED_LABEL = "claven/sent-scanned"


def build_known_senders(service, conn, user_id, should_continue=None, shutdown_event=None):
    """Build known senders list by scanning unlabeled sent messages.

    Queries Gmail for sent messages without the 'claven/sent-scanned' label,
    extracts recipients, inserts into sent_recipients, and applies the label.
    Loops until no unlabeled sent messages remain.

    Progress is mailbox-based — multiple workers converge naturally since
    each queries remaining unlabeled messages and labels what it processes.

    shutdown_event: threading.Event that, when set, wakes sleeps immediately
    so the thread exits within one loop iteration instead of blocking.

    Returns the number of sent messages scanned in this run.
    """
    scanned_label_id = ensure_label_exists(service, SENT_SCANNED_LABEL)
    query = f"in:sent -label:{SENT_SCANNED_LABEL}"
    logger.info("Sent scan starting (query=%s)", query)

    total_scanned = 0
    batch_num = 0
    while True:
        if should_continue is not None and not should_continue():
            logger.info("Sent scan stopped by caller after %d scanned", total_scanned)
            return total_scanned

        # Fetch a pool of unscanned messages and randomly sample a batch.
        # Random sampling desynchronizes concurrent workers (local + cloud)
        # so they process different messages instead of always grabbing the
        # same newest-first batch from Gmail.
        pool = list_messages(service, query=query, max_results=_BATCH_SIZE * _SAMPLE_POOL_MULTIPLIER)
        if not pool:
            logger.info("Sent scan complete: %d messages scanned, 0 remaining", total_scanned)
            break

        batch_num += 1
        batch = _sample_batch(pool, _BATCH_SIZE)
        batch_ids = [m["id"] for m in batch]
        logger.info("Sent scan batch %d: %d unscanned messages", batch_num, len(batch_ids))

        # Batch fetch To/Cc/Bcc headers
        try:
            metadata = batch_get_message_metadata(service, batch_ids, ["To", "Cc", "Bcc"])
        except Exception as exc:
            logger.warning("Batch sent fetch failed: %s", exc)
            _interruptible_sleep(5, shutdown_event)
            continue

        # Extract recipients
        recipients = []
        scanned_ids = []
        for msg_id in batch_ids:
            result = metadata.get(msg_id)
            if not result:
                continue
            headers = result[0]
            for field in ("to", "cc", "bcc"):
                if value := headers.get(field):
                    for addr in _parse_addresses(value):
                        recipients.append(addr.lower())
            scanned_ids.append(msg_id)

        # Insert recipients and mark messages as scanned
        if recipients:
            db.bulk_add_known_senders(conn, user_id, recipients)
        if scanned_ids:
            try:
                applied = batch_apply_labels(service, [(mid, scanned_label_id) for mid in scanned_ids])
                total_scanned += applied
                senders_count = db.count_known_senders(conn, user_id)
                _notify_progress(conn, user_id, "sent_scan_progress",
                                 scanned=total_scanned, senders=senders_count)
                conn.commit()
                logger.info("Sent scan batch %d: scanned %d messages (%d total, %d senders)",
                            batch_num, applied, total_scanned, senders_count)
            except Exception as exc:
                logger.warning("Batch label apply failed: %s", exc)
                _interruptible_sleep(5, shutdown_event)

        _interruptible_sleep(1, shutdown_event)

    return total_scanned


def _unlabeled_query(label_configs, scope="inbox"):
    """Build a Gmail query for messages missing filter labels.

    scope='inbox': only inbox messages (default)
    scope='allmail': all messages without the known-sender label
    """
    if scope == "allmail":
        # All-mail scope: only apply known-sender label
        exclude = []
        for lc in label_configs:
            exclude.append(f"-label:{lc['id']}")
        return " ".join(exclude)
    # Inbox scope: exclude both known and unknown labels
    exclude = []
    for lc in label_configs:
        exclude.append(f"-label:{lc['id']}")
        if unknown := lc.get("unknown_label"):
            exclude.append(f"-label:{unknown}")
    return "in:inbox " + " ".join(exclude)


def scan_inbox(service, conn, user_id, label_configs, label_id_cache, known_senders=None, should_continue=None, shutdown_event=None, scope="inbox"):
    """Label unlabeled messages using batch API calls.

    scope='inbox': label inbox messages as known-sender or unknown-sender
    scope='allmail': label all messages as known-sender only (skip unknown)

    Queries Gmail for messages that don't have the relevant label(s),
    processes them in batches, and repeats until none remain. Progress
    is based entirely on mailbox state — multiple workers naturally converge.

    shutdown_event: threading.Event that, when set, wakes sleeps immediately
    so the thread exits within one loop iteration instead of blocking.

    Returns the total number of messages labeled in this run.
    """
    query = _unlabeled_query(label_configs, scope=scope)
    logger.info("Inbox scan starting (query=%s, known_senders=%d)",
                query, len(known_senders or []))

    total_labeled = 0
    batch_num = 0
    while True:
        if should_continue is not None and not should_continue():
            logger.info("Inbox scan stopped by caller after %d labeled", total_labeled)
            return total_labeled

        # Fetch a pool of unlabeled messages and randomly sample a batch.
        # Random sampling desynchronizes concurrent workers (local + cloud)
        # so they process different messages instead of always grabbing the
        # same newest-first batch from Gmail.
        unlabeled_pool = list_messages(service, query=query, max_results=_BATCH_SIZE * _SAMPLE_POOL_MULTIPLIER)
        db.touch_last_fetched(conn, user_id)
        conn.commit()
        if not unlabeled_pool:
            logger.info("Inbox scan complete: %d messages labeled, 0 remaining", total_labeled)
            break

        batch_num += 1
        batch = _sample_batch(unlabeled_pool, _BATCH_SIZE)
        batch_ids = [m["id"] for m in batch]
        logger.info("Inbox scan batch %d: %d unlabeled messages to process", batch_num, len(batch_ids))

        # Batch fetch headers
        try:
            headers_map = batch_get_message_headers(service, batch_ids)
        except Exception as exc:
            logger.warning("Batch header fetch failed: %s", exc)
            _interruptible_sleep(5, shutdown_event)
            continue

        # Evaluate rules and collect label applications
        to_label = []
        newest_date_ms = None
        for msg_id in batch_ids:
            result = headers_map.get(msg_id)
            if not result:
                continue
            headers, existing_labels, internal_date_ms = result
            if not headers:
                continue
            for lc in label_configs:
                matched = any(matches_rule(headers, rule, known_senders) for rule in lc["rules"])
                if scope == "allmail":
                    # All-mail scope: only apply known-sender label, skip unknown
                    apply_id = lc["id"] if matched else None
                else:
                    apply_id = lc["id"] if matched else lc.get("unknown_label")
                if apply_id:
                    gmail_label_id = label_id_cache.get(apply_id)
                    if gmail_label_id and gmail_label_id not in existing_labels:
                        to_label.append((msg_id, gmail_label_id))
                        if internal_date_ms and (newest_date_ms is None or internal_date_ms > newest_date_ms):
                            newest_date_ms = internal_date_ms

        # Batch apply labels
        if to_label:
            try:
                applied = batch_apply_labels(service, to_label)
                total_labeled += applied
                if applied > 0:
                    db.touch_last_labeled(conn, user_id)
                    if newest_date_ms:
                        db.update_newest_labeled(conn, user_id, newest_date_ms)
                    _notify_progress(conn, user_id, "inbox_scan_progress",
                                     labeled=total_labeled)
                    conn.commit()
                logger.info("Inbox scan batch %d: labeled %d messages (%d total)", batch_num, applied, total_labeled)
            except Exception as exc:
                logger.warning("Batch label apply failed: %s", exc)
                _interruptible_sleep(5, shutdown_event)
        else:
            # All messages in this batch were already labeled (race with another worker)
            logger.info("Inbox scan batch %d: all %d already labeled by another worker", batch_num, len(batch_ids))

        _interruptible_sleep(1, shutdown_event)

    # Update history_id to current point
    profile = get_profile(service)
    db.set_history_id(conn, user_id, int(profile["historyId"]))
    _notify_progress(conn, user_id, "inbox_scan_complete", labeled=total_labeled)
    conn.commit()
    return total_labeled


def _recipients_from_messages(service, messages):
    """Extract all To/Cc/Bcc addresses from a list of message metadata stubs."""
    recipients = set()
    for msg_meta in messages:
        msg = get_message(service, msg_meta["id"], format="metadata",
                          metadata_headers=["To", "Cc", "Bcc"])
        for header in msg.get("payload", {}).get("headers", []):
            if header["name"].lower() in ("to", "cc", "bcc"):
                for addr in _parse_addresses(header["value"]):
                    recipients.add(addr.lower())
    return recipients


def initial_scan(service, data_dir, label_configs, label_id_cache, known_senders=None, max_messages=None):
    """Scan existing inbox messages and apply labels, skipping already-processed ones."""
    known_senders_count = len(known_senders) if known_senders else 0

    limit_str = str(max_messages) if max_messages else "all"
    logger.info("Running initial inbox scan (%s messages)...", limit_str)
    messages = list_messages(service, query="in:inbox", max_results=max_messages)

    processed_ids, checkpoint_senders_count = load_scan_checkpoint(data_dir)
    if processed_ids and known_senders_count > checkpoint_senders_count:
        logger.info(
            "Known senders list grew from %d to %d — reprocessing all messages to apply new labels",
            checkpoint_senders_count, known_senders_count,
        )
        processed_ids = set()

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
            save_scan_checkpoint(processed_ids, data_dir, known_senders_count)
            return
        process_message(service, msg["id"], label_configs, label_id_cache, known_senders)
        processed_ids.add(msg["id"])
        if i % 10 == 0 or i == total:
            logger.info("Progress: %d/%d messages processed (%.0f%%)", i, total, 100 * i / total)
            save_scan_checkpoint(processed_ids, data_dir, known_senders_count)
