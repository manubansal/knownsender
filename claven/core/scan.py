import logging

import claven.core.db as db
from claven.core.gmail import (
    get_message,
    get_profile,
    list_history,
    list_messages,
    load_scan_checkpoint,
    save_scan_checkpoint,
    _parse_addresses,
)
from claven.core.process import process_message

logger = logging.getLogger(__name__)

running = True

_BATCH_SIZE = 50


def build_known_senders(service, conn, user_id, should_continue=None):
    """Build or incrementally update the known senders list from Sent mail.

    On first run (no cursor): scans all sent messages, extracts To/Cc/Bcc
    addresses, and bulk-inserts them into sent_recipients.

    On subsequent runs (cursor exists): uses the Gmail History API to fetch
    only new sent messages since the last run.

    If the cursor has expired (404), falls back to a full scan.

    Inserts are batched and idempotent (ON CONFLICT DO NOTHING), so the
    function is safe to interrupt and re-run from scratch. The cursor is
    only saved on successful completion — an interrupted full scan will
    restart from the beginning next time.

    Returns a dict with:
      - known_senders: total count in DB after the update
      - messages_scanned: number of sent messages processed in this run
    """
    cursor = db.get_sent_scan_cursor(conn, user_id)
    messages_scanned = 0

    if cursor is not None:
        try:
            records = list_history(service, cursor, label_id="SENT")
        except Exception as exc:
            if "404" in str(exc):
                logger.warning("Sent scan cursor expired, falling back to full scan")
                cursor = None
            else:
                raise

    prior = db.get_sent_scan_progress(conn, user_id)
    cumulative_scanned = prior["messages_scanned"]
    messages_total = prior["messages_total"]

    if cursor is not None:
        # Incremental: only new sent messages since last cursor
        new_ids = {
            added["message"]["id"]
            for record in records
            for added in record.get("messagesAdded", [])
            if "SENT" in added["message"].get("labelIds", [])
        }
        if new_ids:
            logger.info("Found %d new sent message(s)", len(new_ids))
            recipients = _recipients_from_messages(service, [{"id": mid} for mid in new_ids])
            db.bulk_add_known_senders(conn, user_id, list(recipients))
            messages_scanned = len(new_ids)
            cumulative_scanned += messages_scanned
            if messages_total is not None:
                messages_total += messages_scanned
        else:
            logger.info("No new sent messages since last scan")
    else:
        # Full scan: walk all sent messages in batches
        messages = list_messages(service, query="in:sent", max_results=None)
        total = len(messages)
        messages_total = total
        logger.info("Full sent scan: %d messages to process", total)
        batch = []
        for i, msg_meta in enumerate(messages, 1):
            if should_continue is not None and not should_continue():
                logger.info("Sent scan interrupted at %d/%d, partial results saved", i - 1, total)
                if batch:
                    db.bulk_add_known_senders(conn, user_id, batch)
                scanned = i - 1
                db.set_sent_scan_progress(conn, user_id, scanned, messages_total)
                return {
                    "known_senders": db.count_known_senders(conn, user_id),
                    "messages_scanned": scanned,
                }
            msg = get_message(service, msg_meta["id"], format="metadata",
                              metadata_headers=["To", "Cc", "Bcc"])
            for header in msg.get("payload", {}).get("headers", []):
                if header["name"].lower() in ("to", "cc", "bcc"):
                    for addr in _parse_addresses(header["value"]):
                        batch.append(addr.lower())
            if len(batch) >= _BATCH_SIZE:
                db.bulk_add_known_senders(conn, user_id, batch)
                batch = []
            if i % 100 == 0 or i == total:
                logger.info("Sent scan progress: %d/%d (%.0f%%)", i, total, 100 * i / total)
        if batch:
            db.bulk_add_known_senders(conn, user_id, batch)
        messages_scanned = total
        cumulative_scanned = total

    profile = get_profile(service)
    db.set_sent_scan_cursor(conn, user_id, int(profile["historyId"]))
    db.set_sent_scan_progress(conn, user_id, cumulative_scanned, messages_total)
    count = db.count_known_senders(conn, user_id)
    logger.info("Known senders: %d total (%d messages scanned)", count, messages_scanned)
    return {"known_senders": count, "messages_scanned": messages_scanned}


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
