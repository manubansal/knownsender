import logging

import claven.core.db as db
from claven.core.gmail import (
    batch_apply_labels,
    batch_get_message_headers,
    batch_get_message_metadata,
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
            conn.commit()
            messages_scanned = len(new_ids)
            cumulative_scanned += messages_scanned
            if messages_total is not None:
                messages_total += messages_scanned
        else:
            logger.info("No new sent messages since last scan")
    else:
        # Full scan: walk all sent messages using batch API
        messages = list_messages(service, query="in:sent", max_results=None)
        total = len(messages)
        messages_total = total
        resume_from = prior["messages_scanned"] if prior["messages_scanned"] > 0 else 0
        if resume_from > 0 and resume_from < total:
            logger.info("Full sent scan: resuming from %d/%d", resume_from, total)
        else:
            resume_from = 0
        logger.info("Full sent scan: %d messages to process (%d already done)", total, resume_from)

        for batch_start in range(resume_from, total, _BATCH_SIZE):
            if batch_start > 0:
                time.sleep(1)
            if should_continue is not None and not should_continue():
                logger.info("Sent scan interrupted at %d/%d, partial results saved", batch_start, total)
                db.set_sent_scan_progress(conn, user_id, batch_start, messages_total)
                conn.commit()
                return {
                    "known_senders": db.count_known_senders(conn, user_id),
                    "messages_scanned": batch_start,
                }
            batch_ids = [m["id"] for m in messages[batch_start:batch_start + _BATCH_SIZE]]
            batch_end = batch_start + len(batch_ids)
            try:
                metadata = batch_get_message_metadata(service, batch_ids, ["To", "Cc", "Bcc"])
            except Exception as exc:
                logger.warning("Batch sent fetch failed at %d-%d: %s", batch_start + 1, batch_end, exc)
                db.set_sent_scan_progress(conn, user_id, batch_end, messages_total)
                conn.commit()
                continue

            recipients = []
            for msg_id in batch_ids:
                result = metadata.get(msg_id)
                if not result:
                    continue
                headers = result[0]
                for field in ("to", "cc", "bcc"):
                    if value := headers.get(field):
                        for addr in _parse_addresses(value):
                            recipients.append(addr.lower())

            if recipients:
                db.bulk_add_known_senders(conn, user_id, recipients)
            db.set_sent_scan_progress(conn, user_id, batch_end, messages_total)
            conn.commit()
            if batch_end % 500 == 0 or batch_end == total:
                logger.info("Sent scan progress: %d/%d (%.0f%%)", batch_end, total, 100 * batch_end / total)

        messages_scanned = total
        cumulative_scanned = total

    profile = get_profile(service)
    db.set_sent_scan_cursor(conn, user_id, int(profile["historyId"]))
    db.set_sent_scan_progress(conn, user_id, cumulative_scanned, messages_total)
    count = db.count_known_senders(conn, user_id)
    logger.info("Known senders: %d total (%d messages scanned)", count, messages_scanned)
    return {"known_senders": count, "messages_scanned": messages_scanned}


def scan_inbox(service, conn, user_id, label_configs, label_id_cache, known_senders=None):
    """Scan all inbox messages and apply labels using batch API calls.

    Fetches message headers in batches of 100, evaluates rules locally,
    then batch-applies labels. ~100x faster than per-message API calls.

    Returns the number of messages processed.
    """
    logger.info("Inbox scan starting (label_id_cache=%s, known_senders=%d)",
                list(label_id_cache.keys()), len(known_senders or []))
    messages = list_messages(service, query="in:inbox", max_results=None)
    total = len(messages)
    logger.info("Inbox scan: %d messages to process", total)
    if total == 0:
        return 0

    errors = 0
    for batch_start in range(0, total, _BATCH_SIZE):
        if batch_start > 0:
            time.sleep(1)
        batch_ids = [m["id"] for m in messages[batch_start:batch_start + _BATCH_SIZE]]
        batch_end = batch_start + len(batch_ids)

        # Batch fetch headers
        try:
            headers_map = batch_get_message_headers(service, batch_ids)
        except Exception as exc:
            errors += len(batch_ids)
            logger.warning("Batch header fetch failed at %d-%d: %s", batch_start + 1, batch_end, exc)
            db.set_processed_count(conn, user_id, batch_end)
            conn.commit()
            continue

        # Evaluate rules and collect label applications
        to_label = []
        newest_date_ms = None
        for msg_id in batch_ids:
            result = headers_map.get(msg_id)
            if not result:
                errors += 1
                continue
            headers, existing_labels, internal_date_ms = result
            if not headers:
                continue
            for lc in label_configs:
                matched = any(matches_rule(headers, rule, known_senders) for rule in lc["rules"])
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
                if applied > 0:
                    db.touch_last_processed(conn, user_id)
                    if newest_date_ms:
                        db.update_newest_labeled(conn, user_id, newest_date_ms)
                logger.info("Batch labeled %d message(s) at %d-%d", applied, batch_start + 1, batch_end)
            except Exception as exc:
                logger.warning("Batch label apply failed at %d-%d: %s", batch_start + 1, batch_end, exc)

        db.set_processed_count(conn, user_id, batch_end)
        conn.commit()
        if batch_end % 500 == 0 or batch_end == total:
            logger.info("Inbox scan progress: %d/%d (%.0f%%), %d errors", batch_end, total, 100 * batch_end / total, errors)

    profile = get_profile(service)
    db.set_history_id(conn, user_id, int(profile["historyId"]))
    db.set_inbox_scan_completed(conn, user_id)
    conn.commit()
    logger.info("Inbox scan complete: %d messages processed, %d errors", total, errors)
    return total


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
