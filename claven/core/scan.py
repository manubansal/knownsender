import logging

from claven.core.gmail import list_messages, load_scan_checkpoint, save_scan_checkpoint
from claven.core.process import process_message

logger = logging.getLogger(__name__)

running = True


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
