import argparse
import logging
import os
import signal
import threading

import claven.core.scan as scan_module
from claven.core.gmail import (
    get_service,
    get_profile,
    ensure_label_exists,
    list_sent_recipients,
)
from claven.core.rules import load_config
from claven.core.process import poll_new_messages
from claven.core.scan import initial_scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

shutdown_event = threading.Event()


def handle_shutdown(signum, frame):
    logger.info("Shutting down...")
    scan_module.running = False
    shutdown_event.set()


def main():
    parser = argparse.ArgumentParser(description="Claven — Gmail labeling service")
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
    known_senders = set(list_sent_recipients(service, data_dir, should_continue=lambda: scan_module.running))
    logger.info("Loaded %d known senders", len(known_senders))

    # Initial scan of existing inbox
    initial_scan(service, data_dir, label_configs, label_id_cache, known_senders, args.max_messages)

    # Get current history ID for incremental polling
    profile = get_profile(service)
    history_id = profile["historyId"]
    logger.info("Starting continuous polling (every %ds)...", interval)

    while scan_module.running:
        shutdown_event.wait(timeout=interval)
        if not scan_module.running:
            break

        logger.info("Polling for new messages...")
        profile = get_profile(service)
        new_history_id = profile["historyId"]

        if new_history_id != history_id:
            # Refresh known senders each polling cycle
            known_senders = set(list_sent_recipients(service, data_dir, should_continue=lambda: scan_module.running))
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
