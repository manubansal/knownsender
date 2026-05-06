"""Background task runners and helpers."""

import logging
import os
import threading
from datetime import datetime, timezone, timedelta

import claven.server as _srv

logger = logging.getLogger(__name__)

_STALE_SCAN_THRESHOLD = timedelta(minutes=1)


def _needs_sent_scan(scan_progress: dict) -> bool:
    """Return True if the sent scan should be (re-)triggered."""
    status = scan_progress["status"]
    if status == "complete":
        logger.debug("_needs_sent_scan: False (status=complete)")
        return False
    if status == "in_progress":
        updated_at = scan_progress.get("updated_at")
        if updated_at and datetime.now(timezone.utc) - updated_at < _STALE_SCAN_THRESHOLD:
            logger.debug("_needs_sent_scan: False (in_progress, updated_at=%s, not stale)", updated_at)
            return False
        # Stale in_progress — treat as failed
        logger.debug("_needs_sent_scan: True (stale in_progress, updated_at=%s)", scan_progress.get("updated_at"))
        return True
    # None, "error", or anything else
    logger.debug("_needs_sent_scan: True (status=%s)", status)
    return True


def _label_id_cache_for_config(service, label_configs: list[dict]) -> dict[str, str]:
    """Build a Gmail label ID cache for all labels referenced in the config."""
    names = []
    for lc in label_configs:
        names.append(lc["id"])
        if unknown := lc.get("unknown_label"):
            names.append(unknown)
    return _srv.build_label_id_cache(service, names)


def _is_current_worker() -> bool:
    """Check if this thread should keep running (global check only).

    Returns False if:
    - --reload spawned a new worker (PID changed)
    - Ctrl+C / SIGTERM received (shutdown event set)
    """
    if _srv._shutdown_event.is_set():
        logger.debug("_is_current_worker: False (shutdown_event set)")
        return False
    pid_match = os.getpid() == _srv._worker_id
    if not pid_match:
        logger.debug("_is_current_worker: False (pid=%d, worker_id=%d)", os.getpid(), _srv._worker_id)
    return pid_match


def _cancel_scans_and_wait(user_id: str, timeout: float = 10) -> None:
    """Set cancel_scans state and wait for scan threads to exit.

    Scans set their own status to 'cancelled' when they see the cancel flag.
    """
    logger.debug("_cancel_scans_and_wait: setting cancel_scans for user %s", user_id)
    with _srv.db.get_connection() as conn:
        _srv.db.set_cancel_state(conn, user_id, "cancel_scans")
    import time as _time
    deadline = _time.monotonic() + timeout
    with _srv._threads_lock:
        threads = list(_srv._active_threads)
    logger.debug("_cancel_scans_and_wait: joining %d threads (timeout=%.1f)", len(threads), timeout)
    for t in threads:
        remaining = deadline - _time.monotonic()
        if remaining > 0:
            t.join(timeout=remaining)
    logger.debug("_cancel_scans_and_wait: done waiting")


def _should_continue_scan(user_id: str) -> bool:
    """For scan loops: exit on any non-NULL cancel state."""
    if not _is_current_worker():
        logger.debug("should_continue_scan: _is_current_worker=False (shutdown=%s, pid=%d, worker_id=%d)",
                      _srv._shutdown_event.is_set(), os.getpid(), _srv._worker_id)
        return False
    with _srv.db.get_connection() as conn:
        state = _srv.db.get_cancel_state(conn, user_id)
        if state is not None:
            logger.debug("should_continue_scan: cancel_state=%s", state)
        return state is None


def _should_continue_job(user_id: str) -> bool:
    """For exclusive jobs: exit only on cancel_job."""
    if not _is_current_worker():
        logger.debug("_should_continue_job: False (_is_current_worker=False)")
        return False
    with _srv.db.get_connection() as conn:
        state = _srv.db.get_cancel_state(conn, user_id)
        if state == "cancel_job":
            logger.debug("_should_continue_job: False (cancel_state=cancel_job)")
            return False
        logger.debug("_should_continue_job: True (cancel_state=%s)", state)
        return True


def _run_inbox_scan(user_id: str):
    """Background task: scan messages and apply labels. Respects scan_scope setting."""
    my_pid = os.getpid()
    logger.info("Inbox scan thread started for %s (worker pid=%d)", user_id, my_pid)
    label_configs = _srv.load_config().get("labels", [])
    try:
        # Setup: short-lived connection for lock + config
        with _srv.db.get_connection() as conn:
            if not _srv.db.try_lock_user_scan(conn, user_id):
                logger.info("Inbox scan skipped for %s — locked by another instance", user_id)
                return
            scope = _srv.db.get_scan_scope(conn, user_id)
            logger.debug("_run_inbox_scan: acquired lock, scope=%s", scope)
            _srv.db.set_inbox_scan_status(conn, user_id, "in_progress")
            _srv.db.log_event(conn, user_id, "scan", f"Label scan started (scope={scope})")
            service = _srv.auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            known_senders = _srv.db.get_known_senders(conn, user_id)
            logger.debug("_run_inbox_scan: setup complete, %d known_senders", len(known_senders))
        # Scan: uses per-batch connections internally
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        count = _srv.scan_inbox(service, None, user_id, label_configs, label_id_cache, known_senders, should_continue=lambda: _should_continue_scan(user_id), shutdown_event=_srv._shutdown_event, scope=scope)
        logger.debug("_run_inbox_scan: scan_inbox returned count=%d", count)
        # Check why scan returned
        if not _should_continue_scan(user_id):
            logger.debug("_run_inbox_scan: post-scan _should_continue_scan=False, setting cancelled")
            with _srv.db.get_connection() as conn:
                _srv.db.set_inbox_scan_status(conn, user_id, "cancelled")
                _srv.db.log_event(conn, user_id, "scan", f"Label scan cancelled after {count} labeled")
            return
        logger.debug("_run_inbox_scan: scan completed normally, setting complete")
        with _srv.db.get_connection() as conn:
            _srv.db.set_inbox_scan_status(conn, user_id, "complete")
            _srv.db.log_event(conn, user_id, "scan", f"Label scan complete — {count} labeled")
        logger.info("Inbox scan for %s: processed %d message(s)", user_id, count,
                     extra={"event": "inbox_scan_complete", "user_id": user_id})
    except Exception as exc:
        logger.exception("Inbox scan failed for user %s: %s", user_id, exc)
        # Classify the error for the health code system
        error_label = "error.unknown"
        exc_str = str(exc).lower()
        if "connection" in exc_str or "closed" in exc_str or "ssl" in exc_str:
            error_label = "error.db.connection_lost"
        elif "429" in exc_str or "rate" in exc_str:
            error_label = "error.gmail.rate_limited"
        elif "401" in exc_str or "403" in exc_str or "token" in exc_str:
            error_label = "error.gmail.auth_expired"
        elif "quota" in exc_str:
            error_label = "error.gmail.quota_exhausted"
        elif "HttpError" in str(type(exc).__name__) or "gmail" in exc_str:
            error_label = "error.gmail.api"
        logger.debug("_run_inbox_scan: classified error as %s (exc_str=%s)", error_label, exc_str[:100])
        try:
            with _srv.db.get_connection() as conn:
                _srv.db.set_inbox_scan_status(conn, user_id, error_label)
                _srv.db.log_event(conn, user_id, "error", f"Label scan failed — {error_label}")
        except Exception:
            logger.exception("Failed to set inbox scan error status for %s", user_id)


def _run_relabel_scan(user_id: str):
    """Background task: relabel messages from newly discovered known senders."""
    logger.debug("_run_relabel_scan: starting for user %s", user_id)
    label_configs = _srv.load_config().get("labels", [])
    try:
        with _srv.db.get_connection() as conn:
            service = _srv.auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        count = _srv.relabel_scan(service, user_id, label_configs, label_id_cache,
                             should_continue=lambda: _should_continue_scan(user_id), shutdown_event=_srv._shutdown_event)
        logger.debug("_run_relabel_scan: relabel_scan returned count=%d", count)
        if count > 0:
            with _srv.db.get_connection() as conn:
                _srv.db.log_event(conn, user_id, "scan", f"Relabel scan complete — {count} relabeled")
        logger.info("Relabel scan for %s: relabeled %d message(s)", user_id, count,
                     extra={"event": "relabel_scan_complete", "user_id": user_id})
    except Exception as exc:
        logger.exception("Relabel scan failed for user %s: %s", user_id, exc)
        try:
            with _srv.db.get_connection() as conn:
                _srv.db.log_event(conn, user_id, "error", f"Relabel scan failed — {exc}")
        except Exception:
            pass


def _run_sent_scan(user_id: str):
    """Background task: build the known senders list, then relabel + label.

    Acquires a row-level lock on scan_state so only one instance processes
    a user at a time. After the sent scan completes, immediately labels
    all inbox messages.
    """
    logger.info("Sent scan thread started for %s (worker pid=%d)", user_id, os.getpid())
    with _srv.db.get_connection() as conn:
        if not _srv.db.try_lock_user_scan(conn, user_id):
            logger.info("Sent scan skipped for %s — locked by another instance", user_id)
            return
        try:
            _srv.db.set_sent_scan_status(conn, user_id, "in_progress")
            _srv.db.log_event(conn, user_id, "scan", "Sent scan started")
            logger.debug("_run_sent_scan: set status=in_progress")
        except Exception:
            logger.exception("Failed to set sent scan status for %s", user_id)
            return
    try:
        # Setup: short-lived connection for lock + service
        with _srv.db.get_connection() as conn:
            if not _srv.db.try_lock_user_scan(conn, user_id):
                logger.info("Sent scan skipped for %s — locked by another instance (second lock)", user_id)
                return
            service = _srv.auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            logger.debug("_run_sent_scan: acquired second lock, got service")
        # Scan: uses per-batch connections internally
        logger.debug("_run_sent_scan: calling build_known_senders")
        _srv.build_known_senders(service, None, user_id, should_continue=lambda: _should_continue_scan(user_id), shutdown_event=_srv._shutdown_event)
        logger.debug("_run_sent_scan: build_known_senders returned")
        # Check why scan returned
        if not _should_continue_scan(user_id):
            logger.debug("_run_sent_scan: post-scan _should_continue_scan=False, setting cancelled")
            with _srv.db.get_connection() as conn:
                _srv.db.set_sent_scan_status(conn, user_id, "cancelled")
                _srv.db.log_event(conn, user_id, "scan", "Sent scan cancelled")
            return
        if not _is_current_worker():
            logger.info("Sent scan stopped — worker replaced (pid=%d, current=%d)", _srv._worker_id, os.getpid())
            with _srv.db.get_connection() as conn:
                _srv.db.set_sent_scan_status(conn, user_id, "cancelled")
            return
        logger.debug("_run_sent_scan: scan completed normally, setting complete")
        with _srv.db.get_connection() as conn:
            _srv.db.set_sent_scan_status(conn, user_id, "complete")
            _srv.db.log_event(conn, user_id, "scan", "Sent scan complete")
    except Exception as exc:
        logger.exception("Sent scan failed for user %s: %s", user_id, exc)
        try:
            with _srv.db.get_connection() as conn:
                _srv.db.set_sent_scan_status(conn, user_id, "error")
                _srv.db.log_event(conn, user_id, "error", f"Sent scan failed — {exc}")
        except Exception:
            logger.exception("Failed to set error status for %s", user_id)
        return

    # Sent scan done → relabel mislabeled messages → label remaining
    logger.debug("_run_sent_scan: chaining to relabel_scan")
    _run_relabel_scan(user_id)
    logger.debug("_run_sent_scan: chaining to inbox_scan")
    _run_inbox_scan(user_id)


def _run_archive_unknown(user_id: str, job_id: str):
    """Background task: archive all inbox messages with unknown-sender label."""
    logger.info("Archive job %s started for %s", job_id, user_id)

    # Wait for running scans to exit (cancel_scans was set by the endpoint)
    with _srv._threads_lock:
        threads = [t for t in _srv._active_threads if t is not threading.current_thread()]
    logger.debug("_run_archive_unknown: waiting for %d threads to exit", len(threads))
    for t in threads:
        t.join(timeout=10)
    logger.debug("_run_archive_unknown: threads joined, proceeding")

    try:
        with _srv.db.get_connection() as conn:
            if not _srv.db.try_lock_user_scan(conn, user_id):
                logger.info("Archive job %s skipped — locked", job_id)
                return

            service = _srv.auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            label_configs = _srv.load_config().get("labels", [])
            all_labels = service.users().labels().list(userId="me").execute().get("labels", [])
            label_id_by_name = {l["name"]: l["id"] for l in all_labels}

            unknown_label_id = None
            for lc in label_configs:
                if unknown := lc.get("unknown_label"):
                    unknown_label_id = label_id_by_name.get(unknown)
            if not unknown_label_id:
                logger.warning("Archive job %s: no unknown-sender label found", job_id)
                _srv.db.set_archive_job(conn, user_id, job_id, "error")
                return

            # Deep count — paginate to get all message IDs
            all_msg_ids = []
            page_token = None
            while True:
                kwargs = {"userId": "me", "labelIds": ["INBOX", unknown_label_id], "maxResults": 500}
                if page_token:
                    kwargs["pageToken"] = page_token
                result = service.users().messages().list(**kwargs).execute()
                all_msg_ids.extend(m["id"] for m in result.get("messages", []))
                page_token = result.get("nextPageToken")
                if not page_token:
                    break

            total = len(all_msg_ids)
            _srv.db.set_archive_job(conn, user_id, job_id, "in_progress", total=total, progress=0)
            from claven.core.scan import _notify_progress
            _notify_progress(conn, user_id, "archive_started", job_id=job_id, total=total)
            conn.commit()
            logger.info("Archive job %s: %d messages to archive", job_id, total)

            if total == 0:
                _srv.db.set_archive_job(conn, user_id, job_id, "complete", total=0, progress=0)
                _notify_progress(conn, user_id, "archive_complete", job_id=job_id, total=0, progress=0)
                conn.commit()
                return

            # Archive in batches
            from claven.core.gmail import batch_remove_labels, _BATCH_LIMIT
            archived = 0
            for i in range(0, total, _BATCH_LIMIT):
                if not _should_continue_job(user_id):
                    _srv.db.set_archive_job(conn, user_id, job_id, "cancelled", total=total, progress=archived)
                    _notify_progress(conn, user_id, "archive_cancelled", job_id=job_id, total=total, progress=archived)
                    conn.commit()
                    logger.info("Archive job %s cancelled at %d/%d", job_id, archived, total)
                    return

                batch_ids = all_msg_ids[i:i + _BATCH_LIMIT]
                modified = batch_remove_labels(service, batch_ids, ["INBOX"])
                archived += modified
                _srv.db.set_archive_job(conn, user_id, job_id, "in_progress", total=total, progress=archived)
                _notify_progress(conn, user_id, "archive_progress", job_id=job_id, total=total, progress=archived)
                conn.commit()

            _srv.db.set_archive_job(conn, user_id, job_id, "complete", total=total, progress=archived)
            _notify_progress(conn, user_id, "archive_complete", job_id=job_id, total=total, progress=archived)
            conn.commit()
            logger.info("Archive job %s complete: %d/%d archived", job_id, archived, total)
    except Exception as exc:
        logger.exception("Archive job %s failed: %s", job_id, exc)
        try:
            with _srv.db.get_connection() as conn:
                _srv.db.set_archive_job(conn, user_id, job_id, "error")
        except Exception:
            logger.exception("Failed to set archive job error status for %s", user_id)
    finally:
        with _srv.db.get_connection() as conn:
            _srv.db.clear_cancel_state(conn, user_id)
        _srv._resumed_jobs.discard(user_id)


def _run_reset_sent_scan(user_id: str, job_id: str):
    """Background task: remove claven/sent-scanned label from all sent messages."""
    logger.info("Reset sent scan job %s started for %s", job_id, user_id)

    # Wait for running scans to exit (cancel_scans was set by the endpoint)
    import time as _time
    with _srv._threads_lock:
        threads = [t for t in _srv._active_threads if t is not threading.current_thread()]
    logger.debug("_run_reset_sent_scan: waiting for %d threads to exit", len(threads))
    for t in threads:
        t.join(timeout=10)
    logger.debug("_run_reset_sent_scan: threads joined, proceeding")

    try:
        with _srv.db.get_connection() as conn:
            if not _srv.db.try_lock_user_scan(conn, user_id):
                logger.info("Reset sent scan job %s skipped — locked", job_id)
                return

            service = _srv.auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])
            logger.debug("_run_reset_sent_scan: acquired lock, got service")

        from claven.core.scan import SENT_SCANNED_LABEL
        from claven.core.gmail import gmail_retry
        all_labels = gmail_retry(lambda: service.users().labels().list(userId="me").execute()).get("labels", [])
        scanned_label_id = next((l["id"] for l in all_labels if l["name"] == SENT_SCANNED_LABEL), None)
        if not scanned_label_id:
            logger.warning("Reset sent scan job %s: label not found", job_id)
            with _srv.db.get_connection() as conn:
                _srv.db.set_reset_sent_job(conn, user_id, job_id, "complete", total=0, progress=0)
            return

        # Deep count — paginate to get all message IDs
        all_msg_ids = []
        page_token = None
        while True:
            kw = {"userId": "me", "labelIds": [scanned_label_id], "maxResults": 500}
            if page_token:
                kw["pageToken"] = page_token
            result = gmail_retry(lambda kw=kw: service.users().messages().list(**kw).execute())
            all_msg_ids.extend(m["id"] for m in result.get("messages", []))
            page_token = result.get("nextPageToken")
            if not page_token:
                break
            _time.sleep(0.5)  # Pace pagination to avoid quota exhaustion

        total = len(all_msg_ids)
        from claven.core.scan import _notify_progress
        with _srv.db.get_connection() as conn:
            _srv.db.set_reset_sent_job(conn, user_id, job_id, "in_progress", total=total, progress=0)
            _notify_progress(conn, user_id, "reset_sent_started", job_id=job_id, total=total)
        logger.info("Reset sent scan job %s: %d messages to reset", job_id, total)

        if total == 0:
            with _srv.db.get_connection() as conn:
                _srv.db.set_reset_sent_job(conn, user_id, job_id, "complete", total=0, progress=0)
                _notify_progress(conn, user_id, "reset_sent_complete", job_id=job_id, total=0, progress=0)
            return

        # Remove labels in batches with fresh connections
        from claven.core.gmail import batch_remove_labels, _BATCH_LIMIT
        removed = 0
        for i in range(0, total, _BATCH_LIMIT):
            if not _should_continue_job(user_id):
                with _srv.db.get_connection() as conn:
                    _srv.db.set_reset_sent_job(conn, user_id, job_id, "cancelled", total=total, progress=removed)
                    _notify_progress(conn, user_id, "reset_sent_cancelled", job_id=job_id, total=total, progress=removed)
                logger.info("Reset sent scan job %s cancelled at %d/%d", job_id, removed, total)
                return

            batch_ids = all_msg_ids[i:i + _BATCH_LIMIT]
            modified = batch_remove_labels(service, batch_ids, [scanned_label_id])
            removed += modified
            with _srv.db.get_connection() as conn:
                _srv.db.set_reset_sent_job(conn, user_id, job_id, "in_progress", total=total, progress=removed)
                _notify_progress(conn, user_id, "reset_sent_progress", job_id=job_id, total=total, progress=removed)

        # Reset sent scan status so it retriggers
        with _srv.db.get_connection() as conn:
            _srv.db.set_reset_sent_job(conn, user_id, job_id, "complete", total=total, progress=removed)
            _srv.db.set_sent_scan_status(conn, user_id, None)
            _notify_progress(conn, user_id, "reset_sent_complete", job_id=job_id, total=total, progress=removed)
        logger.info("Reset sent scan job %s complete: %d/%d removed", job_id, removed, total)
    except Exception as exc:
        logger.exception("Reset sent scan job %s failed: %s", job_id, exc)
        try:
            with _srv.db.get_connection() as conn:
                _srv.db.set_reset_sent_job(conn, user_id, job_id, "error")
        except Exception:
            logger.exception("Failed to set reset sent scan job error status for %s", user_id)
    finally:
        with _srv.db.get_connection() as conn:
            _srv.db.clear_cancel_state(conn, user_id)
        _srv._resumed_jobs.discard(user_id)
