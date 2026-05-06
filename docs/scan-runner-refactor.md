# Refactor: Split server.py, Unified Task Runner, Error Classification

## Context
`claven/server.py` is 1,588 lines — a monolith containing OAuth, dashboard API, background task runners, SSE, webhooks, and internal endpoints. Five background task runners share a common lifecycle but implement it independently, causing:
- Raw exception strings leaking into the activity log
- Inconsistent error classification (only inbox scan classifies errors)
- Duplicated lock/status/cancel/error handling (~250 lines of boilerplate)
- Harder to debug: 5 different entry/exit points with different logging patterns

This refactor splits `server.py` into focused modules AND extracts a unified `_run_task` runner with proper error classification.

## Phase 1: Split server.py into modules

Split the 1,588-line monolith into 6 focused files using FastAPI's `APIRouter`.

### New file structure

**`claven/server.py`** (~150 lines) — App assembly
- `_CloudJsonFormatter`, logging setup
- `_shutdown_event`, `_active_threads`, `_resumed_jobs`, signal handler
- `_spawn_scan_thread`
- `lifespan` (startup/shutdown)
- `app = FastAPI(...)`, CORS middleware
- `app.include_router(...)` for all route modules

**`claven/server/auth_routes.py`** (~200 lines) — OAuth + session
- `_make_flow`, `_issue_session`, `_get_session`
- `_require_internal_auth`, `_verify_pubsub_token`
- `_redirect_base`, `_error_redirect`
- Routes: `/oauth/start`, `/oauth/callback`, `/api/logout`

**`claven/server/api_routes.py`** (~400 lines) — Dashboard API
- `_needs_sent_scan`, `_log_health`, `_label_id_cache_for_config`
- Routes: `/api/me`, `/api/config`, `/api/connect`, `/api/disconnect`, `/api/settings/scan-scope`, `/api/events`

**`claven/server/tasks.py`** (~300 lines) — Unified task runner + all background tasks
- `_classify_error`
- `_is_current_worker`, `_should_continue_scan`, `_should_continue_job`
- `_cancel_scans_and_wait`, `_cleanup_job`
- `_run_task` (unified runner)
- `_run_sent_scan`, `_run_relabel_scan`, `_run_inbox_scan`
- `_run_archive_unknown`, `_run_reset_sent_scan`

**`claven/server/action_routes.py`** (~100 lines) — Action endpoints
- Routes: `/api/actions/archive-unknown`, `/api/actions/reset-sent-scan`, `/api/actions/cancel`

**`claven/server/internal_routes.py`** (~100 lines) — Internal + webhook
- Routes: `/internal/poll`, `/internal/build-known-senders`, `/webhook/gmail`

### Shared state access

Module-level globals (`_shutdown_event`, `_active_threads`, `_threads_lock`, `_resumed_jobs`, `_worker_id`, `_spawn_scan_thread`) live in `server.py` and are imported by other modules:

```python
# In tasks.py, api_routes.py, etc:
from claven.server import _shutdown_event, _active_threads, _spawn_scan_thread, ...
```

### `__init__.py`

Create `claven/server/__init__.py` that re-exports `app` for backwards compatibility:
```python
from claven.server.app import app
```

Wait — this conflicts with the existing `claven/server.py` file. We need to either:
- **Option A**: Rename `claven/server.py` → `claven/server/app.py`, add `__init__.py`
- **Option B**: Keep `claven/server.py` as the assembly point, put route modules in `claven/routes/`

**Recommend Option B** — simpler, no import path changes:
- `claven/server.py` stays as the app entry point (uvicorn target unchanged)
- `claven/routes/auth.py`, `claven/routes/api.py`, `claven/routes/actions.py`, `claven/routes/internal.py`
- `claven/tasks.py` for the task runner and background tasks

This avoids the package-vs-module conflict entirely.

### Revised file structure (Option B)

```
claven/
  server.py           (~200 lines) — app assembly, lifespan, shared state
  tasks.py            (~300 lines) — _run_task, all 5 runners, helpers
  routes/
    __init__.py
    auth.py           (~200 lines) — OAuth + session
    api.py            (~400 lines) — /api/me, /api/config, etc.
    actions.py        (~100 lines) — /api/actions/*
    internal.py       (~100 lines) — /internal/*, /webhook/*
```

## Phase 2: Unified task runner + error classification

### `_classify_error(exc) -> str`

In `claven/tasks.py`:

```python
def _classify_error(exc: Exception) -> str:
    """Map an exception to a health code label."""
    exc_str = str(exc).lower()
    if "connection" in exc_str or "closed" in exc_str or "ssl" in exc_str:
        return "error.db.connection_lost"
    if "429" in exc_str or "rate" in exc_str:
        return "error.gmail.rate_limited"
    if "401" in exc_str or "403" in exc_str or "token" in exc_str or "invalid_grant" in exc_str:
        return "error.gmail.auth_expired"
    if "quota" in exc_str:
        return "error.gmail.quota_exhausted"
    if "HttpError" in type(exc).__name__ or "gmail" in exc_str:
        return "error.gmail.api"
    return "error.unknown"
```

### `_run_task` signature

```python
def _run_task(
    user_id: str,
    task_name: str,                  # "Sent scan", "Label scan", "Archive", etc.
    task_fn,                         # fn(service) → count
    set_status,                      # fn(conn, user_id, status) — normalized
    chain: list[callable] = None,    # next runners on success
    should_continue = None,          # default: _should_continue_scan
    wait_for_threads: bool = False,  # jobs: wait for scans to drain
    cleanup: callable = None,        # jobs: clear cancel_state + _resumed_jobs
):
```

### How differences are handled

| Aspect | Scans use | Jobs use |
|---|---|---|
| `should_continue` | default (`_should_continue_scan`) | `lambda: _should_continue_job(user_id)` |
| `wait_for_threads` | `False` (default) | `True` |
| `cleanup` | `None` (default) | `lambda: _cleanup_job(user_id)` |
| `set_status` | `db.set_sent_scan_status` etc. | Closure capturing job_id |
| `chain` | Sent: `[_run_relabel_scan, _run_inbox_scan]` | `None` |
| `task_fn` | Delegates to core scan function | Own batch loop with progress |

### `_run_task` pseudocode

```python
def _run_task(user_id, task_name, task_fn, set_status,
              chain=None, should_continue=None, wait_for_threads=False, cleanup=None):
    if should_continue is None:
        should_continue = lambda: _should_continue_scan(user_id)

    logger.info("%s started for %s (pid=%d)", task_name, user_id, os.getpid())

    if wait_for_threads:
        with _threads_lock:
            threads = [t for t in _active_threads if t is not threading.current_thread()]
        logger.debug("_run_task[%s]: waiting for %d threads", task_name, len(threads))
        for t in threads:
            t.join(timeout=10)

    try:
        with db.get_connection() as conn:
            if not db.try_lock_user_scan(conn, user_id):
                logger.info("%s skipped — locked", task_name)
                return
            set_status(conn, user_id, "in_progress")
            db.log_event(conn, user_id, "scan", f"{task_name} started")
            service = auth.get_service(conn, user_id, os.environ["TOKEN_ENCRYPTION_KEY"])

        count = task_fn(service)
        logger.debug("_run_task[%s]: returned count=%s", task_name, count)

        if not should_continue():
            logger.debug("_run_task[%s]: cancelled", task_name)
            with db.get_connection() as conn:
                set_status(conn, user_id, "cancelled")
                db.log_event(conn, user_id, "scan", f"{task_name} cancelled")
            return

        with db.get_connection() as conn:
            set_status(conn, user_id, "complete")
            db.log_event(conn, user_id, "scan", f"{task_name} complete — {count} processed")

    except Exception as exc:
        error_label = _classify_error(exc)
        logger.exception("%s failed: %s (classified: %s)", task_name, user_id, exc, error_label)
        try:
            with db.get_connection() as conn:
                set_status(conn, user_id, error_label)
                db.log_event(conn, user_id, "error", f"{task_name} failed — {error_label}")
        except Exception:
            logger.exception("Failed to set error status for %s", user_id)
        return

    finally:
        if cleanup:
            cleanup()

    # Chain on success (after cleanup)
    for next_task in (chain or []):
        logger.debug("_run_task[%s]: chaining to %s", task_name, next_task.__name__)
        next_task(user_id)
```

### Refactored callers (all in `claven/tasks.py`)

**`_run_sent_scan(user_id)`**:
```python
def _run_sent_scan(user_id):
    def task_fn(service):
        return build_known_senders(service, None, user_id,
            should_continue=lambda: _should_continue_scan(user_id),
            shutdown_event=_shutdown_event)
    _run_task(user_id, "Sent scan", task_fn,
              set_status=db.set_sent_scan_status,
              chain=[_run_relabel_scan, _run_inbox_scan])
```

**`_run_relabel_scan(user_id)`**:
```python
def _run_relabel_scan(user_id):
    def task_fn(service):
        label_configs = load_config().get("labels", [])
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        return relabel_scan(service, user_id, label_configs, label_id_cache,
            should_continue=lambda: _should_continue_scan(user_id),
            shutdown_event=_shutdown_event)
    _run_task(user_id, "Relabel scan", task_fn,
              set_status=lambda conn, uid, s: None)
```

**`_run_inbox_scan(user_id)`**:
```python
def _run_inbox_scan(user_id):
    def task_fn(service):
        label_configs = load_config().get("labels", [])
        with db.get_connection() as conn:
            scope = db.get_scan_scope(conn, user_id)
            known_senders = db.get_known_senders(conn, user_id)
        label_id_cache = _label_id_cache_for_config(service, label_configs)
        return scan_inbox(service, None, user_id, label_configs,
            label_id_cache, known_senders,
            should_continue=lambda: _should_continue_scan(user_id),
            shutdown_event=_shutdown_event, scope=scope)
    _run_task(user_id, "Label scan", task_fn,
              set_status=db.set_inbox_scan_status)
```

**`_run_archive_unknown(user_id, job_id)`**:
```python
def _run_archive_unknown(user_id, job_id):
    def task_fn(service):
        # existing batch loop with _should_continue_job, progress updates
        # returns archived count
        ...
    _run_task(user_id, "Archive", task_fn,
              set_status=lambda conn, uid, s: db.set_archive_job(conn, uid, job_id, s),
              should_continue=lambda: _should_continue_job(user_id),
              wait_for_threads=True,
              cleanup=lambda: _cleanup_job(user_id))
```

**`_run_reset_sent_scan(user_id, job_id)`**:
```python
def _run_reset_sent_scan(user_id, job_id):
    def task_fn(service):
        # existing batch loop with _should_continue_job, progress updates
        # resets sent_scan_status at end
        # returns removed count
        ...
    _run_task(user_id, "Reset sent scan", task_fn,
              set_status=lambda conn, uid, s: db.set_reset_sent_job(conn, uid, job_id, s),
              should_continue=lambda: _should_continue_job(user_id),
              wait_for_threads=True,
              cleanup=lambda: _cleanup_job(user_id))
```

### `chain` design note

The `chain` loop runs after the try/except/finally — only on success, after cleanup:
- Task fails → exception path returns early, no chaining
- Task cancelled → cancel path returns early, no chaining
- Cleanup always runs (finally)
- Chain only on success

## Phase 3: Dashboard error code on sent scan

When `sent_scan_status` starts with `"error"`, display the health code as a clickable monospace pill on the sent scan header (same pattern as inbox scan). The API already returns `sent_scan_status` which will now contain the classified label.

## Implementation order

Each step gets its own commit (no amending). This keeps each change visible as a separate commit hash for easy review and bisect.

1. **Split files first** — create `claven/routes/` and `claven/tasks.py`, move code, verify tests pass (pure restructure, no behavior change). Commit.
2. **Add `_classify_error` + `_run_task`** — replace 5 runner implementations, verify tests pass. Commit.
3. **Dashboard error code** — add sent scan error code display. Commit.
4. **Tests** — `TestClassifyError` class, update any broken mock targets from the file split. Commit.

## What does NOT change
- Core scan functions in `claven/core/scan.py`
- Database layer in `claven/core/db.py`
- Health codes in `claven/core/health.py`
- Inner logic of each task (batch loops, progress, Gmail queries) — stays in `task_fn` closures
- `_should_continue_scan` / `_should_continue_job` — unchanged
- uvicorn entry point: still `claven.server:app`

## Verification
```bash
# After each phase:
python -m pytest tests/ -x -q --tb=short -m "not live"
cd web && npm test

# Manual: trigger auth error, verify classified label in activity log
```
