# Test Plan: Graceful Shutdown System

## Context

The server uses daemon threads for background scans (sent scan, inbox scan). These threads could orphan uvicorn processes on Ctrl+C because:
1. `time.sleep()` in scan loops blocked for the full duration even after shutdown signal
2. No thread registry or join — threads were abandoned on shutdown
3. No graceful shutdown timeout on uvicorn — SSE connections kept workers alive

The fix added three layers:
- `threading.Event` (`_shutdown_event`) replaces a boolean flag — threads can `.wait()` on it
- Thread registry (`_active_threads`) + FastAPI `lifespan` joins threads on shutdown
- `_interruptible_sleep()` replaces `time.sleep()` — wakes instantly when event is set
- Makefile adds `--timeout-graceful-shutdown 3` and pre-start cleanup

None of this logic has test coverage. This plan adds 25 tests.

## Files to modify

- `tests/test_scan.py` — 8 new tests
- `tests/server/test_server.py` — 17 new tests across 6 new classes

## Code under test

### `claven/core/scan.py`

```python
def _interruptible_sleep(seconds, shutdown_event=None):
    if shutdown_event is not None:
        shutdown_event.wait(seconds)
    else:
        time.sleep(seconds)
```

`build_known_senders(..., shutdown_event=None)` and `scan_inbox(..., shutdown_event=None)` use `_interruptible_sleep()` for all sleep calls (1s between batches, 5s on errors).

### `claven/server.py`

```python
_worker_id = os.getpid()
_shutdown_event = threading.Event()
_active_threads: list[threading.Thread] = []
_threads_lock = threading.Lock()

def _shutdown_handler(signum, frame):
    _shutdown_event.set()

def _spawn_scan_thread(target, args):
    t = threading.Thread(target=target, args=args, daemon=True)
    with _threads_lock:
        _active_threads.append(t)
    t.start()
    return t

@asynccontextmanager
async def lifespan(app):
    _shutdown_event.clear()
    _active_threads.clear()
    yield
    _shutdown_event.set()
    for t in list(_active_threads):
        t.join(timeout=5)
    _active_threads.clear()

def _is_current_worker():
    if _shutdown_event.is_set():
        return False
    return os.getpid() == _worker_id
```

---

## Tests: `tests/test_scan.py`

### Class: `TestInterruptibleSleep` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 1 | `test_falls_back_to_time_sleep_without_event` | No event -> delegates to `time.sleep` | Patch `time.sleep`, call with `None`, assert `time.sleep` called with correct seconds |
| 2 | `test_uses_event_wait_when_event_provided` | Event provided -> uses `event.wait()`, NOT `time.sleep` | Real Event (not set), patch `time.sleep`, call with 0.01s timeout, assert `time.sleep` NOT called |
| 3 | `test_returns_immediately_when_event_already_set` | Set event -> instant return | Set event, call with 10s timeout, assert <0.1s elapsed |
| 4 | `test_wakes_when_event_set_during_sleep` | Event set mid-sleep -> wakes immediately | `Timer(0.05, event.set)`, call with 10s timeout, assert <0.5s elapsed |

### Class: `TestBuildKnownSenders` (add to existing)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 5 | `test_passes_shutdown_event_to_interruptible_sleep` | `shutdown_event` wired through to sleep calls | Patch `_interruptible_sleep`, pass event, verify calls include event arg |
| 6 | `test_error_uses_interruptible_sleep_with_event` | Error backoff uses interruptible sleep | Make `batch_get_message_metadata` raise, verify `_interruptible_sleep(5, event)` called |

### Class: `TestScanInbox` (add to existing)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 7 | `test_passes_shutdown_event_to_interruptible_sleep` | Same as #5 for scan_inbox | Patch `_interruptible_sleep`, pass event, verify calls include event arg |
| 8 | `test_error_uses_interruptible_sleep_with_event` | Same as #6 for scan_inbox | Make `batch_get_message_headers` raise, verify `_interruptible_sleep(5, event)` called |

---

## Tests: `tests/server/test_server.py`

### Class: `TestIsCurrentWorker` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 9 | `test_returns_true_normally` | Event clear + PID matches -> True | Import, assert True. Cleanup: ensure event clear |
| 10 | `test_returns_false_when_shutdown_event_set` | Event set -> False | `_shutdown_event.set()`, assert False. Cleanup: `.clear()` |
| 11 | `test_returns_false_when_pid_changed` | PID mismatch -> False | `patch("claven.server._worker_id", os.getpid() + 1)`, assert False |

### Class: `TestShutdownHandler` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 12 | `test_sets_shutdown_event` | Handler sets the event | Call `_shutdown_handler(SIGTERM, None)`, assert `is_set()`. Cleanup: `.clear()` |
| 13 | `test_is_idempotent` | Safe to call twice | Call twice, no exception, still `is_set()`. Cleanup: `.clear()` |

### Class: `TestSpawnScanThread` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 14 | `test_creates_daemon_thread` | Thread is daemon=True, start() called | Mock `threading.Thread`, verify kwargs. Cleanup: clear `_active_threads` |
| 15 | `test_adds_thread_to_active_threads` | Thread added to registry | Real short-lived thread, verify in `_active_threads`. Cleanup: join + clear |
| 16 | `test_starts_the_thread` | Thread actually runs | Thread sets an Event, verify Event set. Cleanup: join + clear |
| 17 | `test_passes_args_to_target` | Args forwarded correctly | Thread records args, verify. Cleanup: join + clear |

### Class: `TestLifespanStartup` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 18 | `test_clears_shutdown_event` | Startup clears event | Set event before TestClient, assert clear inside `with` block |
| 19 | `test_clears_active_threads` | Startup clears thread list | Add mock thread before TestClient, assert empty inside `with` block |

### Class: `TestLifespanShutdown` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 20 | `test_sets_shutdown_event` | Shutdown sets event | Assert clear inside TestClient, assert set after exit |
| 21 | `test_joins_threads` | Threads joined with timeout | Insert mock threads after startup, verify `.join(timeout=5)` after exit |
| 22 | `test_clears_active_threads` | Thread list cleared after shutdown | Insert mock threads after startup, verify empty after exit |
| 23 | `test_logs_warning_for_stuck_threads` | Warning logged when threads survive timeout | Mock thread with `is_alive()=True`, verify `logger.warning` called |

### Class: `TestGracefulShutdownIntegration` (new)

| # | Method | What it tests | Approach |
|---|--------|---------------|----------|
| 24 | `test_spawned_thread_exits_on_shutdown` | Full flow: spawn -> lifespan shutdown -> thread exits | Spawn thread looping on `_shutdown_event.wait()`, exit TestClient, verify `is_alive()` is False |
| 25 | `test_multiple_threads_all_exit` | Multiple threads all exit on shutdown | Spawn 3 threads, exit TestClient, verify all dead |

---

## Cleanup strategy

- `_shutdown_event`: `.clear()` in try/finally, or rely on TestClient lifespan startup auto-clear
- `_active_threads`: `.clear()` with lock, or rely on lifespan auto-clear
- `_worker_id`: use `patch()` context manager for auto-restore

## Verification

```bash
python -m pytest tests/test_scan.py tests/server/test_server.py -x -q
```
