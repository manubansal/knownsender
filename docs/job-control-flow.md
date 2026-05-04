# Job Control Flow

How Claven coordinates scan loops, exclusive jobs, and cancellation.

## Job types

### Scan loops (continuous)

Run in sequence, triggered by `/api/connect`, `/api/me` retrigger, or `oauth_callback`:

1. **Sent scan** (`build_known_senders`) — scans sent mail, builds known senders list
2. **Relabel scan** (`relabel_scan`) — swaps unknown-sender → known-sender for newly discovered known senders
3. **Label scan** (`scan_inbox`) — labels unlabeled messages as known-sender or unknown-sender

These run as a chain: sent → relabel → label. Each checks `should_continue()` per batch and exits if cancelled.

### Exclusive jobs (one-off)

User-initiated actions that require no scan loops running:

- **Archive unknown-sender** — removes INBOX label from unknown-sender messages
- **Reset sent scan** — removes `claven/sent-scanned` label, triggering a full re-scan

Exclusive jobs and scan loops cannot run concurrently for the same user. An exclusive job must cancel running scans before starting.

## Cancellation

### Cancel flag

`scan_state.cancel_requested_at TIMESTAMPTZ` — per-user, stored in the database.

- `NULL` — no cancel, scans run normally
- Non-NULL — cancel requested, scan loops exit on their next batch boundary

### Who checks it

Every scan loop checks the cancel flag once per batch via `should_continue()`:

```python
def _should_continue(user_id):
    if not _is_current_worker():       # global: shutdown or worker replaced
        return False
    with db.get_connection() as conn:
        cancel = db.get_cancel_requested(conn, user_id)
        return cancel is None           # NULL = keep running
```

This covers all cancel reasons with one check — exclusive jobs, disconnect, pause.

### Who sets it

| Action | Sets cancel | Clears cancel |
|---|---|---|
| Archive unknown-sender | Before starting job | After job completes or is cancelled |
| Reset sent scan | Before starting job | After job completes or is cancelled |
| Pause labeling / Disconnect | Before clearing watch state | After watch state cleared |
| Server restart (lifespan) | N/A | Clears all cancel flags on startup |

### Cancel lifecycle

Every exclusive job follows the same sequence, whether started by a user click or resumed after a crash:

1. **Set cancel**: `UPDATE scan_state SET cancel_requested_at = NOW() WHERE user_id = %s`
2. **Wait**: poll active threads or short timeout until scan loops exit
3. **Run job**: the exclusive operation (archive, reset, etc.)
4. **Clear cancel**: `UPDATE scan_state SET cancel_requested_at = NULL WHERE user_id = %s`

This is the same code path for fresh starts and crash recovery — no special cases.

## Startup priority order

When `/api/me` runs (every dashboard load), it evaluates work in priority order:

```
1. Lifespan startup already cleared stale cancel flags
2. Check for incomplete exclusive jobs (archive, reset)
   → If found: set cancel → wait for scans to stop → resume job
   → Blocks all subsequent steps until complete
3. Check for stalled scans (in_progress + last_fetched_at > 2min)
   → Reset to error status
4. Auto-clear error status when unlabeled count is 0
5. Check for unlabeled messages + scan not running
   → Retrigger scan chain (sent → relabel → label)
```

Step 2 blocks step 5 — scan loops never start while an exclusive job is pending.

## Row locking

`try_lock_user_scan()` uses `SELECT ... FOR UPDATE SKIP LOCKED` on `scan_state`. This prevents two processes from running the same user's scans concurrently. If the lock is taken, the second caller skips.

The cancel flag is separate from the row lock — it's a cooperative signal. The lock prevents concurrent execution; the cancel flag requests graceful exit.

## Fault tolerance

### Scan loop crash
- Status stuck at `in_progress` → stalled detection resets to error → retrigger resumes
- Per-batch fresh DB connections prevent Neon idle timeout
- Labels applied to Gmail are permanent; DB progress may lag but catches up on retry

### Exclusive job crash
- Job status stuck at `in_progress` in DB → detected on next `/api/me` → resumed
- Cancel flag may be stale → cleared on server restart (lifespan)
- Job itself is idempotent — restarting from scratch is safe

### Server crash
- Lifespan startup clears cancel flags and thread registry
- `/api/me` priority order detects incomplete jobs and resumes them
- No manual intervention required

## Global vs per-user cancellation

| Scope | Mechanism | When |
|---|---|---|
| Global (all users) | `_shutdown_event` (in-memory threading.Event) | SIGTERM, SIGINT, lifespan shutdown |
| Per-user | `cancel_requested_at` (DB column) | Exclusive jobs, disconnect, pause |

Both are checked by `should_continue()`. Global takes precedence (checked first).
