"""Database access layer — all reads and writes go through this module.

All functions take an open psycopg2 connection as their first argument.
Transaction management (commit / rollback) is the caller's responsibility;
use get_connection() for production code or inject a test connection directly.
"""

import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras


@contextmanager
def get_connection(database_url: str | None = None):
    """Open a DB connection, commit on success, rollback on exception."""
    url = database_url or os.environ["DATABASE_URL"]
    conn = psycopg2.connect(url)
    psycopg2.extras.register_uuid(conn_or_curs=conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Users ─────────────────────────────────────────────────────────────────────

def upsert_user(conn, email: str) -> str:
    """Insert user if not present; return user_id as str."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (email)
            VALUES (%s)
            ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
            RETURNING id
            """,
            (email,),
        )
        return str(cur.fetchone()[0])


def get_user_by_email(conn, email: str) -> dict | None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id::text, email, created_at FROM users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(conn, user_id: str) -> dict | None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id::text, email, created_at FROM users WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_all_users(conn) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id::text, email, created_at FROM users")
        return [dict(row) for row in cur.fetchall()]


# ── Gmail tokens ──────────────────────────────────────────────────────────────

def store_tokens(
    conn,
    user_id: str,
    access_token_enc: bytes,
    refresh_token_enc: bytes,
    token_expiry,
    scopes: list[str],
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO gmail_tokens (user_id, access_token_enc, refresh_token_enc, token_expiry, scopes)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                access_token_enc = EXCLUDED.access_token_enc,
                refresh_token_enc = EXCLUDED.refresh_token_enc,
                token_expiry = EXCLUDED.token_expiry,
                scopes = EXCLUDED.scopes
            """,
            (user_id, access_token_enc, refresh_token_enc, token_expiry, scopes),
        )


def load_tokens(conn, user_id: str) -> dict | None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT access_token_enc, refresh_token_enc, token_expiry, scopes
            FROM gmail_tokens WHERE user_id = %s
            """,
            (user_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def delete_credentials(conn, user_id: str) -> None:
    """Remove gmail_tokens and scan_state for a user (keeps the users row)."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM gmail_tokens WHERE user_id = %s", (user_id,))
        cur.execute("DELETE FROM scan_state WHERE user_id = %s", (user_id,))


def clear_watch_state(conn, user_id: str) -> None:
    """Clear the Gmail watch without losing scan progress.

    Nulls out history_id so polling/webhook processing stops, but keeps
    processed_count, sent scan state, and known senders intact. The user
    can resume filtering with a single click (no re-scan required).
    """
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_state SET history_id = 0, updated_at = NOW() WHERE user_id = %s",
            (user_id,),
        )


# ── Scan state ────────────────────────────────────────────────────────────────

def try_lock_user_scan(conn, user_id: str) -> bool:
    """Attempt to acquire a row-level lock on the user's scan_state row.

    Uses SELECT ... FOR UPDATE SKIP LOCKED so a concurrent instance that
    already holds the lock gets False immediately (no blocking).  The lock
    is released when the transaction commits or rolls back.

    Returns True if the lock was acquired, False if another process holds it.
    Returns False if no scan_state row exists for this user.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM scan_state WHERE user_id = %s FOR UPDATE SKIP LOCKED",
            (user_id,),
        )
        return cur.fetchone() is not None


def get_history_id(conn, user_id: str) -> int | None:
    with conn.cursor() as cur:
        cur.execute("SELECT history_id FROM scan_state WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        return row[0] if row and row[0] else None


def set_history_id(conn, user_id: str, history_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_state (user_id, history_id)
            VALUES (%s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                history_id = EXCLUDED.history_id,
                updated_at = NOW()
            """,
            (user_id, history_id),
        )


def touch_last_processed(conn, user_id: str) -> None:
    """Set last_processed_at to NOW()."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_state SET last_processed_at = NOW() WHERE user_id = %s",
            (user_id,),
        )


def get_last_processed_at(conn, user_id: str):
    """Return last_processed_at timestamp or None."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT last_processed_at FROM scan_state WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None


def update_newest_labeled(conn, user_id: str, message_date_ms: int) -> None:
    """Update newest_labeled_at if the given message date is newer than what's stored."""
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(message_date_ms / 1000, tz=timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_state
            SET newest_labeled_at = GREATEST(COALESCE(newest_labeled_at, '1970-01-01'::timestamptz), %s)
            WHERE user_id = %s
            """,
            (dt, user_id),
        )


def get_newest_labeled_at(conn, user_id: str):
    """Return newest_labeled_at timestamp or None."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT newest_labeled_at FROM scan_state WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None


def is_inbox_scan_completed(conn, user_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT inbox_scan_completed FROM scan_state WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        return bool(row[0]) if row else False


def set_inbox_scan_completed(conn, user_id: str, completed: bool = True) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_state SET inbox_scan_completed = %s, updated_at = NOW() WHERE user_id = %s",
            (completed, user_id),
        )


def get_processed_count(conn, user_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT processed_count FROM scan_state WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        return row[0] if row else 0


def increment_processed_count(conn, user_id: str, n: int) -> None:
    if n <= 0:
        return
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_state SET processed_count = processed_count + %s WHERE user_id = %s",
            (n, user_id),
        )


def set_processed_count(conn, user_id: str, n: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_state SET processed_count = %s WHERE user_id = %s",
            (n, user_id),
        )


def get_sent_scan_cursor(conn, user_id: str) -> int | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sent_scan_cursor FROM scan_state WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None


def set_sent_scan_cursor(conn, user_id: str, cursor: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_state (user_id, history_id, sent_scan_cursor)
            VALUES (%s, 0, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                sent_scan_cursor = EXCLUDED.sent_scan_cursor,
                updated_at = NOW()
            """,
            (user_id, cursor),
        )


def get_sent_scan_progress(conn, user_id: str) -> dict:
    """Return sent scan progress: messages_scanned, messages_total, status, updated_at."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT sent_messages_scanned, sent_messages_total, sent_scan_status, updated_at FROM scan_state WHERE user_id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if row:
            return {"messages_scanned": row[0], "messages_total": row[1], "status": row[2], "updated_at": row[3]}
        return {"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}


def set_sent_scan_status(conn, user_id: str, status: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_state (user_id, history_id, sent_scan_status)
            VALUES (%s, 0, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                sent_scan_status = EXCLUDED.sent_scan_status,
                updated_at = NOW()
            """,
            (user_id, status),
        )


def set_sent_scan_progress(conn, user_id: str, scanned: int, total: int | None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_state (user_id, history_id, sent_messages_scanned, sent_messages_total)
            VALUES (%s, 0, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                sent_messages_scanned = EXCLUDED.sent_messages_scanned,
                sent_messages_total = EXCLUDED.sent_messages_total,
                updated_at = NOW()
            """,
            (user_id, scanned, total),
        )


# ── Sent recipients ───────────────────────────────────────────────────────────

def count_known_senders(conn, user_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM sent_recipients WHERE user_id = %s", (user_id,))
        return cur.fetchone()[0]


def get_known_senders(conn, user_id: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT email FROM sent_recipients WHERE user_id = %s", (user_id,))
        return {row[0] for row in cur.fetchall()}


def add_known_sender(conn, user_id: str, email_addr: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sent_recipients (user_id, email)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (user_id, email_addr),
        )


def bulk_add_known_senders(conn, user_id: str, email_addrs: list[str]) -> None:
    if not email_addrs:
        return
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO sent_recipients (user_id, email)
            VALUES %s
            ON CONFLICT DO NOTHING
            """,
            [(user_id, addr) for addr in email_addrs],
        )
