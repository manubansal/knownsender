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
    """Clear the Gmail watch / scan position without removing OAuth credentials.

    Use this for disconnect — the user stays authorized and can reconnect
    with a single click (no OAuth round-trip required).
    """
    with conn.cursor() as cur:
        cur.execute("DELETE FROM scan_state WHERE user_id = %s", (user_id,))


# ── Scan state ────────────────────────────────────────────────────────────────

def get_history_id(conn, user_id: str) -> int | None:
    with conn.cursor() as cur:
        cur.execute("SELECT history_id FROM scan_state WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None


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
