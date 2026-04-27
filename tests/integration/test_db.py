"""Integration tests for claven/core/db.py — require a real Postgres database.

Run with: PYTEST_DATABASE_URL=postgresql://... pytest -m integration
"""

import pytest

import claven.core.db as db

pytestmark = pytest.mark.integration


class TestUpsertUser:
    def test_creates_new_user(self, db_conn):
        user_id = db.upsert_user(db_conn, "new@example.com")
        assert user_id is not None
        assert isinstance(user_id, str)

    def test_returns_same_id_for_duplicate_email(self, db_conn):
        id1 = db.upsert_user(db_conn, "dup@example.com")
        id2 = db.upsert_user(db_conn, "dup@example.com")
        assert id1 == id2

    def test_different_emails_get_different_ids(self, db_conn):
        id1 = db.upsert_user(db_conn, "alice@example.com")
        id2 = db.upsert_user(db_conn, "bob@example.com")
        assert id1 != id2


class TestGetUser:
    def test_get_user_by_email_found(self, db_conn):
        user_id = db.upsert_user(db_conn, "lookup@example.com")
        user = db.get_user_by_email(db_conn, "lookup@example.com")
        assert user is not None
        assert user["email"] == "lookup@example.com"
        assert user["id"] == user_id

    def test_get_user_by_email_missing_returns_none(self, db_conn):
        result = db.get_user_by_email(db_conn, "missing@example.com")
        assert result is None

    def test_get_all_users_includes_created_users(self, db_conn):
        db.upsert_user(db_conn, "ua@example.com")
        db.upsert_user(db_conn, "ub@example.com")
        users = db.get_all_users(db_conn)
        emails = {u["email"] for u in users}
        assert "ua@example.com" in emails
        assert "ub@example.com" in emails


class TestTokens:
    def test_store_and_load_round_trip(self, db_conn):
        user_id = db.upsert_user(db_conn, "tokens@example.com")
        db.store_tokens(db_conn, user_id, b"access-enc", b"refresh-enc", None, ["scope1"])
        row = db.load_tokens(db_conn, user_id)
        assert row is not None
        assert bytes(row["access_token_enc"]) == b"access-enc"
        assert bytes(row["refresh_token_enc"]) == b"refresh-enc"
        assert row["scopes"] == ["scope1"]

    def test_load_tokens_missing_returns_none(self, db_conn):
        user_id = db.upsert_user(db_conn, "notokens@example.com")
        assert db.load_tokens(db_conn, user_id) is None

    def test_store_tokens_overwrites_existing(self, db_conn):
        user_id = db.upsert_user(db_conn, "overwrite@example.com")
        db.store_tokens(db_conn, user_id, b"old-access", b"old-refresh", None, [])
        db.store_tokens(db_conn, user_id, b"new-access", b"new-refresh", None, ["s"])
        row = db.load_tokens(db_conn, user_id)
        assert bytes(row["access_token_enc"]) == b"new-access"
        assert bytes(row["refresh_token_enc"]) == b"new-refresh"


class TestScanState:
    def test_set_and_get_history_id(self, db_conn):
        user_id = db.upsert_user(db_conn, "history@example.com")
        db.set_history_id(db_conn, user_id, 12345)
        assert db.get_history_id(db_conn, user_id) == 12345

    def test_get_history_id_missing_returns_none(self, db_conn):
        user_id = db.upsert_user(db_conn, "nohistory@example.com")
        assert db.get_history_id(db_conn, user_id) is None

    def test_set_history_id_overwrites(self, db_conn):
        user_id = db.upsert_user(db_conn, "updatehist@example.com")
        db.set_history_id(db_conn, user_id, 100)
        db.set_history_id(db_conn, user_id, 200)
        assert db.get_history_id(db_conn, user_id) == 200


class TestSentRecipients:
    def test_add_and_get_known_senders(self, db_conn):
        user_id = db.upsert_user(db_conn, "senders@example.com")
        db.add_known_sender(db_conn, user_id, "alice@test.com")
        senders = db.get_known_senders(db_conn, user_id)
        assert "alice@test.com" in senders

    def test_add_known_sender_idempotent(self, db_conn):
        user_id = db.upsert_user(db_conn, "idem@example.com")
        db.add_known_sender(db_conn, user_id, "bob@test.com")
        db.add_known_sender(db_conn, user_id, "bob@test.com")  # no error
        senders = db.get_known_senders(db_conn, user_id)
        # No duplicates — it's a set
        assert senders == {"bob@test.com"}

    def test_bulk_add_known_senders(self, db_conn):
        user_id = db.upsert_user(db_conn, "bulk@example.com")
        db.bulk_add_known_senders(db_conn, user_id, ["x@a.com", "y@b.com", "z@c.com"])
        assert db.get_known_senders(db_conn, user_id) == {"x@a.com", "y@b.com", "z@c.com"}

    def test_bulk_add_empty_list_is_noop(self, db_conn):
        user_id = db.upsert_user(db_conn, "emptyrecip@example.com")
        db.bulk_add_known_senders(db_conn, user_id, [])  # must not raise
        assert db.get_known_senders(db_conn, user_id) == set()

    def test_get_known_senders_empty(self, db_conn):
        user_id = db.upsert_user(db_conn, "nosenders@example.com")
        assert db.get_known_senders(db_conn, user_id) == set()
