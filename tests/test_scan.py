"""Tests for build_known_senders — DB-backed known senders scan from Sent mail."""
import pytest
from unittest.mock import MagicMock, patch, call


def _make_service():
    return MagicMock()


def _make_conn(cursor=None, count=0):
    """Return a mock DB connection pre-configured with common return values."""
    conn = MagicMock()
    return conn


def _msg(msg_id, to=None, cc=None, bcc=None):
    """Build a fake Gmail message metadata payload."""
    headers = []
    if to:
        headers.append({"name": "To", "value": to})
    if cc:
        headers.append({"name": "Cc", "value": cc})
    if bcc:
        headers.append({"name": "Bcc", "value": bcc})
    return {"id": msg_id, "payload": {"headers": headers}}


# ---------------------------------------------------------------------------
# Full scan (no cursor in DB)
# ---------------------------------------------------------------------------

class TestFullScan:
    def test_fetches_all_sent_messages(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=2), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]) as mock_list, \
             patch("claven.core.scan.get_message", side_effect=[
                 _msg("s1", to="alice@example.com"),
                 _msg("s2", to="bob@example.com"),
             ]), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        mock_list.assert_called_once_with(service, query="in:sent", max_results=None)

    def test_inserts_recipients_into_db(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=2), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]), \
             patch("claven.core.scan.get_message", side_effect=[
                 _msg("s1", to="alice@example.com"),
                 _msg("s2", to="bob@example.com"),
             ]), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted

    def test_extracts_cc_and_bcc(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=3), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.get_message", return_value=_msg(
                 "s1", to="alice@example.com", cc="bob@example.com", bcc="carol@example.com"
             )), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted
        assert "carol@example.com" in all_inserted

    def test_inserts_lowercase_addresses(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=1), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="Alice@Example.COM")), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "Alice@Example.COM" not in all_inserted

    def test_no_sent_messages_still_saves_cursor(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.count_known_senders", return_value=0), \
             patch("claven.core.scan.list_messages", return_value=[]), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            result = build_known_senders(service, conn, "user-1")
        mock_cursor.assert_called_once_with(conn, "user-1", 99)
        assert result["known_senders"] == 0
        assert result["messages_scanned"] == 0

    def test_saves_cursor_after_full_scan(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.count_known_senders", return_value=1), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="alice@example.com")), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "42"}):
            build_known_senders(service, conn, "user-1")
        mock_cursor.assert_called_once_with(conn, "user-1", 42)

    def test_returns_known_senders_count_and_messages_scanned(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=7), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}, {"id": "s3"}]), \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="alice@example.com")), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            result = build_known_senders(service, conn, "user-1")
        assert result["known_senders"] == 7
        assert result["messages_scanned"] == 3


# ---------------------------------------------------------------------------
# Incremental update (cursor exists in DB)
# ---------------------------------------------------------------------------

class TestIncrementalUpdate:
    def test_uses_history_api_when_cursor_exists(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", return_value=[]) as mock_history, \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=5), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "101"}):
            result = build_known_senders(service, conn, "user-1")
        mock_history.assert_called_once_with(service, 100, label_id="SENT")
        assert result["messages_scanned"] == 0

    def test_inserts_new_recipients_from_history(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        history = [{"messagesAdded": [{"message": {"id": "s2", "labelIds": ["SENT"]}}]}]
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", return_value=history), \
             patch("claven.core.scan.get_message", return_value=_msg("s2", to="bob@example.com")), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=2), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "101"}):
            result = build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "bob@example.com" in all_inserted
        assert result["messages_scanned"] == 1

    def test_ignores_non_sent_messages_in_history(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        history = [{"messagesAdded": [{"message": {"id": "m1", "labelIds": ["INBOX"]}}]}]
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", return_value=history), \
             patch("claven.core.scan.get_message") as mock_get, \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=0), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "101"}):
            build_known_senders(service, conn, "user-1")
        mock_get.assert_not_called()

    def test_updates_cursor_after_incremental_update(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", return_value=[]), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.count_known_senders", return_value=5), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "200"}):
            build_known_senders(service, conn, "user-1")
        mock_cursor.assert_called_once_with(conn, "user-1", 200)

    def test_expired_cursor_falls_back_to_full_scan(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", side_effect=Exception("404 historyId expired")), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]) as mock_list, \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="alice@example.com")), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=1), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        mock_list.assert_called_once_with(service, query="in:sent", max_results=None)

    def test_non_404_history_error_propagates(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=100), \
             patch("claven.core.scan.list_history", side_effect=Exception("500 Server Error")):
            with pytest.raises(Exception, match="500 Server Error"):
                build_known_senders(service, conn, "user-1")


# ---------------------------------------------------------------------------
# Interruption (should_continue)
# ---------------------------------------------------------------------------

class TestInterruption:
    def test_stops_processing_when_should_continue_returns_false(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        messages = [{"id": f"s{i}"} for i in range(10)]
        call_count = 0

        def stop_after_two():
            nonlocal call_count
            call_count += 1
            return call_count <= 2

        processed = []
        def fake_get(svc, msg_id, **kwargs):
            processed.append(msg_id)
            return _msg(msg_id, to=f"{msg_id}@example.com")

        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.get_message", side_effect=fake_get), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=2):
            result = build_known_senders(service, conn, "user-1", should_continue=stop_after_two)

        assert len(processed) <= 2
        assert result["messages_scanned"] == len(processed)

    def test_does_not_save_cursor_when_interrupted(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()

        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]), \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="alice@example.com")), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.count_known_senders", return_value=1):
            build_known_senders(service, conn, "user-1", should_continue=lambda: False)

        mock_cursor.assert_not_called()

    def test_partial_results_are_still_inserted_on_interruption(self):
        from claven.core.scan import build_known_senders
        service = _make_service()
        conn = _make_conn()
        messages = [{"id": "s1"}, {"id": "s2"}, {"id": "s3"}]
        call_count = 0

        def stop_after_one():
            nonlocal call_count
            call_count += 1
            return call_count <= 1

        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.get_message", return_value=_msg("s1", to="alice@example.com")), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.count_known_senders", return_value=1):
            build_known_senders(service, conn, "user-1", should_continue=stop_after_one)

        assert mock_bulk.called
