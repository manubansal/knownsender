"""Tests for scan functions — build_known_senders and scan_inbox."""
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


def _batch_metadata(**msg_map):
    """Build a fake batch_get_message_metadata return value.

    Usage: _batch_metadata(s1={"to": "a@x.com"}, s2={"to": "b@x.com", "cc": "c@x.com"})
    Returns: {"s1": ({"to": "a@x.com"}, []), "s2": ({"to": "b@x.com", "cc": "c@x.com"}, [])}
    """
    return {msg_id: (headers, [], None) for msg_id, headers in msg_map.items()}


# ---------------------------------------------------------------------------
# Full scan (no cursor in DB)
# ---------------------------------------------------------------------------

class TestFullScan:
    def _patches(self, **overrides):
        """Common patches for full scan tests. Override any via kwargs."""
        defaults = {
            "claven.core.scan.db.get_sent_scan_cursor": None,
            "claven.core.scan.db.set_sent_scan_cursor": None,
            "claven.core.scan.db.count_known_senders": 0,
            "claven.core.scan.db.set_sent_scan_progress": None,
            "claven.core.scan.list_messages": [],
            "claven.core.scan.batch_get_message_metadata": {},
            "claven.core.scan.get_profile": {"historyId": "99"},
        }
        defaults.update(overrides)
        return defaults

    def test_fetches_all_sent_messages(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        p = self._patches(**{"claven.core.scan.list_messages": [{"id": "s1"}, {"id": "s2"}]})
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=p["claven.core.scan.db.get_sent_scan_cursor"]), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=2), \
             patch("claven.core.scan.list_messages", return_value=p["claven.core.scan.list_messages"]) as mock_list, \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "alice@example.com"}, s2={"to": "bob@example.com"})), \
             patch("claven.core.scan.get_profile", return_value=p["claven.core.scan.get_profile"]):
            build_known_senders(service, conn, "user-1")
        mock_list.assert_called_once_with(service, query="in:sent", max_results=None)

    def test_inserts_recipients_into_db(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=2), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "alice@example.com"}, s2={"to": "bob@example.com"})), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted

    def test_extracts_cc_and_bcc(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=3), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "alice@example.com", "cc": "bob@example.com", "bcc": "carol@example.com"})), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted
        assert "carol@example.com" in all_inserted

    def test_inserts_lowercase_addresses(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders") as mock_bulk, \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=1), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "Alice@Example.COM"})), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            build_known_senders(service, conn, "user-1")
        all_inserted = [addr for c in mock_bulk.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "Alice@Example.COM" not in all_inserted

    def test_no_sent_messages_still_saves_cursor(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=0), \
             patch("claven.core.scan.list_messages", return_value=[]), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}):
            result = build_known_senders(service, conn, "user-1")
        mock_cursor.assert_called_once_with(conn, "user-1", 99)
        assert result["known_senders"] == 0
        assert result["messages_scanned"] == 0

    def test_saves_cursor_after_full_scan(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=1), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "alice@example.com"})), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "42"}):
            build_known_senders(service, conn, "user-1")
        mock_cursor.assert_called_once_with(conn, "user-1", 42)

    def test_returns_known_senders_count_and_messages_scanned(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=7), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}, {"id": "s3"}]), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "a@x.com"}, s2={"to": "b@x.com"}, s3={"to": "c@x.com"})), \
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
             patch("claven.core.scan.batch_get_message_metadata", return_value=_batch_metadata(
                 s1={"to": "alice@example.com"})), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
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
    def test_does_not_save_cursor_when_interrupted(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        # 200 messages = 4 batches of 50; interrupt immediately
        messages = [{"id": f"s{i}"} for i in range(200)]
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.batch_get_message_metadata", return_value={}), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor") as mock_cursor, \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=0):
            build_known_senders(service, conn, "user-1", should_continue=lambda: False)
        mock_cursor.assert_not_called()

    def test_returns_partial_count_when_interrupted(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": f"s{i}"} for i in range(200)]
        with patch("claven.core.scan.db.get_sent_scan_cursor", return_value=None), \
             patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.batch_get_message_metadata", return_value={}), \
             patch("claven.core.scan.db.bulk_add_known_senders"), \
             patch("claven.core.scan.db.set_sent_scan_cursor"), \
             patch("claven.core.scan.db.set_sent_scan_progress"), \
             patch("claven.core.scan.db.get_sent_scan_progress", return_value={"messages_scanned": 0, "messages_total": None, "status": None, "updated_at": None}), \
             patch("claven.core.scan.db.count_known_senders", return_value=0):
            result = build_known_senders(service, conn, "user-1", should_continue=lambda: False)
        assert result["messages_scanned"] == 0  # interrupted before first batch


# ---------------------------------------------------------------------------
# scan_inbox
# ---------------------------------------------------------------------------

_LABEL_CONFIGS = [{
    "id": "known-sender",
    "name": "Known Sender",
    "unknown_label": "unknown-sender",
    "rules": [{"field": "from", "known_sender": True}],
}]
_LABEL_ID_CACHE = {"known-sender": "Label_K", "unknown-sender": "Label_U"}


class TestScanInbox:
    """Tests for scan_inbox — queries Gmail for unlabeled messages and labels them in a loop."""

    def _once_then_empty(self, messages):
        """Return messages on first call, empty on second — simulates labeling completing."""
        calls = [0]
        def side_effect(*args, **kwargs):
            calls[0] += 1
            return messages if calls[0] == 1 else []
        return side_effect

    def test_returns_zero_for_empty_inbox(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        with patch("claven.core.scan.list_messages", return_value=[]), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE)
        assert result == 0

    def test_labels_messages_and_returns_count(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        messages = [{"id": f"m{i}"} for i in range(3)]
        headers_map = {
            "m0": ({"from": "alice@x.com"}, [], None),
            "m1": ({"from": "bob@x.com"}, [], None),
            "m2": ({"from": "carol@x.com"}, [], None),
        }
        with patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_headers", return_value=headers_map), \
             patch("claven.core.scan.batch_apply_labels", return_value=3), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, known_senders=set())
        assert result == 3

    def test_applies_known_sender_label(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        messages = [{"id": "m1"}]
        headers_map = {"m1": ({"from": "alice@x.com"}, [], None)}
        with patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_headers", return_value=headers_map), \
             patch("claven.core.scan.batch_apply_labels", return_value=1) as mock_apply, \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, known_senders={"alice@x.com"})
        pairs = mock_apply.call_args[0][1]
        assert ("m1", "Label_K") in pairs

    def test_applies_unknown_sender_label(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        messages = [{"id": "m1"}]
        headers_map = {"m1": ({"from": "stranger@x.com"}, [], None)}
        with patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_headers", return_value=headers_map), \
             patch("claven.core.scan.batch_apply_labels", return_value=1) as mock_apply, \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, known_senders=set())
        pairs = mock_apply.call_args[0][1]
        assert ("m1", "Label_U") in pairs

    def test_updates_history_id_on_completion(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        messages = [{"id": "m1"}]
        headers_map = {"m1": ({"from": "a@x.com"}, [], None)}
        with patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_headers", return_value=headers_map), \
             patch("claven.core.scan.batch_apply_labels", return_value=1), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "42"}), \
             patch("claven.core.scan.db") as mock_db, \
             patch("claven.core.scan.time.sleep"):
            scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, known_senders=set())
        mock_db.set_history_id.assert_called_once_with(conn, "u1", 42)

    def test_stops_when_should_continue_returns_false(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        # list_messages always returns messages, but should_continue stops it
        with patch("claven.core.scan.list_messages", return_value=[{"id": "m1"}]), \
             patch("claven.core.scan.batch_get_message_headers"), \
             patch("claven.core.scan.batch_apply_labels"), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, should_continue=lambda: False)
        assert result == 0  # stopped before processing

    def test_retries_on_header_fetch_failure(self):
        from claven.core.scan import scan_inbox
        conn = MagicMock()
        messages = [{"id": "m1"}]
        call_count = [0]
        def fetch_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("API error")
            return {"m1": ({"from": "a@x.com"}, [], None)}
        # list_messages: first two calls return messages (retry after error), third returns empty
        list_calls = [0]
        def list_side_effect(*args, **kwargs):
            list_calls[0] += 1
            return messages if list_calls[0] <= 2 else []
        with patch("claven.core.scan.list_messages", side_effect=list_side_effect), \
             patch("claven.core.scan.batch_get_message_headers", side_effect=fetch_side_effect), \
             patch("claven.core.scan.batch_apply_labels", return_value=1), \
             patch("claven.core.scan.get_profile", return_value={"historyId": "99"}), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, known_senders=set())
        assert result == 1  # labeled on retry
