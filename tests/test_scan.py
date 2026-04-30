"""Tests for scan functions — build_known_senders and scan_inbox."""
import pytest
from unittest.mock import MagicMock, patch, call


def _make_service():
    return MagicMock()


def _make_conn():
    return MagicMock()


def _batch_metadata(**msg_map):
    """Build a fake batch_get_message_metadata return value."""
    return {msg_id: (headers, [], None) for msg_id, headers in msg_map.items()}


# ---------------------------------------------------------------------------
# build_known_senders — label-based sent scan
# ---------------------------------------------------------------------------

class TestBuildKnownSenders:
    """Tests for build_known_senders — queries unlabeled sent messages,
    extracts recipients, and applies sent-scanned label."""

    def _once_then_empty(self, messages):
        calls = [0]
        def side_effect(*args, **kwargs):
            calls[0] += 1
            return messages if calls[0] == 1 else []
        return side_effect

    def test_returns_zero_for_no_unscanned(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", return_value=[]), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = build_known_senders(service, conn, "u1")
        assert result == 0

    def test_inserts_recipients_into_db(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": "s1"}, {"id": "s2"}]
        metadata = _batch_metadata(
            s1={"to": "alice@example.com"},
            s2={"to": "bob@example.com"},
        )
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=metadata), \
             patch("claven.core.scan.batch_apply_labels", return_value=2), \
             patch("claven.core.scan.db") as mock_db, \
             patch("claven.core.scan.time.sleep"):
            build_known_senders(service, conn, "u1")
        all_inserted = [addr for c in mock_db.bulk_add_known_senders.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted

    def test_extracts_cc_and_bcc(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": "s1"}]
        metadata = _batch_metadata(
            s1={"to": "alice@example.com", "cc": "bob@example.com", "bcc": "carol@example.com"},
        )
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=metadata), \
             patch("claven.core.scan.batch_apply_labels", return_value=1), \
             patch("claven.core.scan.db") as mock_db, \
             patch("claven.core.scan.time.sleep"):
            build_known_senders(service, conn, "u1")
        all_inserted = [addr for c in mock_db.bulk_add_known_senders.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "bob@example.com" in all_inserted
        assert "carol@example.com" in all_inserted

    def test_inserts_lowercase_addresses(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": "s1"}]
        metadata = _batch_metadata(s1={"to": "Alice@Example.COM"})
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=metadata), \
             patch("claven.core.scan.batch_apply_labels", return_value=1), \
             patch("claven.core.scan.db") as mock_db, \
             patch("claven.core.scan.time.sleep"):
            build_known_senders(service, conn, "u1")
        all_inserted = [addr for c in mock_db.bulk_add_known_senders.call_args_list for addr in c.args[2]]
        assert "alice@example.com" in all_inserted
        assert "Alice@Example.COM" not in all_inserted

    def test_applies_sent_scanned_label(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": "s1"}]
        metadata = _batch_metadata(s1={"to": "a@x.com"})
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=metadata), \
             patch("claven.core.scan.batch_apply_labels", return_value=1) as mock_apply, \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            build_known_senders(service, conn, "u1")
        pairs = mock_apply.call_args[0][1]
        assert ("s1", "Label_scanned") in pairs

    def test_stops_when_should_continue_returns_false(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = build_known_senders(service, conn, "u1", should_continue=lambda: False)
        assert result == 0

    def test_returns_count_of_scanned_messages(self):
        from claven.core.scan import build_known_senders
        service, conn = _make_service(), _make_conn()
        messages = [{"id": "s1"}, {"id": "s2"}, {"id": "s3"}]
        metadata = _batch_metadata(
            s1={"to": "a@x.com"}, s2={"to": "b@x.com"}, s3={"to": "c@x.com"},
        )
        with patch("claven.core.scan.ensure_label_exists", return_value="Label_scanned"), \
             patch("claven.core.scan.list_messages", side_effect=self._once_then_empty(messages)), \
             patch("claven.core.scan.batch_get_message_metadata", return_value=metadata), \
             patch("claven.core.scan.batch_apply_labels", return_value=3), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = build_known_senders(service, conn, "u1")
        assert result == 3


# ---------------------------------------------------------------------------
# scan_inbox — label-based inbox scan
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
        with patch("claven.core.scan.list_messages", return_value=[{"id": "m1"}]), \
             patch("claven.core.scan.batch_get_message_headers"), \
             patch("claven.core.scan.batch_apply_labels"), \
             patch("claven.core.scan.db"), \
             patch("claven.core.scan.time.sleep"):
            result = scan_inbox(MagicMock(), conn, "u1", _LABEL_CONFIGS, _LABEL_ID_CACHE, should_continue=lambda: False)
        assert result == 0

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
        assert result == 1
