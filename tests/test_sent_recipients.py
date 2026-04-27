"""Tests for list_sent_recipients — known senders cache built from Sent mail."""
import pytest
from unittest.mock import MagicMock, patch, call


def mock_service():
    return MagicMock()


def make_message(msg_id, to=None, cc=None, bcc=None):
    """Build a fake Gmail message payload with recipient headers."""
    headers = []
    if to:
        headers.append({"name": "To", "value": to})
    if cc:
        headers.append({"name": "Cc", "value": cc})
    if bcc:
        headers.append({"name": "Bcc", "value": bcc})
    return {"id": msg_id, "payload": {"headers": headers}}


# ---------------------------------------------------------------------------
# Full scan (no cache)
# ---------------------------------------------------------------------------

class TestFullScan:
    def test_returns_recipients_from_sent_messages(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        messages = [{"id": "s1"}, {"id": "s2"}]
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=messages), \
             patch("claven.core.gmail.get_message", side_effect=[
                 make_message("s1", to="alice@example.com"),
                 make_message("s2", to="bob@example.com"),
             ]), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h99"}), \
             patch("claven.core.gmail._save_recipients_cache") as mock_save:
            result = list_sent_recipients(service, str(tmp_path))
        assert "alice@example.com" in result
        assert "bob@example.com" in result

    def test_extracts_cc_and_bcc(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.gmail.get_message", return_value=make_message(
                 "s1",
                 to="alice@example.com",
                 cc="bob@example.com",
                 bcc="charlie@example.com",
             )), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert "alice@example.com" in result
        assert "bob@example.com" in result
        assert "charlie@example.com" in result

    def test_returns_lowercase_addresses(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.gmail.get_message", return_value=make_message("s1", to="Alice@Example.COM")), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert "alice@example.com" in result
        assert "Alice@Example.COM" not in result

    def test_returns_sorted_list(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]), \
             patch("claven.core.gmail.get_message", side_effect=[
                 make_message("s1", to="zebra@example.com"),
                 make_message("s2", to="alpha@example.com"),
             ]), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert result == sorted(result)

    def test_no_sent_messages_returns_empty(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[]), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert result == []

    def test_saves_cache_with_history_id_on_completion(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.gmail.get_message", return_value=make_message("s1", to="alice@example.com")), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h99"}), \
             patch("claven.core.gmail._save_recipients_cache") as mock_save:
            list_sent_recipients(service, str(tmp_path))
        # Final save must include the historyId from get_profile
        final_call = mock_save.call_args_list[-1]
        assert "h99" in final_call.args or final_call.args[1] == "h99"

    def test_deduplicates_recipients(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}, {"id": "s2"}]), \
             patch("claven.core.gmail.get_message", side_effect=[
                 make_message("s1", to="alice@example.com"),
                 make_message("s2", to="alice@example.com"),  # duplicate
             ]), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert result.count("alice@example.com") == 1


# ---------------------------------------------------------------------------
# Incremental update (cache exists)
# ---------------------------------------------------------------------------

class TestIncrementalUpdate:
    def test_no_new_messages_returns_cached_recipients(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        cached = {"alice@example.com", "bob@example.com"}
        with patch("claven.core.gmail._load_recipients_cache", return_value=(cached, "h1", 0)), \
             patch("claven.core.gmail.list_history", return_value=[]), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h2"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert "alice@example.com" in result
        assert "bob@example.com" in result

    def test_merges_new_recipients_with_cached(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        cached = {"alice@example.com"}
        history_records = [{
            "messagesAdded": [{"message": {"id": "s2", "labelIds": ["SENT"]}}]
        }]
        with patch("claven.core.gmail._load_recipients_cache", return_value=(cached, "h1", 0)), \
             patch("claven.core.gmail.list_history", return_value=history_records), \
             patch("claven.core.gmail.get_message", return_value=make_message("s2", to="bob@example.com")), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h2"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        assert "alice@example.com" in result
        assert "bob@example.com" in result

    def test_ignores_non_sent_messages_in_history(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        cached = {"alice@example.com"}
        history_records = [{
            "messagesAdded": [{"message": {"id": "s2", "labelIds": ["INBOX"]}}]  # not SENT
        }]
        with patch("claven.core.gmail._load_recipients_cache", return_value=(cached, "h1", 0)), \
             patch("claven.core.gmail.list_history", return_value=history_records), \
             patch("claven.core.gmail.get_message") as mock_get_msg, \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h2"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        mock_get_msg.assert_not_called()
        assert result == ["alice@example.com"]

    def test_expired_history_id_falls_back_to_full_scan(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        cached = {"alice@example.com"}
        with patch("claven.core.gmail._load_recipients_cache", return_value=(cached, "expired_h", 0)), \
             patch("claven.core.gmail.list_history", side_effect=Exception("404: historyId invalid")), \
             patch("claven.core.gmail.list_messages", return_value=[{"id": "s1"}]), \
             patch("claven.core.gmail.get_message", return_value=make_message("s1", to="bob@example.com")), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h_new"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            result = list_sent_recipients(service, str(tmp_path))
        # Full scan discards old cached recipients and rebuilds
        assert "bob@example.com" in result


# ---------------------------------------------------------------------------
# Interruption and resume
# ---------------------------------------------------------------------------

class TestInterruptionAndResume:
    def test_interrupted_scan_saves_progress(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        messages = [{"id": f"s{i}"} for i in range(5)]
        call_count = 0

        def should_continue_twice():
            nonlocal call_count
            call_count += 1
            return call_count <= 2

        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 0)), \
             patch("claven.core.gmail.list_messages", return_value=messages), \
             patch("claven.core.gmail.get_message", return_value=make_message("sx", to="alice@example.com")), \
             patch("claven.core.gmail._save_recipients_cache") as mock_save:
            list_sent_recipients(service, str(tmp_path), should_continue=should_continue_twice)

        # Should have saved progress (not the final save with a history ID)
        assert mock_save.called

    def test_resumes_from_saved_index(self, tmp_path):
        from claven.core.gmail import list_sent_recipients
        service = mock_service()
        messages = [{"id": f"s{i}"} for i in range(5)]
        processed_in_call = []

        def fake_get_message(service, msg_id, **kwargs):
            processed_in_call.append(msg_id)
            return make_message(msg_id, to=f"{msg_id}@example.com")

        with patch("claven.core.gmail._load_recipients_cache", return_value=(set(), None, 2)), \
             patch("claven.core.gmail.list_messages", return_value=messages), \
             patch("claven.core.gmail.get_message", side_effect=fake_get_message), \
             patch("claven.core.gmail.get_profile", return_value={"historyId": "h1"}), \
             patch("claven.core.gmail._save_recipients_cache"):
            list_sent_recipients(service, str(tmp_path))

        # Should have skipped first 2 messages (index 0 and 1)
        assert "s0" not in processed_in_call
        assert "s1" not in processed_in_call
        assert "s2" in processed_in_call
