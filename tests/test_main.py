"""Tests for core logic — process_message, poll_new_messages, initial_scan."""
import pytest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# process_message
# ---------------------------------------------------------------------------

class TestProcessMessage:
    def test_applies_matching_label(self):
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label") as mock_apply:
            mock_headers.return_value = ({"from": "news@example.com"}, ["INBOX"])
            mock_labels.return_value = ["Newsletter"]
            process_message(service, "msg1", [], {"Newsletter": "Label_123"})
            mock_apply.assert_called_once_with(service, "msg1", "Label_123")

    def test_does_not_apply_label_already_present(self):
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label") as mock_apply:
            # Label_123 is already on the message
            mock_headers.return_value = ({"from": "news@example.com"}, ["INBOX", "Label_123"])
            mock_labels.return_value = ["Newsletter"]
            process_message(service, "msg1", [], {"Newsletter": "Label_123"})
            mock_apply.assert_not_called()

    def test_no_matching_labels(self):
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label") as mock_apply:
            mock_headers.return_value = ({"from": "friend@example.com"}, ["INBOX"])
            mock_labels.return_value = []
            process_message(service, "msg1", [], {})
            mock_apply.assert_not_called()

    def test_returns_early_if_no_headers(self):
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.apply_label") as mock_apply:
            mock_headers.return_value = (None, [])
            process_message(service, "msg1", [], {"Newsletter": "Label_123"})
            mock_apply.assert_not_called()

    def test_applies_multiple_matching_labels(self):
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label") as mock_apply:
            mock_headers.return_value = ({"from": "billing@example.com"}, ["INBOX"])
            mock_labels.return_value = ["Finance", "Invoice"]
            process_message(service, "msg1", [], {"Finance": "Label_1", "Invoice": "Label_2"})
            assert mock_apply.call_count == 2
            mock_apply.assert_any_call(service, "msg1", "Label_1")
            mock_apply.assert_any_call(service, "msg1", "Label_2")

    def test_skips_label_not_in_cache(self):
        # Label matched by rules but not in label_id_cache — silently skipped
        from claven.core.process import process_message
        service = MagicMock()
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label") as mock_apply:
            mock_headers.return_value = ({"from": "news@example.com"}, ["INBOX"])
            mock_labels.return_value = ["Newsletter"]
            process_message(service, "msg1", [], {})  # empty cache
            mock_apply.assert_not_called()

    def test_passes_known_senders_to_get_matching_labels(self):
        from claven.core.process import process_message
        service = MagicMock()
        known_senders = {"alice@example.com"}
        with patch("claven.core.process.get_message_headers") as mock_headers, \
             patch("claven.core.process.get_matching_labels") as mock_labels, \
             patch("claven.core.process.apply_label"):
            mock_headers.return_value = ({"from": "alice@example.com"}, ["INBOX"])
            mock_labels.return_value = []
            process_message(service, "msg1", [], {}, known_senders=known_senders)
            _, kwargs = mock_labels.call_args
            assert kwargs.get("known_senders") == known_senders or mock_labels.call_args[0][2] == known_senders


# ---------------------------------------------------------------------------
# poll_new_messages
# ---------------------------------------------------------------------------

class TestPollNewMessages:
    def test_processes_new_inbox_message(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            mock_history.return_value = [{
                "messagesAdded": [{"message": {"id": "msg1", "labelIds": ["INBOX"]}}]
            }]
            result = poll_new_messages(service, "history123", [], {})
            mock_process.assert_called_once_with(service, "msg1", [], {}, None)
            assert result == "history123"

    def test_ignores_non_inbox_messages(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            mock_history.return_value = [{
                "messagesAdded": [{"message": {"id": "msg1", "labelIds": ["SENT"]}}]
            }]
            poll_new_messages(service, "history123", [], {})
            mock_process.assert_not_called()

    def test_returns_none_on_expired_history_id(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history:
            mock_history.side_effect = Exception("404: historyId is invalid")
            result = poll_new_messages(service, "expired_id", [], {})
            assert result is None

    def test_returns_history_id_when_no_new_messages(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            mock_history.return_value = []
            result = poll_new_messages(service, "history123", [], {})
            mock_process.assert_not_called()
            assert result == "history123"

    def test_processes_multiple_new_messages(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            mock_history.return_value = [{
                "messagesAdded": [
                    {"message": {"id": "msg1", "labelIds": ["INBOX"]}},
                    {"message": {"id": "msg2", "labelIds": ["INBOX"]}},
                ]
            }]
            poll_new_messages(service, "history123", [], {})
            assert mock_process.call_count == 2

    def test_deduplicates_messages_across_history_records(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            # Same message ID appears in two history records
            mock_history.return_value = [
                {"messagesAdded": [{"message": {"id": "msg1", "labelIds": ["INBOX"]}}]},
                {"messagesAdded": [{"message": {"id": "msg1", "labelIds": ["INBOX"]}}]},
            ]
            poll_new_messages(service, "history123", [], {})
            assert mock_process.call_count == 1

    def test_passes_known_senders(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        known_senders = {"alice@example.com"}
        with patch("claven.core.process.list_history") as mock_history, \
             patch("claven.core.process.process_message") as mock_process:
            mock_history.return_value = [{
                "messagesAdded": [{"message": {"id": "msg1", "labelIds": ["INBOX"]}}]
            }]
            poll_new_messages(service, "history123", [], {}, known_senders=known_senders)
            mock_process.assert_called_once_with(service, "msg1", [], {}, known_senders)

    def test_reraises_non_404_exceptions(self):
        from claven.core.process import poll_new_messages
        service = MagicMock()
        with patch("claven.core.process.list_history") as mock_history:
            mock_history.side_effect = Exception("500: Internal Server Error")
            with pytest.raises(Exception, match="500"):
                poll_new_messages(service, "history123", [], {})


# ---------------------------------------------------------------------------
# initial_scan
# ---------------------------------------------------------------------------

class TestInitialScan:
    def setup_method(self):
        # Ensure the global running flag is True before each test
        import claven.core.scan as scan_module
        scan_module.running = True

    def test_processes_all_pending_messages(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": "msg1"}, {"id": "msg2"}, {"id": "msg3"}]
        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message") as mock_process, \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {})
            assert mock_process.call_count == 3

    def test_skips_already_processed_messages(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": "msg1"}, {"id": "msg2"}, {"id": "msg3"}]
        already_processed = {"msg1", "msg2"}
        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(already_processed, 0)), \
             patch("claven.core.scan.process_message") as mock_process, \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {})
            assert mock_process.call_count == 1
            mock_process.assert_called_once_with(service, "msg3", [], {}, None)

    def test_reprocesses_all_when_known_senders_grew(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": "msg1"}, {"id": "msg2"}]
        already_processed = {"msg1", "msg2"}
        # known_senders_count in checkpoint is 5; current known_senders has 10
        known_senders = set(f"user{i}@example.com" for i in range(10))
        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(already_processed, 5)), \
             patch("claven.core.scan.process_message") as mock_process, \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {}, known_senders=known_senders)
            assert mock_process.call_count == 2  # all reprocessed

    def test_does_not_reprocess_when_known_senders_unchanged(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": "msg1"}, {"id": "msg2"}]
        already_processed = {"msg1", "msg2"}
        known_senders = set(f"user{i}@example.com" for i in range(5))
        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(already_processed, 5)), \
             patch("claven.core.scan.process_message") as mock_process, \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {}, known_senders=known_senders)
            mock_process.assert_not_called()

    def test_respects_max_messages(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        with patch("claven.core.scan.list_messages") as mock_list, \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message"), \
             patch("claven.core.scan.save_scan_checkpoint"):
            mock_list.return_value = [{"id": "msg1"}, {"id": "msg2"}]
            initial_scan(service, str(tmp_path), [], {}, max_messages=2)
            mock_list.assert_called_once_with(service, query="in:inbox", max_results=2)

    def test_saves_checkpoint_on_completion(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": "msg1"}, {"id": "msg2"}]
        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message"), \
             patch("claven.core.scan.save_scan_checkpoint") as mock_save:
            initial_scan(service, str(tmp_path), [], {})
            assert mock_save.called

    def test_stops_when_running_is_false(self, tmp_path):
        import claven.core.scan as scan_module
        from claven.core.scan import initial_scan
        service = MagicMock()
        messages = [{"id": f"msg{i}"} for i in range(20)]
        call_count = 0

        def fake_process(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                scan_module.running = False

        with patch("claven.core.scan.list_messages", return_value=messages), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message", side_effect=fake_process), \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {})
            assert call_count < len(messages)

    def test_no_messages_to_process(self, tmp_path):
        from claven.core.scan import initial_scan
        service = MagicMock()
        with patch("claven.core.scan.list_messages", return_value=[]), \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message") as mock_process, \
             patch("claven.core.scan.save_scan_checkpoint"):
            initial_scan(service, str(tmp_path), [], {})
            mock_process.assert_not_called()

    def test_max_messages_none_does_not_crash(self, tmp_path):
        # Regression: 513013a fixed a format crash when max_messages=None was
        # passed directly to the log string. Verify None is handled cleanly.
        from claven.core.scan import initial_scan
        service = MagicMock()
        with patch("claven.core.scan.list_messages") as mock_list, \
             patch("claven.core.scan.load_scan_checkpoint", return_value=(set(), 0)), \
             patch("claven.core.scan.process_message"), \
             patch("claven.core.scan.save_scan_checkpoint"):
            mock_list.return_value = []
            initial_scan(service, str(tmp_path), [], {}, max_messages=None)
            mock_list.assert_called_once_with(service, query="in:inbox", max_results=None)
