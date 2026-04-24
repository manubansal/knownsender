"""Tests for gmail_service.py — file-based state and Gmail API wrappers."""
import pytest
from unittest.mock import MagicMock, call
from gmail_service import (
    _parse_addresses,
    load_scan_checkpoint,
    save_scan_checkpoint,
    _load_recipients_cache,
    _save_recipients_cache,
    get_message_headers,
    ensure_label_exists,
    apply_label,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mock_service():
    """Return a MagicMock that mimics the Gmail API service fluent interface."""
    return MagicMock()


# ---------------------------------------------------------------------------
# _parse_addresses
# ---------------------------------------------------------------------------

def test_parse_addresses_bare_email():
    assert _parse_addresses("alice@example.com") == ["alice@example.com"]


def test_parse_addresses_display_name_format():
    assert _parse_addresses("Alice Smith <alice@example.com>") == ["alice@example.com"]


def test_parse_addresses_multiple_comma_separated():
    result = _parse_addresses("alice@example.com, bob@example.com")
    assert "alice@example.com" in result
    assert "bob@example.com" in result


def test_parse_addresses_empty_string():
    assert _parse_addresses("") == []


def test_parse_addresses_no_email():
    assert _parse_addresses("no email here") == []


def test_parse_addresses_mixed_formats():
    result = _parse_addresses("Alice <alice@example.com>, bob@example.com")
    assert "alice@example.com" in result
    assert "bob@example.com" in result


# ---------------------------------------------------------------------------
# load_scan_checkpoint / save_scan_checkpoint
# ---------------------------------------------------------------------------

def test_load_scan_checkpoint_returns_empty_when_missing(tmp_path):
    ids, count = load_scan_checkpoint(str(tmp_path))
    assert ids == set()
    assert count == 0


def test_save_load_scan_checkpoint_roundtrip(tmp_path):
    ids = {"msg1", "msg2", "msg3"}
    save_scan_checkpoint(ids, str(tmp_path), known_senders_count=42)
    loaded_ids, loaded_count = load_scan_checkpoint(str(tmp_path))
    assert loaded_ids == ids
    assert loaded_count == 42


def test_save_load_scan_checkpoint_zero_senders(tmp_path):
    save_scan_checkpoint({"msg1"}, str(tmp_path), known_senders_count=0)
    _, count = load_scan_checkpoint(str(tmp_path))
    assert count == 0


def test_save_load_scan_checkpoint_empty_ids(tmp_path):
    save_scan_checkpoint(set(), str(tmp_path), known_senders_count=5)
    ids, count = load_scan_checkpoint(str(tmp_path))
    assert ids == set()
    assert count == 5


def test_save_scan_checkpoint_overwrites_previous(tmp_path):
    save_scan_checkpoint({"msg1"}, str(tmp_path), known_senders_count=1)
    save_scan_checkpoint({"msg2", "msg3"}, str(tmp_path), known_senders_count=2)
    ids, count = load_scan_checkpoint(str(tmp_path))
    assert ids == {"msg2", "msg3"}
    assert count == 2


# ---------------------------------------------------------------------------
# _load_recipients_cache / _save_recipients_cache
# ---------------------------------------------------------------------------

def test_load_recipients_cache_returns_empty_when_missing(tmp_path):
    recipients, history_id, resume_index = _load_recipients_cache(str(tmp_path))
    assert recipients == set()
    assert history_id is None
    assert resume_index == 0


def test_save_load_recipients_cache_roundtrip(tmp_path):
    recipients = {"alice@example.com", "bob@example.com"}
    _save_recipients_cache(recipients, "history123", str(tmp_path), resume_index=5)
    loaded_recipients, loaded_history_id, loaded_index = _load_recipients_cache(str(tmp_path))
    assert loaded_recipients == recipients
    assert loaded_history_id == "history123"
    assert loaded_index == 5


def test_save_load_recipients_cache_no_history_id(tmp_path):
    _save_recipients_cache({"alice@example.com"}, None, str(tmp_path))
    _, history_id, _ = _load_recipients_cache(str(tmp_path))
    assert history_id is None


def test_save_load_recipients_cache_zero_resume_index(tmp_path):
    _save_recipients_cache({"alice@example.com"}, "h1", str(tmp_path), resume_index=0)
    _, _, resume_index = _load_recipients_cache(str(tmp_path))
    assert resume_index == 0


# ---------------------------------------------------------------------------
# get_message_headers
# ---------------------------------------------------------------------------

def test_get_message_headers_extracts_all_fields():
    service = mock_service()
    service.users().messages().get().execute.return_value = {
        "payload": {
            "headers": [
                {"name": "From", "value": "Alice <alice@example.com>"},
                {"name": "Subject", "value": "Hello there"},
                {"name": "To", "value": "bob@example.com"},
            ]
        },
        "labelIds": ["INBOX", "UNREAD"],
    }
    headers, label_ids = get_message_headers(service, "msg123")
    assert headers["from"] == "Alice <alice@example.com>"
    assert headers["subject"] == "Hello there"
    assert headers["to"] == "bob@example.com"
    assert "INBOX" in label_ids
    assert "UNREAD" in label_ids


def test_get_message_headers_returns_lowercase_keys():
    service = mock_service()
    service.users().messages().get().execute.return_value = {
        "payload": {"headers": [{"name": "FROM", "value": "test@example.com"}]},
        "labelIds": [],
    }
    headers, _ = get_message_headers(service, "msg1")
    assert "from" in headers
    assert "FROM" not in headers


def test_get_message_headers_missing_headers_returns_empty():
    service = mock_service()
    service.users().messages().get().execute.return_value = {
        "payload": {"headers": []},
        "labelIds": [],
    }
    headers, label_ids = get_message_headers(service, "msg1")
    assert headers == {}
    assert label_ids == []


def test_get_message_headers_ignores_irrelevant_headers():
    service = mock_service()
    service.users().messages().get().execute.return_value = {
        "payload": {
            "headers": [
                {"name": "From", "value": "alice@example.com"},
                {"name": "Date", "value": "Mon, 1 Jan 2024"},
                {"name": "X-Custom", "value": "ignored"},
            ]
        },
        "labelIds": [],
    }
    headers, _ = get_message_headers(service, "msg1")
    assert "from" in headers
    assert "date" not in headers
    assert "x-custom" not in headers


# ---------------------------------------------------------------------------
# ensure_label_exists
# ---------------------------------------------------------------------------

def test_ensure_label_exists_returns_existing_id():
    service = mock_service()
    service.users().labels().list().execute.return_value = {
        "labels": [{"name": "Newsletter", "id": "Label_123"}]
    }
    label_id = ensure_label_exists(service, "Newsletter")
    assert label_id == "Label_123"


def test_ensure_label_exists_creates_when_missing():
    service = mock_service()
    service.users().labels().list().execute.return_value = {"labels": []}
    service.users().labels().create().execute.return_value = {
        "name": "Newsletter", "id": "Label_456"
    }
    label_id = ensure_label_exists(service, "Newsletter")
    assert label_id == "Label_456"


def test_ensure_label_exists_case_insensitive_match():
    service = mock_service()
    service.users().labels().list().execute.return_value = {
        "labels": [{"name": "NEWSLETTER", "id": "Label_123"}]
    }
    label_id = ensure_label_exists(service, "newsletter")
    assert label_id == "Label_123"


def test_ensure_label_exists_does_not_create_if_exists():
    service = mock_service()
    service.users().labels().list().execute.return_value = {
        "labels": [{"name": "Newsletter", "id": "Label_123"}]
    }
    ensure_label_exists(service, "Newsletter")
    service.users().labels().create.assert_not_called()


# ---------------------------------------------------------------------------
# apply_label
# ---------------------------------------------------------------------------

def test_apply_label_calls_modify_with_correct_args():
    service = mock_service()
    apply_label(service, "msg123", "Label_123")
    service.users().messages().modify.assert_called_once_with(
        userId="me",
        id="msg123",
        body={"addLabelIds": ["Label_123"]},
    )


def test_apply_label_calls_execute():
    service = mock_service()
    apply_label(service, "msg1", "Label_1")
    service.users().messages().modify().execute.assert_called_once()
