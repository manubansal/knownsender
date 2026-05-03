"""Tests for scan health code system."""
from datetime import datetime, timezone, timedelta

from claven.core.health import (
    HEALTH_CODES,
    OK,
    COMPLETE,
    STALLED,
    ERROR_DB,
    ERROR_GMAIL,
    ERROR_UNKNOWN,
    compute_scan_health,
    _make_code,
)


class TestMakeCode:
    def test_deterministic(self):
        assert _make_code("E", "error.db.connection_lost") == _make_code("E", "error.db.connection_lost")

    def test_different_labels_different_codes(self):
        assert _make_code("E", "error.db.connection_lost") != _make_code("E", "error.gmail.api")

    def test_format(self):
        code = _make_code("W", "warning.scan.stalled")
        assert code.startswith("W")
        assert len(code) == 7  # W + 6 hex chars

    def test_severity_prefix(self):
        assert OK["code"].startswith("I")
        assert COMPLETE["code"].startswith("S")
        assert STALLED["code"].startswith("W")
        assert ERROR_DB["code"].startswith("E")


class TestHealthRegistry:
    def test_all_codes_unique(self):
        codes = [entry["code"] for entry in HEALTH_CODES.values()]
        assert len(codes) == len(set(codes))

    def test_all_entries_have_required_fields(self):
        for label, entry in HEALTH_CODES.items():
            assert "code" in entry
            assert "label" in entry
            assert "severity" in entry
            assert entry["label"] == label


class TestComputeScanHealth:
    def test_none_status_returns_none(self):
        assert compute_scan_health(None, None) is None

    def test_complete_returns_success(self):
        result = compute_scan_health("complete", None)
        assert result == COMPLETE
        assert result["severity"] == "success"

    def test_in_progress_recent_returns_ok(self):
        recent = datetime.now(timezone.utc) - timedelta(seconds=30)
        result = compute_scan_health("in_progress", recent)
        assert result == OK
        assert result["severity"] == "info"

    def test_in_progress_stale_returns_stalled(self):
        stale = datetime.now(timezone.utc) - timedelta(minutes=5)
        result = compute_scan_health("in_progress", stale)
        assert result == STALLED
        assert result["severity"] == "warning"

    def test_in_progress_no_fetched_at_returns_ok(self):
        result = compute_scan_health("in_progress", None)
        assert result == OK

    def test_error_db_returns_error(self):
        result = compute_scan_health("error.db.connection_lost", None)
        assert result == ERROR_DB
        assert result["severity"] == "error"

    def test_error_gmail_returns_error(self):
        result = compute_scan_health("error.gmail.api", None)
        assert result == ERROR_GMAIL

    def test_legacy_error_returns_unknown(self):
        result = compute_scan_health("error", None)
        assert result == ERROR_UNKNOWN

    def test_unknown_status_returns_none(self):
        assert compute_scan_health("something_weird", None) is None
