"""Unit tests for claven/core/watch.py."""

from unittest.mock import MagicMock

import pytest

from claven.core.watch import start_watch, stop_watch


class TestStartWatch:
    def test_calls_gmail_watch_api(self):
        service = MagicMock()
        service.users().watch().execute.return_value = {
            "historyId": "12345",
            "expiration": "1234567890000",
        }

        result = start_watch(service, "projects/proj/topics/gmail-push")

        service.users().watch.assert_called_with(
            userId="me",
            body={
                "labelIds": ["INBOX"],
                "topicName": "projects/proj/topics/gmail-push",
            },
        )
        assert result["historyId"] == "12345"

    def test_returns_watch_response(self):
        service = MagicMock()
        service.users().watch().execute.return_value = {
            "historyId": "99999",
            "expiration": "9999999999000",
        }

        result = start_watch(service, "projects/proj/topics/gmail-push")

        assert "historyId" in result
        assert "expiration" in result


class TestStopWatch:
    def test_calls_gmail_stop_api(self):
        service = MagicMock()
        service.users().stop().execute.return_value = {}

        stop_watch(service)

        service.users().stop.assert_called_with(userId="me")
