"""Tests for labeler.py — label rule matching logic."""
import os
import pytest
from claven.core.rules import matches_rule, get_matching_labels, load_config

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

def test_load_config_returns_labels_and_interval():
    config = load_config(os.path.join(FIXTURES_DIR, "config.yaml"))
    assert "labels" in config
    assert config["polling_interval_seconds"] == 30


def test_load_config_label_names():
    config = load_config(os.path.join(FIXTURES_DIR, "config.yaml"))
    names = [l["name"] for l in config["labels"]]
    assert "Known" in names
    assert "Newsletter" in names
    assert "Finance" in names


def test_load_config_label_rules_present():
    config = load_config(os.path.join(FIXTURES_DIR, "config.yaml"))
    for label in config["labels"]:
        assert "rules" in label
        assert len(label["rules"]) > 0


def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent.yaml")


def test_load_config_malformed_yaml_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("labels: [unclosed bracket\n  - invalid")
    with pytest.raises(Exception):
        load_config(str(bad))


# ---------------------------------------------------------------------------
# matches_rule — contains-based rules
# ---------------------------------------------------------------------------

def test_matches_rule_from_contains():
    headers = {"from": "newsletter@company.com", "subject": "Weekly update"}
    rule = {"field": "from", "contains": ["newsletter"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_subject_contains():
    headers = {"from": "billing@example.com", "subject": "Your invoice #123"}
    rule = {"field": "subject", "contains": ["invoice"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_no_match():
    headers = {"from": "friend@example.com", "subject": "Hello"}
    rule = {"field": "from", "contains": ["newsletter"]}
    assert matches_rule(headers, rule) is False


def test_matches_rule_case_insensitive_header_value():
    headers = {"from": "Newsletter@Company.COM"}
    rule = {"field": "from", "contains": ["newsletter"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_case_insensitive_contains_value():
    headers = {"from": "newsletter@company.com"}
    rule = {"field": "from", "contains": ["NEWSLETTER"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_any_contains_value_matches():
    headers = {"from": "promo@shop.com"}
    rule = {"field": "from", "contains": ["newsletter", "promo", "deals"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_missing_header_returns_false():
    headers = {}
    rule = {"field": "from", "contains": ["newsletter"]}
    assert matches_rule(headers, rule) is False


def test_matches_rule_substring_match():
    # "noreply" is a substring of "noreply@service.com"
    headers = {"from": "noreply@service.com"}
    rule = {"field": "from", "contains": ["noreply"]}
    assert matches_rule(headers, rule) is True


def test_matches_rule_contains_is_substring_not_regex():
    # The current implementation does substring matching only — not regex.
    # A dot in a contains value matches a literal dot, not "any character".
    headers = {"from": "axbxc@example.com"}
    rule = {"field": "from", "contains": ["a.b"]}  # regex "a.b" would match "axb", but substring won't
    assert matches_rule(headers, rule) is False


# ---------------------------------------------------------------------------
# matches_rule — known_sender rules
# ---------------------------------------------------------------------------

def test_matches_rule_known_sender_match():
    headers = {"from": "Alice <alice@example.com>"}
    rule = {"field": "from", "known_sender": True}
    known_senders = {"alice@example.com"}
    assert matches_rule(headers, rule, known_senders=known_senders) is True


def test_matches_rule_known_sender_no_match():
    headers = {"from": "stranger@example.com"}
    rule = {"field": "from", "known_sender": True}
    known_senders = {"alice@example.com"}
    assert matches_rule(headers, rule, known_senders=known_senders) is False


def test_matches_rule_known_sender_empty_set():
    headers = {"from": "alice@example.com"}
    rule = {"field": "from", "known_sender": True}
    assert matches_rule(headers, rule, known_senders=set()) is False


def test_matches_rule_known_sender_case_insensitive():
    headers = {"from": "Alice@Example.COM"}
    rule = {"field": "from", "known_sender": True}
    known_senders = {"alice@example.com"}
    assert matches_rule(headers, rule, known_senders=known_senders) is True


def test_matches_rule_known_sender_display_name_format():
    # Address in "Display Name <email>" format
    headers = {"from": "Alice Smith <alice@example.com>"}
    rule = {"field": "from", "known_sender": True}
    known_senders = {"alice@example.com"}
    assert matches_rule(headers, rule, known_senders=known_senders) is True


# ---------------------------------------------------------------------------
# get_matching_labels
# ---------------------------------------------------------------------------

def test_get_matching_labels_single_match():
    headers = {"from": "newsletter@company.com"}
    label_configs = [{"name": "Newsletter", "rules": [{"field": "from", "contains": ["newsletter"]}]}]
    assert get_matching_labels(headers, label_configs) == ["Newsletter"]


def test_get_matching_labels_no_match():
    headers = {"from": "friend@example.com"}
    label_configs = [{"name": "Newsletter", "rules": [{"field": "from", "contains": ["newsletter"]}]}]
    assert get_matching_labels(headers, label_configs) == []


def test_get_matching_labels_multiple_labels_both_match():
    headers = {"from": "newsletter@company.com", "subject": "Invoice #123"}
    label_configs = [
        {"name": "Newsletter", "rules": [{"field": "from", "contains": ["newsletter"]}]},
        {"name": "Invoice", "rules": [{"field": "subject", "contains": ["invoice"]}]},
    ]
    result = get_matching_labels(headers, label_configs)
    assert "Newsletter" in result
    assert "Invoice" in result


def test_get_matching_labels_multiple_labels_one_match():
    headers = {"from": "newsletter@company.com", "subject": "Hello"}
    label_configs = [
        {"name": "Newsletter", "rules": [{"field": "from", "contains": ["newsletter"]}]},
        {"name": "Invoice", "rules": [{"field": "subject", "contains": ["invoice"]}]},
    ]
    result = get_matching_labels(headers, label_configs)
    assert result == ["Newsletter"]


def test_get_matching_labels_not_applied_twice_if_multiple_rules_match():
    # If two rules for the same label both match, the label is only returned once
    headers = {"from": "newsletter@company.com", "subject": "Weekly newsletter"}
    label_configs = [{
        "name": "Newsletter",
        "rules": [
            {"field": "from", "contains": ["newsletter"]},
            {"field": "subject", "contains": ["newsletter"]},
        ]
    }]
    result = get_matching_labels(headers, label_configs)
    assert result.count("Newsletter") == 1


def test_get_matching_labels_second_rule_matches():
    # First rule doesn't match, second does — label is still applied
    headers = {"from": "friend@example.com", "subject": "Weekly newsletter"}
    label_configs = [{
        "name": "Newsletter",
        "rules": [
            {"field": "from", "contains": ["newsletter"]},
            {"field": "subject", "contains": ["newsletter"]},
        ]
    }]
    assert get_matching_labels(headers, label_configs) == ["Newsletter"]


def test_get_matching_labels_empty_config():
    headers = {"from": "anyone@example.com"}
    assert get_matching_labels(headers, []) == []


def test_get_matching_labels_known_sender():
    headers = {"from": "alice@example.com"}
    label_configs = [{"name": "Known", "rules": [{"field": "from", "known_sender": True}]}]
    result = get_matching_labels(headers, label_configs, known_senders={"alice@example.com"})
    assert result == ["Known"]


def test_get_matching_labels_known_sender_no_match():
    headers = {"from": "stranger@example.com"}
    label_configs = [{"name": "Known", "rules": [{"field": "from", "known_sender": True}]}]
    result = get_matching_labels(headers, label_configs, known_senders={"alice@example.com"})
    assert result == []
