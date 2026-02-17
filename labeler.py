import logging
import re
import yaml

from gmail_service import _load_recipients_cache, _parse_addresses

logger = logging.getLogger(__name__)


def load_config(path="config.yaml"):
    """Load labeling rules and settings from a YAML config file."""
    with open(path) as f:
        return yaml.safe_load(f)


def _get_known_senders():
    """Load the set of known recipients from the cache."""
    recipients, _ = _load_recipients_cache()
    return recipients


def matches_rule(headers, rule, known_senders=None):
    """Check if message headers match a single rule."""
    if rule.get("known_sender"):
        if known_senders is None:
            known_senders = _get_known_senders()
        field = rule["field"].lower()
        value = headers.get(field, "")
        addresses = _parse_addresses(value)
        return any(addr.lower() in known_senders for addr in addresses)

    field = rule["field"].lower()
    value = headers.get(field, "").lower()
    return any(substring.lower() in value for substring in rule["contains"])


def get_matching_labels(headers, label_configs, known_senders=None):
    """Return label names that should be applied to a message.

    A label is applied if ANY of its rules match.
    """
    matching = []
    for label_config in label_configs:
        for rule in label_config["rules"]:
            if matches_rule(headers, rule, known_senders):
                matching.append(label_config["name"])
                break
    return matching
