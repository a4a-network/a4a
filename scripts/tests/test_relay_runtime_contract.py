"""Tests for the loopback-only live relay contract checker."""

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-relay-runtime-contract.py"
SPEC = importlib.util.spec_from_file_location("relay_runtime_contract", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def good_nip11(kinds):
    return {
        "supported_nips": [1, 11, 40],
        "version": "0.3.22 (a4a-relay 0.10.0)",
        "limitation": {"restricted_writes": True},
        "a4a": {
            "protocol": "0.4",
            "multi_char_tag_filters": True,
            "inbox_auth": False,
            "delegation_required_for_kinds": kinds,
        },
    }


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1:8080",
        "http://localhost:8080",
        "http://192.0.2.10:8080",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
    ],
)
def test_base_url_rejects_every_nonliteral_or_nonorigin_form(value):
    with pytest.raises(MODULE.ContractError):
        MODULE.validate_base_url(value)


def test_base_url_accepts_ipv4_and_ipv6_loopback():
    assert MODULE.validate_base_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert MODULE.validate_base_url("http://[::1]:8080/") == "http://[::1]:8080"


def test_nip11_matches_the_exact_configured_kind_order():
    kinds = [31001, 31002, 31020]
    assert MODULE.validate_nip11(good_nip11(kinds), kinds, False).startswith("0.3.22 ")
    with pytest.raises(MODULE.ContractError, match="delegation kinds differ"):
        MODULE.validate_nip11(good_nip11(list(reversed(kinds))), kinds, False)


def test_nip11_inbox_auth_matches_configuration():
    document = good_nip11([31001])
    with pytest.raises(MODULE.ContractError, match="inbox authentication differs"):
        MODULE.validate_nip11(document, [31001], True)
    document["a4a"]["inbox_auth"] = True
    MODULE.validate_nip11(document, [31001], True)


def test_health_requires_consistent_versions_and_positive_schema():
    good = {
        "status": "ok",
        "version": "0.10.0",
        "a4a_version": "0.3.22",
        "schema_version": 21,
    }
    MODULE.validate_health(good, "0.3.22 (a4a-relay 0.10.0)")
    bad = dict(good, a4a_version="0.3.20")
    with pytest.raises(MODULE.ContractError, match="versions differ"):
        MODULE.validate_health(bad, "0.3.22 (a4a-relay 0.10.0)")
    bad = dict(good, schema_version=True)
    with pytest.raises(MODULE.ContractError, match="positive schema"):
        MODULE.validate_health(bad, "0.3.22 (a4a-relay 0.10.0)")


def test_metrics_require_every_operator_series():
    payload = "\n".join(
        f"# TYPE {metric} {metric_type}\n"
        + (f"{metric}_bucket{{le=\"1\"}} 0" if metric_type == "histogram" else f"{metric} 0")
        for metric, metric_type in MODULE.REQUIRED_METRICS.items()
    ).encode()
    MODULE.validate_metrics(payload)
    with pytest.raises(MODULE.ContractError, match="nostr_connections_active"):
        MODULE.validate_metrics(payload.replace(b"nostr_connections_active", b"removed"))


def test_expected_kinds_rejects_duplicates(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("[a4a]\nrequired_for_kinds = [31001, 31001]\n", encoding="utf-8")
    with pytest.raises(MODULE.ContractError, match="unique nonempty integers"):
        MODULE.expected_kinds(config)


def test_expected_inbox_auth_defaults_false_and_requires_boolean(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("[a4a]\nrequired_for_kinds = [31001]\n", encoding="utf-8")
    assert MODULE.expected_inbox_auth(config) is False
    config.write_text('[a4a]\ninbox_auth = "yes"\n', encoding="utf-8")
    with pytest.raises(MODULE.ContractError, match="must be a boolean"):
        MODULE.expected_inbox_auth(config)
