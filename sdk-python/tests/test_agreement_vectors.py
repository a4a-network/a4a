"""Offline fixed agreement-v2 bytes and strict codec inputs; no relay or identity."""
import json
from pathlib import Path

import pytest
from a4a import types


VECTORS = json.loads((Path(__file__).resolve().parents[2]
    / "interop/vectors/agreement-v2.json").read_text(encoding="ascii"))
NAMES = {"intentId": "intent_id", "offerId": "offer_id", "agentA": "agent_a", "agentB": "agent_b"}


def terms(vector):
    return {NAMES.get(key, key): int(value) if key in ("price", "deadline") else value
            for key, value in vector["terms"].items()}


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=lambda v: v["name"])
def test_frozen_v2_bytes_and_digest(vector):
    assert types.AGREEMENT_DOMAIN == VECTORS["domain"]
    assert types.agreement_canonical(**terms(vector)) == vector["canonical"].encode("ascii")
    assert types.agreement_digest(**terms(vector)) == vector["digest"]


@pytest.mark.parametrize("field", ["price", "deadline"])
@pytest.mark.parametrize("value", [-1, 10**19, True, False, 1.5, 1.0, "12", "01", None, float("nan"), float("inf"), b"12"])
def test_codec_rejects_non_integer_or_out_of_range_numbers(field, value):
    values = {**terms(VECTORS["cases"][0]), field: value}
    with pytest.raises(ValueError):
        types.agreement_canonical(**values)
    with pytest.raises(ValueError):
        types.agreement_digest(**values)


@pytest.mark.parametrize("field", ["intent_id", "offer_id", "currency", "agent_a", "agent_b"])
@pytest.mark.parametrize("value", [None, 0, True, [], {}, b"USD", bytearray(b"USD")])
def test_codec_rejects_non_string_text_without_coercion(field, value):
    with pytest.raises(ValueError):
        types.agreement_canonical(**{**terms(VECTORS["cases"][0]), field: value})


@pytest.mark.parametrize("field", ["price", "deadline"])
@pytest.mark.parametrize("value", [True, False, 1.0, "12"])
def test_agreement_model_does_not_erase_invalid_input_types(field, value):
    with pytest.raises(ValueError):
        types.Agreement(**{**terms(VECTORS["cases"][0]), field: value}, sig_a="", sig_b="")


@pytest.mark.parametrize("field", ["intent_id", "offer_id", "currency", "agent_a", "agent_b"])
@pytest.mark.parametrize("value", [b"USD", bytearray(b"USD")])
def test_agreement_model_rejects_coercible_non_string_text(field, value):
    with pytest.raises(ValueError):
        types.Agreement(**{**terms(VECTORS["cases"][0]), field: value}, sig_a="", sig_b="")


def test_text_normalization_would_change_the_signed_agreement():
    vectors = {v["name"]: v for v in VECTORS["cases"]}
    assert vectors["precomposed"]["digest"] != vectors["decomposed"]["digest"]
    assert vectors["legacy-ascii"]["digest"] == "0c3a734fd58e2f95ce39875702a748410de1ee67c3e267e623bc0448122526c8"
