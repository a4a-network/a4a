"""Input guards the suite failed to prove (mutation pass, 2026-08-29).

The pass disabled each `if …: raise` check individually and ran the entire suite.
The cases below survived mutation, meaning no test noticed their absence. All parse
NETWORK DATA or owner input, so "that will never happen" is not a valid assumption.
"""
import pytest
from pydantic import ValidationError

from a4a import files, types
from a4a.event import Event
from a4a.keys import Keys


# --- canonical event fields (event.py) ----------------------------------------

def test_event_rejects_uppercase_id():
    """Uppercase hex is valid hex but NOT a canonical representation.

    Different casing of one ID breaks string-based deduplication, NIP-09 deletion
    matching, and delegation lookup. A relay gap found that morning relied on this
    exact issue; this test establishes the same boundary in the SDK.
    """
    with pytest.raises(ValidationError):
        Event(kind=1, tags=[], content="", id="A" * 64)


def test_event_rejects_id_of_wrong_length():
    with pytest.raises(ValidationError):
        Event(kind=1, tags=[], content="", id="ab" * 20)


def test_event_rejects_malformed_signature():
    """A wrong-length signature marks a corrupt or forged event.

    Allowing it into the model passes garbage to `verify()`, where it looks like an
    ordinary invalid signature and sends diagnosis down the wrong path.
    """
    with pytest.raises(ValidationError):
        Event(kind=1, tags=[], content="", sig="ff" * 10)
    with pytest.raises(ValidationError):
        Event(kind=1, tags=[], content="", sig="F" * 128)


# --- closed enumerations (types.py) -------------------------------------------

def test_profile_rejects_unknown_category():
    """An unknown category makes a profile undiscoverable because search uses facets."""
    with pytest.raises(ValidationError) as e:
        types.AgentProfile(capabilities=["x"], category="invented")
    assert "development" in str(e.value), "error does not suggest allowed values"


def test_intent_rejects_unknown_type():
    with pytest.raises(ValidationError) as e:
        types.Intent(intent_type="invented", category="design", need="n",
                     budget_min=0, budget_max=1, deadline=0)
    assert "service_request" in str(e.value)


def test_agreement_rejects_unknown_status():
    with pytest.raises(ValidationError) as e:
        types.Agreement(intent_id="i", offer_id="o", price=1, currency="USD",
                        deadline=0, agent_a="a", agent_b="b", sig_a="", sig_b="",
                        status="invented")
    assert "agreed" in str(e.value)


@pytest.mark.parametrize("field", ["intent_id", "offer_id", "currency", "agent_a", "agent_b"])
def test_agreement_codec_rejects_non_string_text_without_external_vectors(field):
    """The signed wire codec must not coerce text fields before hashing.

    The frozen-vector suite proves the same contract, but it reads data outside
    ``sdk-python``.  Keeping this small negative control self-contained lets the
    mutation audit exercise the guard inside its disposable package snapshot.
    """
    values = {
        "intent_id": "i",
        "offer_id": "o",
        "price": 1,
        "currency": "USD",
        "deadline": 2,
        "agent_a": "a",
        "agent_b": "b",
    }
    values[field] = None
    with pytest.raises(ValueError, match="text fields must be strings"):
        types.agreement_canonical(**values)


# --- parsing externally supplied keys (keys.py) -------------------------------

def test_asec_decoding_rejects_garbage():
    """Owners paste keys; corrupt input must not become somebody else's key."""
    with pytest.raises(ValueError, match="bech32"):
        Keys.from_asec("not-a-key-at-all")


def test_asec_decoding_rejects_bad_payload():
    """The bech32 envelope checksum may pass while its payload remains invalid.

    Both layers require validation; this branch specifically covers the payload.
    """
    import bech32
    broken = bech32.bech32_encode("asec", [1, 2, 3])   # not a whole number of bytes
    with pytest.raises(ValueError, match="bech32"):
        Keys.from_asec(broken)

# --- file download address (files.py) -----------------------------------------

def test_download_target_rejects_host_without_addresses():
    """A hostname resolving to an empty list is a failure, not zero safe addresses.

    Later code reads `addresses[0]`; without this branch, an IndexError would replace
    the useful diagnostic.
    """
    with pytest.raises(files.DownloadTargetError, match="did not resolve to any address"):
        files.resolve_download_target("https://example.org/f.bin", _resolver=lambda h: [])
