"""The `level` field was unrestricted text (internal audit, 2026-08-29).

Two issuers used "verified" for entirely different evidence, making cross-issuer level
comparisons meaningless even though consumers make decisions from those comparisons.
Worse, an issuer could claim `gov_id` after checking only an email address and remain
formally correct because the semantics were "defined by the issuer."

The vocabulary names the EVIDENCE rather than the result and is accompanied by a
normalized assurance scale (eIDAS: low / substantial / high), allowing consumers to
write policy without knowing every national scheme.
"""
import pytest
from pydantic import ValidationError

from a4a import types
from a4a.keys import Keys


def test_canonical_levels_are_accepted():
    for level in ("account:telegram", "org:domain", "org:kep", "person:gosklyuch"):
        att = types.IdentityAttestation(subject="a" * 64, level=level)
        assert att.to_event().tag_value("level") == level


def test_unknown_level_is_rejected():
    """Without rejection, the vocabulary is meaningless because any value is allowed."""
    with pytest.raises(ValidationError):
        types.IdentityAttestation(subject="a" * 64, level="verified")


def test_issuer_specific_level_needs_an_explicit_prefix():
    """Experiments are allowed but must be visibly marked as non-standard."""
    att = types.IdentityAttestation(subject="a" * 64, level="x-acme:internal-kyc")
    assert att.to_event().tag_value("level") == "x-acme:internal-kyc"


def test_assurance_is_derived_and_published():
    """Consumers compare assurance, not national scheme names."""
    att = types.IdentityAttestation(subject="a" * 64, level="org:kep")
    ev = att.to_event()
    assert ev.tag_value("loa") == "high"
    assert types.IdentityAttestation.from_event(ev).loa == "high"


def test_experimental_level_has_the_lowest_assurance():
    """A non-standard level cannot grant itself high assurance."""
    att = types.IdentityAttestation(subject="a" * 64, level="x-acme:internal-kyc")
    assert att.to_event().tag_value("loa") == "low"


def test_organisation_reference_is_namespaced():
    """Organization references are namespace-value pairs.

    National tax and registration IDs, LEIs, and domains cannot share one field tied
    to a single national identifier; the first foreign issuer would break that model.
    """
    att = types.IdentityAttestation(subject="a" * 64, level="org:kep",
                                    ref="inn:7701234567")
    ev = att.to_event()
    assert ev.tag_value("ref") == "inn:7701234567"
    assert types.IdentityAttestation.from_event(ev).ref == "inn:7701234567"


def test_reference_without_namespace_is_rejected():
    with pytest.raises(ValidationError):
        types.IdentityAttestation(subject="a" * 64, level="org:kep", ref="7701234567")
