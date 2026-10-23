"""The specification and code must agree wherever compatibility is byte-exact.

The agreement digest is the only value both parties sign. If another implementation
differs by one separator or the type of `price`, signatures can never match, preventing
the agreement, its reputation, and its task flow. The algorithm must therefore appear
IN THE SPECIFICATION, not only in our code.

Until 2026-08-30 the algorithm was absent: the kind registry listed tags and described
the digest only as "canonical." An advertised open protocol could not be implemented
from its own documentation.

This test keeps the document and code aligned by reading a vector FROM the specification
and recomputing it in code. Any divergence fails the suite.
"""
import re
from pathlib import Path

from a4a.types import agreement_digest

SPEC = Path(__file__).resolve().parent.parent.parent / "docs" / "spec" / "a4a-protocol-v0.4.md"


def _documented_digest() -> str:
    text = SPEC.read_text(encoding="utf-8")
    m = re.search(r"digest = ([0-9a-f]{64})", text)
    assert m, "the specification has no reference digest to verify"
    return m.group(1)


def test_documented_digest_matches_the_implementation():
    """The specification's reference vector must be reproducible by the code."""
    computed = agreement_digest("i" * 64, "o" * 64, 45000, "USD", 1_800_000_000,
                                "a" * 64, "b" * 64)
    assert computed == _documented_digest(), (
        "the specification and code disagree on the agreement digest; another "
        "implementation following the document cannot produce a compatible signature")


def test_party_order_changes_the_deal():
    """Party order is significant and explicitly documented by the specification.

    A symmetric digest would make "A's agreement with B" and "B's agreement with A"
    the same obligation with reversed roles, even though roles determine the worker.
    """
    straight = agreement_digest("i" * 64, "o" * 64, 45000, "USD", 1_800_000_000,
                                "a" * 64, "b" * 64)
    swapped = agreement_digest("i" * 64, "o" * 64, 45000, "USD", 1_800_000_000,
                               "b" * 64, "a" * 64)
    assert straight != swapped


def test_price_is_hashed_as_a_string_not_a_number():
    """Hash `price` as a string.

    This non-obvious rule is explicit in the specification: an implementation that
    encodes a number gets a different digest and can never interoperate, while the
    symptom appears only as an "invalid signature."
    """
    import hashlib
    import json

    from a4a.types import AGREEMENT_DOMAIN, tagged_hash

    as_string = json.dumps(["a4a-agreement-v2", "i" * 64, "o" * 64, "45000", "USD",
                            1_800_000_000, "a" * 64, "b" * 64], separators=(",", ":"))
    as_number = json.dumps(["a4a-agreement-v2", "i" * 64, "o" * 64, 45000, "USD",
                            1_800_000_000, "a" * 64, "b" * 64], separators=(",", ":"))
    assert tagged_hash(AGREEMENT_DOMAIN, as_string.encode()).hex() == _documented_digest()
    assert tagged_hash(AGREEMENT_DOMAIN, as_number.encode()).hex() != _documented_digest()
    # Bare SHA-256 (the untagged v1 format) intentionally no longer matches the document.
    assert hashlib.sha256(as_string.encode()).hexdigest() != _documented_digest()
