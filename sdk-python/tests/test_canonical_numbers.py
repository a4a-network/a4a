"""All network-facing readers accept numbers ONLY in canonical form.

A wire probe on 2026-09-04 showed that relays store tag values as strings and
interpret only `expiration` numerically (since that day, canonically as
`0|[1-9][0-9]{0,18}`). Leading zeros are forbidden because "045000" and "45000"
represent one number but produce two digests under the rule that hashes the exact
tag string (§1.1 rule 7).

The SDK read `price`, `rating`, `weight`, `deadline`, and others through bare
`int()`/`float()`, which accept "+45000", " 45000", "45_000", non-ASCII digits, and
"5e-1". Live measurements showed a wire price of "+45000" parsed as 45000 with
VALID signatures because the model digest used `str(price)`; rating "+5" entered
reputation, and trust weight "5e-1" became a graph edge. A strict specification-
based implementation reads none of these, producing two states on one network.

The test enumerates readers by name: a new numeric field without canonical parsing
must fail `test_every_numeric_reader_is_listed` instead of silently inheriting `int()`.
"""
import re
import time
from pathlib import Path

import pytest

from a4a import types
from a4a.agent import _safe_from_event
from a4a.event import Event, format_decimal, parse_decimal, parse_uint
from a4a.identity import verify_identity_attestation
from a4a.keys import Keys
from a4a.reputation import build_trust_graph, compute_reputation

NON_CANONICAL_INTS = ["+5", " 5", "5 ", "5_0", "٥", "0x5", "5.0", "-5", "05", "00", ""]
NON_CANONICAL_DECIMALS = ["+0.5", " 0.5", ".5", "5e-1", "0.5_0", "0,5", "nan", "inf", "-0.5",
                          "05.5", "00.5"]


def _event(kind: int, tags: list[list[str]], keys: Keys | None = None) -> Event:
    return Event(kind=kind, tags=tags, content="").sign(keys or Keys())


# --- primitives -----------------------------------------------------------

@pytest.mark.parametrize("raw", NON_CANONICAL_INTS)
def test_parse_uint_rejects_every_non_canonical_form(raw):
    assert parse_uint(raw) is None


@pytest.mark.parametrize("raw", NON_CANONICAL_DECIMALS)
def test_parse_decimal_rejects_every_non_canonical_form(raw):
    assert parse_decimal(raw) is None


def test_parse_decimal_accepts_canonical_forms():
    assert parse_decimal("0.5") == 0.5
    assert parse_decimal("1") == 1.0
    assert parse_decimal("0.00001") == 1e-05
    assert parse_decimal("0") == 0.0
    assert parse_decimal("10.05") == 10.05    # zero after decimal point is not leading


def test_parse_uint_accepts_zero_and_no_leading_zero():
    assert parse_uint("0") == 0
    assert parse_uint("10") == 10
    assert parse_uint("1" + "0" * 18) == 10 ** 18
    assert parse_uint("1" + "0" * 19) is None    # 20 digits exceed the protocol digit limit


@pytest.mark.parametrize("value", [0.5, 1.0, 0.0, 1e-05, 0.1 + 0.2, 1e-09])
def test_format_decimal_round_trips_through_parse_decimal(value):
    text = format_decimal(value)
    assert parse_decimal(text) == value, text


# --- models: one noncanonical number discards the entire event -----------------

def _cases():
    now = int(time.time())
    yield types.AgentProfile, types.KIND_AGENT_PROFILE, "price_range", lambda v: [
        ["capability", "x"], ["category", "development"], ["price_range", v, "10", "USD"]]
    yield types.Intent, types.KIND_INTENT, "budget_min", lambda v: [
        ["intent_type", "service_request"], ["category", "development"], ["need", "x"],
        ["budget_min", v], ["budget_max", "10"], ["deadline", str(now)]]
    yield types.Intent, types.KIND_INTENT, "deadline", lambda v: [
        ["intent_type", "service_request"], ["category", "development"], ["need", "x"],
        ["budget_min", "1"], ["budget_max", "10"], ["deadline", v]]
    yield types.Offer, types.KIND_OFFER, "price", lambda v: [
        ["intent", "a" * 64], ["price", v, "USD"], ["eta", str(now)]]
    yield types.Offer, types.KIND_OFFER, "eta", lambda v: [
        ["intent", "a" * 64], ["price", "5", "USD"], ["eta", v]]
    yield types.Agreement, types.KIND_AGREEMENT, "price", lambda v: [
        ["intent", "a" * 64], ["offer", "b" * 64], ["price", v, "USD"], ["deadline", str(now)],
        ["agent_a", "c" * 64], ["agent_b", "d" * 64], ["sig_a", ""], ["sig_b", ""]]
    yield types.Agreement, types.KIND_AGREEMENT, "deadline", lambda v: [
        ["intent", "a" * 64], ["offer", "b" * 64], ["price", "5", "USD"], ["deadline", v],
        ["agent_a", "c" * 64], ["agent_b", "d" * 64], ["sig_a", ""], ["sig_b", ""]]
    yield types.Review, types.KIND_REVIEW, "rating", lambda v: [
        ["agreement", "a" * 64], ["p", "c" * 64], ["rating", v]]
    yield types.Invoice, types.KIND_INVOICE, "amount", lambda v: [
        ["bolt11", "ln"], ["amount", v, "USD"], ["agreement", "a" * 64],
        ["payer", "c" * 64], ["payee", "d" * 64]]
    yield types.SearchIntent, types.KIND_SEARCH_INTENT, "budget_max", lambda v: [
        ["query", "q"], ["budget_max", v]]
    yield types.IdentityAttestation, types.KIND_IDENTITY_ATTESTATION, "expiration", lambda v: [
        ["p", "c" * 64], ["level", "account:email"], ["expiration", v]]
    yield types.TaskRequest, types.KIND_TASK_REQUEST, "deadline", lambda v: [
        ["agreement", "a" * 64], ["task_id", "t"], ["description", "x"], ["deadline", v]]
    yield types.TaskStatus, types.KIND_TASK_STATUS, "progress", lambda v: [
        ["task_id", "t"], ["agreement", "a" * 64], ["status", "accepted"], ["progress", v]]


@pytest.mark.parametrize("model, kind, field, tags", list(_cases()),
                         ids=[f"{m.__name__}.{f}" for m, _, f, _ in _cases()])
def test_int_field_non_canonical_drops_event_canonical_reads(model, kind, field, tags):
    assert _safe_from_event(model, _event(kind, tags("5"))) is not None, "canonical value parses"
    for raw in NON_CANONICAL_INTS[:-1]:            # empty string covered separately below
        assert _safe_from_event(model, _event(kind, tags(raw))) is None, (field, raw)


def test_trust_weight_non_canonical_drops_event():
    def tags(v):
        return [["trust", "c" * 64], ["weight", v]]
    kind = types.KIND_TRUST_ASSERTION
    assert _safe_from_event(types.TrustAssertion, _event(kind, tags("0.5"))).weight == 0.5
    for raw in NON_CANONICAL_DECIMALS:
        assert _safe_from_event(types.TrustAssertion, _event(kind, tags(raw))) is None, raw


def test_trust_weight_direct_parser_identifies_the_rejected_wire_value():
    """Direct callers must see which non-canonical token was rejected.

    Model validation would still reject ``None`` if the explicit parser guard
    disappeared, but that fallback loses the original untrusted wire value.
    """
    ev = _event(types.KIND_TRUST_ASSERTION,
                [["trust", "c" * 64], ["weight", "5e-1"]])
    with pytest.raises(ValueError, match="5e-1"):
        types.TrustAssertion.from_event(ev)


def test_trust_weight_is_written_without_exponent():
    ev = types.TrustAssertion(trusted="c" * 64, weight=1e-05).to_event()
    assert ev.tag_value("weight") == "0.00001"
    assert types.TrustAssertion.from_event(ev).weight == 1e-05


# --- agreement: a noncanonical price must not become a concluded deal ----------

def test_agreement_with_plus_price_is_not_a_deal_even_with_matching_signatures():
    a, b = Keys(), Keys()
    now = int(time.time())
    canonical = types.Agreement(intent_id="a" * 64, offer_id="b" * 64, price=45000,
                                currency="USD", deadline=now, agent_a=a.pubkey_hex,
                                agent_b=b.pubkey_hex, sig_a="", sig_b="")
    digest = canonical.digest()
    from a4a import crypto
    signed = canonical.model_copy(update={"sig_a": crypto.sign(digest, a.privkey_hex),
                                          "sig_b": crypto.sign(digest, b.privkey_hex)})
    ev = signed.to_event()
    assert _safe_from_event(types.Agreement, ev.sign(a)).verify_signatures()
    # Same deal, but the wire price includes a sign. Our signatures over "45000"
    # would verify while a strict client's digest over "+45000" would not.
    ev.tags = [["price", "+45000", "USD"] if t[0] == "price" else t for t in ev.tags]
    assert _safe_from_event(types.Agreement, ev.sign(a)) is None


# --- reputation and attestations: equivalent readers outside models ------------

def test_reputation_ignores_non_canonical_rating():
    subject = "c" * 64
    author = Keys()

    def review(rating: str) -> Event:
        return _event(types.KIND_REVIEW, [["agreement", "a" * 64], ["p", subject],
                                          ["rating", rating]], author)
    assert compute_reputation([review("5")], subject=subject).total_reviews == 1
    for raw in ["+5", " 5", "٥", "5_0"]:
        assert compute_reputation([review(raw)], subject=subject).total_reviews == 0, raw


def test_trust_graph_ignores_non_canonical_weight():
    author = Keys()

    def trust(weight: str) -> Event:
        return _event(types.KIND_TRUST_ASSERTION, [["trust", "c" * 64], ["weight", weight]],
                      author)
    assert build_trust_graph([trust("0.5")]) == {author.pubkey_hex: {"c" * 64: 0.5}}
    for raw in ["+0.5", "5e-1", "0.5_0", " 0.5"]:
        assert build_trust_graph([trust(raw)]) == {}, raw


def test_identity_readers_agree_on_non_canonical_expiration():
    """The model once read "+N" as indefinite (0) while validation read an expiry.

    One attestation produced two answers; both paths now reject it.
    """
    issuer, subject = Keys(), "c" * 64
    future = str(int(time.time()) + 3600)
    for raw in ["+" + future, " " + future, "abc"]:
        ev = _event(types.KIND_IDENTITY_ATTESTATION,
                    [["p", subject], ["level", "account:email"], ["expiration", raw]], issuer)
        assert not verify_identity_attestation(ev, subject)
        assert _safe_from_event(types.IdentityAttestation, ev) is None
    ok = _event(types.KIND_IDENTITY_ATTESTATION,
                [["p", subject], ["level", "account:email"], ["expiration", future]], issuer)
    assert verify_identity_attestation(ok, subject)
    assert _safe_from_event(types.IdentityAttestation, ok).expiration == int(future)


# --- guard: no bare int()/float() over tag values ------------------------------

def test_every_numeric_reader_is_listed():
    """Ban bare `int(`/`float(` over network `tag_value`/`tag[...]` data.

    Search source rather than behavior so a new noncanonical field cannot appear
    silently. Writer-side calls such as `int(time.time())` or `int(deadline)` do not
    count; only conversions applied to tag values are caught.
    """
    pattern = re.compile(r"\b(?:int|float)\((?:ev\.)?tag(?:_value|s?\[)")
    src_dir = Path(types.__file__).parent
    offenders = []
    for path in src_dir.glob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert offenders == [], "\n".join(offenders)
