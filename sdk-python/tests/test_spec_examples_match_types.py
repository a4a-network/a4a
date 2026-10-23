"""Public-spec event examples must match what the SDK actually sends.

Why this guard exists. On 2026-09-04, an agent forbidden from reading our code and
allowed to use only the specification built a client from scratch, then discovered
that the §8 examples in `a4a-master-spec.md` were stale. This was not a single typo
but a class of errors: the examples had none of the tags added while closing
internal-audit findings.

The cost is concrete. A third-party implementation following §8.5 literally
publishes a deal without the `delegation` tag, so the relay rejects it, and without
`p` tags, so the counterparty cannot find it outside our fork. These are exactly
findings 34 and 55, which were declared closed. They were closed in code but stayed
open in the normative document, and that document is PUBLIC and part of the open
source slice.

Visual review does not catch this: the mismatch appears only by comparing ten
examples with ten events actually built by the SDK. The guard is therefore
mechanical, like `test_enforced_kinds_match_registry.py`, written for the same reason.

How it works, and why. The first version extracted tag names from `to_event` source
with a REGEX. An independent reviewer demonstrated that it missed tags added by a
helper or loop (`SearchIntent` adds six tags in a loop while the regex saw four),
and ignored VALUES: `["t", "development"]` passed even though the SDK sends
`a4a:cat:development`, making an implementation based on that example invisible to
search. The guard now INSTANTIATES models and CALLS `to_event`, comparing a real
event instead of function source.
"""
import json
import re
from pathlib import Path

import pytest

from a4a import types

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "a4a-master-spec.md"

_PK_A = "a" * 64
_PK_B = "b" * 64
_ID = "c" * 64

# Samples populate ALL optional fields so optional tags appear in the event too;
# the specification example must show everything the implementation can emit.
SAMPLES = [
    lambda: types.AgentProfile(
        capabilities=["web_development"], category="development",
        price_range=(1, 2, "USD"), availability="24h", portfolio="https://x"),
    lambda: types.Intent(
        intent_type="service_request", category="development", need="n",
        budget_min=1, budget_max=2, deadline=1, location="spb"),
    lambda: types.Offer(intent_id=_ID, price=1, eta=1, portfolio="https://x"),
    lambda: types.Agreement(
        intent_id=_ID, offer_id=_ID, price=1, deadline=1,
        agent_a=_PK_A, agent_b=_PK_B, sig_a="", sig_b=""),
    lambda: types.Review(agreement_id=_ID, target=_PK_B, rating=5),
    lambda: types.Invoice(
        bolt11="", amount=1, agreement_id=_ID, payer=_PK_A, payee=_PK_B),
    lambda: types.SearchIntent(
        query="q", category="development", intent_type="service_request",
        budget_min=1, budget_max=2, language="ru", since=1),
    lambda: types.TaskRequest(
        agreement_id=_ID, task_id="t", description="d", deadline=1, executor=_PK_B),
    lambda: types.TaskStatus(task_id="t", agreement_id=_ID, status="in_progress"),
    lambda: types.TaskResult(task_id="t", agreement_id=_ID, result_url="https://x"),
]

# Tags intentionally absent from examples. Every entry must include a REASON;
# without one, it is an unnoticed mismatch rather than an exception.
# `expiration` USED to be exempt ("documented in a separate section"), until an
# external check on 2026-09-04 (finding 108) exposed the cost: an implementation
# following §8 publishes requests and offers without expiry, while the SDK always
# sets it (§2.8, NIP-40); on a foreign relay those events live forever. A tag the
# implementation always emits must appear in the example.
ALLOWED_ABSENT: dict[str, str] = {}


def _real_event(make):
    model = make()
    if isinstance(model, types.Agreement):
        return model.to_event(publisher_delegation=_ID, counterparty_delegation=_ID)
    return model.to_event(delegation_id=_ID)


def _sdk_events() -> dict[int, list[list[str]]]:
    """Map kind to tags on the event the SDK actually builds."""
    out = {}
    for make in SAMPLES:
        ev = _real_event(make)
        assert ev.kind not in out, "two samples for kind %d" % ev.kind
        out[ev.kind] = ev.tags
    return out


def _spec_examples() -> dict[int, list[list[str]]]:
    """Map kind to tags from the JSON example in specification §8.

    Read ONLY section 8 ("Event reference"): it is normative and implementations
    are built from it. Section 6.1 demonstrates the generic Nostr event structure
    and uses kind 31001 as an arbitrary placeholder with `["key","value"]`; treating
    it as an agent-profile example would be a guard bug, not a finding.
    """
    text = SPEC.read_text(encoding="utf-8")
    start = text.find("\n## 8.")
    assert start > 0, "section 8 not found; the guard is stale"
    end = text.find("\n## 9.", start)
    text = text[start:end if end > 0 else len(text)]
    out: dict[int, list[list[str]]] = {}
    for block in re.findall(r"```json\n(.*?)\n```", text, re.S):
        try:
            ev = json.loads(block)
        except ValueError:
            continue
        if not isinstance(ev, dict) or "kind" not in ev or "tags" not in ev:
            continue
        out.setdefault(ev["kind"], []).extend(t for t in ev["tags"] if t)
    return out


def _names(tags) -> set[str]:
    return {t[0] for t in tags}


def test_there_is_something_to_compare():
    """Positive control: an empty parse must not look like a passing test."""
    sdk, spec = _sdk_events(), _spec_examples()
    missing = sorted(k for k in sdk if k not in spec)
    assert not missing, "§8 has no example for kinds %s; the guard is blind" % missing
    assert all(_names(t) for t in sdk.values()), "the SDK built an event without tags"


@pytest.mark.parametrize("make", SAMPLES, ids=lambda m: type(m()).__name__)
def test_spec_example_shows_every_tag_the_sdk_sends(make):
    """Every SDK tag must appear in its example or in the exception list."""
    ev = _real_event(make)
    absent = _names(ev.tags) - _names(_spec_examples()[ev.kind]) - set(ALLOWED_ABSENT)
    assert not absent, (
        "kind %d: the SDK sends tags %s, but the public §8 example omits them. A "
        "third-party implementation following the example will not add them. Update "
        "the example or add the tag to ALLOWED_ABSENT WITH A REASON."
        % (ev.kind, sorted(absent)))


@pytest.mark.parametrize("make", SAMPLES, ids=lambda m: type(m()).__name__)
def test_spec_example_shows_no_tag_the_sdk_never_sends(make):
    """Conversely, examples must not promise tags the implementation never emits."""
    ev = _real_event(make)
    invented = _names(_spec_examples()[ev.kind]) - _names(ev.tags)
    assert not invented, (
        "kind %d: the public §8 example shows tags %s that the SDK never emits. "
        "A third-party implementation will assume they are part of the protocol."
        % (ev.kind, sorted(invented)))


@pytest.mark.parametrize("make", SAMPLES, ids=lambda m: type(m()).__name__)
def test_indexable_facet_values_carry_the_namespace(make):
    """Example `t` values must carry the same namespace as the SDK.

    The tag name can match while the value does not: `["t", "development"]` versus
    `a4a:cat:development`. Search uses the value, so an implementation following
    the bad example publishes requests nobody can find. Found by an independent
    reviewer on 2026-09-04.
    """
    ev = _real_event(make)
    sdk_prefixes = {v.split(":")[0] + ":" + v.split(":")[1] + ":"
                    for _, v in ((t[0], t[1]) for t in ev.tags if t[0] == "t")}
    if not sdk_prefixes:
        pytest.skip("this kind carries no `t` facets")
    for tag in _spec_examples()[ev.kind]:
        if tag[0] != "t":
            continue
        assert any(tag[1].startswith(p) for p in sdk_prefixes), (
            "kind %d: example value %r has no namespace; the SDK sends %s"
            % (ev.kind, tag[1], sorted(sdk_prefixes)))


def test_every_exception_carries_a_reason():
    """An exception without a reason is a forgotten mismatch, not an exception."""
    for tag, reason in ALLOWED_ABSENT.items():
        assert len(reason) > 40, "exception for tag %r has no meaningful reason" % tag
