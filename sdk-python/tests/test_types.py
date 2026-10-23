import time

import pytest
from pydantic import ValidationError

from a4a import types
from a4a.crypto import sign
from a4a.keys import Keys

DEADLINE = int(time.time()) + 5 * 86400
PUB_A, PUB_B = "aa" * 32, "bb" * 32


def _intent(**over):
    base = dict(intent_type="service_request", category="development", need="landing_page",
                budget_min=30000, budget_max=50000, currency="USD",
                deadline=DEADLINE, language="ru", content="Need a landing page")
    base.update(over)
    return types.Intent(**base)


def test_intent_roundtrip_and_tags():
    ev = _intent().to_event(delegation_id="d" * 64)
    assert ev.kind == types.KIND_INTENT
    assert ev.tag_value("category") == "development"
    assert ev.tag_value("delegation") == "d" * 64
    restored = types.Intent.from_event(ev)
    assert restored.budget_max == 50000 and restored.need == "landing_page"
    assert restored.source is ev


def test_intent_rejects_unknown_category():
    with pytest.raises(ValidationError):
        _intent(category="magic")


def test_addressable_events_get_unique_d_tag():
    a, b = _intent().to_event(), _intent().to_event()
    assert a.tag_value("d") and b.tag_value("d") and a.tag_value("d") != b.tag_value("d")


def test_profile_uses_fixed_d_tag():
    profile = types.AgentProfile(capabilities=["web_development"], category="development",
                                 languages=["ru"], price_range=(5000, 50000, "USD"),
                                 content="Web development")
    ev = profile.to_event()
    assert ev.tag_value("d") == "profile"
    assert ev.tag_values("capability") == ["web_development"]


def test_offer_roundtrip():
    offer = types.Offer(intent_id="e" * 64, price=45000, currency="USD",
                        eta=DEADLINE, content="Ready in five days")
    ev = offer.to_event()
    assert ev.tag_value("intent") == "e" * 64
    restored = types.Offer.from_event(ev)
    assert restored.price == 45000 and restored.eta == DEADLINE


def test_agreement_signatures():
    ka, kb = Keys(), Keys()
    digest = types.agreement_digest("i" * 64, "o" * 64, 45000, "USD", DEADLINE,
                                    ka.pubkey_hex, kb.pubkey_hex)
    agreement = types.Agreement(
        intent_id="i" * 64, offer_id="o" * 64, price=45000, currency="USD",
        deadline=DEADLINE, agent_a=ka.pubkey_hex, agent_b=kb.pubkey_hex,
        sig_a=sign(digest, ka.privkey_hex), sig_b=sign(digest, kb.privkey_hex))
    assert agreement.verify_signatures()
    agreement.price = 1  # tampering with terms invalidates both signatures
    assert not agreement.verify_signatures()


def test_review_has_target_p_tag():
    review = types.Review(agreement_id="a" * 64, target=PUB_B, rating=5,
                          content="Excellent")
    ev = review.to_event()
    assert ev.tag_value("p") == PUB_B and ev.tag_value("rating") == "5"
    assert types.Review.from_event(ev).rating == 5


def test_review_rating_bounds():
    with pytest.raises(ValidationError):
        types.Review(agreement_id="a" * 64, target=PUB_B, rating=6)


def test_task_flow_models_roundtrip():
    req = types.TaskRequest(agreement_id="a" * 64, task_id="t-1",
                            description="Build a landing page", deadline=DEADLINE)
    st = types.TaskStatus(task_id="t-1", agreement_id="a" * 64,
                          status="in_progress", progress=50)
    res = types.TaskResult(task_id="t-1", agreement_id="a" * 64,
                           result_url="https://example.com/r")
    assert types.TaskRequest.from_event(req.to_event()).task_id == "t-1"
    assert types.TaskStatus.from_event(st.to_event()).progress == 50
    assert types.TaskResult.from_event(res.to_event()).result_url == "https://example.com/r"


def test_task_status_rejects_unknown_status():
    with pytest.raises(ValidationError):
        types.TaskStatus(task_id="t", agreement_id="a" * 64, status="lost", progress=0)


def test_remaining_kinds_roundtrip():
    inv = types.Invoice(bolt11="lnbc1...", amount=45000, currency="USD",
                        agreement_id="a" * 64, payer=PUB_A, payee=PUB_B)
    si = types.SearchIntent(query="landing page", category="development",
                            intent_type="service_request")
    ta = types.TrustAssertion(trusted=PUB_B, weight=0.9, reason="five deals")
    rep = types.Report(target_event="e" * 64, content="spam")
    assert types.Invoice.from_event(inv.to_event()).payee == PUB_B
    assert types.SearchIntent.from_event(si.to_event()).query == "landing page"
    assert types.TrustAssertion.from_event(ta.to_event()).weight == 0.9
    assert types.Report.from_event(rep.to_event()).target_event == "e" * 64


def test_report_requires_target():
    with pytest.raises(ValidationError):
        types.Report(content="report without a target")


def test_validation_lower_bounds():
    with pytest.raises(ValidationError):
        types.Review(agreement_id="a" * 64, target=PUB_B, rating=0)
    with pytest.raises(ValidationError):
        types.TrustAssertion(trusted=PUB_B, weight=-0.1)
    with pytest.raises(ValidationError):
        types.TaskStatus(task_id="t", agreement_id="a" * 64, status="in_progress", progress=101)


def test_kind_constants_exported_from_package():
    import a4a
    assert a4a.KIND_INTENT == 31002 and a4a.KIND_REVIEW == 31005


# --- Third-party relay portability: duplicate facets into indexable tags -----------

def test_intent_carries_indexed_topic_tags():
    """Duplicate facets into namespaced `t` tags for NIP-01 relay indexing.

    NIP-01 indexes only SINGLE-CHARACTER tags. Without this duplication, search fails
    on third-party relays, as confirmed across 25 live relays on 2026-08-28.
    """
    ev = types.Intent(intent_type="service_request", category="design", need="landing_page",
                      budget_min=0, budget_max=1, deadline=0,
                      language="ru").to_event()
    topics = ev.tag_values("t")
    assert "a4a:cat:design" in topics
    assert "a4a:type:service_request" in topics
    assert "a4a:lang:ru" in topics
    # Keep original multi-character tags for more precise searches on our relay fork.
    assert ev.tag_value("category") == "design"


def test_offer_references_intent_by_event_tag():
    """Reference `intent_id` with the standard `e` event tag indexed by all relays."""
    ev = types.Offer(intent_id="a" * 64, price=100, eta=3).to_event()
    assert ev.tag_value("e") == "a" * 64
    assert ev.tag_value("intent") == "a" * 64
