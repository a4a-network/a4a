"""Public events must declare when they become stale (NIP-40).

An intent is useless after its deadline, but events were published without an
`expiration` tag. Only relay-local retention policy could remove them, so our stale
events lived forever on foreign relays at the operator's storage expense. Retention
policy does not travel with an event; a tag does.

Do not add expiry where an event forms HISTORY: agreements, reviews, trust,
attestations, delegations, and profiles. Deleting them would erase reputation.
"""
import time

from a4a import types

NOW = int(time.time())
DEADLINE = NOW + 3 * 86400


def _exp(ev) -> int | None:
    raw = ev.tag_value("expiration")
    return int(raw) if raw else None


def test_intent_expires_after_its_own_deadline():
    ev = types.Intent(intent_type="service_request", category="design", need="x",
                      budget_min=0, budget_max=1, deadline=DEADLINE).to_event()
    exp = _exp(ev)
    assert exp is not None, "intent does not declare when it becomes stale"
    assert exp > DEADLINE, "event expires before the intent deadline"
    assert exp <= DEADLINE + types.PUBLIC_GRACE_SECONDS + 5


def test_task_request_expires_after_its_deadline():
    ev = types.TaskRequest(agreement_id="a" * 64, task_id="t", description="d",
                           deadline=DEADLINE).to_event()
    assert (_exp(ev) or 0) > DEADLINE


def test_offer_and_search_get_a_default_lifetime():
    """They have no intrinsic deadline: offers depend on intents and searches are transient."""
    for ev in (types.Offer(intent_id="a" * 64, price=1, eta=3).to_event(),
               types.SearchIntent(query="q").to_event()):
        exp = _exp(ev)
        assert exp is not None and exp > NOW, f"kind {ev.kind} has no lifetime"


def test_history_bearing_events_never_expire():
    """Agreements, reviews, trust, attestations, profiles, and delegations are history.

    Expiring them would make reputation disappear on its own.
    """
    from a4a.delegation import create_delegation
    from a4a.keys import Keys
    owner, agent = Keys(), Keys()
    events = [
        types.AgentProfile(capabilities=["x"], category="design").to_event(),
        types.Review(agreement_id="a" * 64, target="b" * 64, rating=5).to_event(),
        types.TrustAssertion(trusted="b" * 64, weight=0.5).to_event(),
        types.IdentityAttestation(subject="b" * 64, level="org:kep").to_event(),
    ]
    for ev in events:
        assert _exp(ev) is None, f"kind {ev.kind} received expiry, erasing history"


def test_delegation_expiration_is_a_mandate_term_not_a_retention_hint():
    """For delegations, `expiration` is a MANDATE term, not a retention hint.

    NIP-40 uses the same tag name, so relays once deleted delegations at expiry and
    made past agent events unverifiable. The tag must remain for mandate validation;
    relay `delete_expired` must retain kinds 31000 and 31007.
    """
    from a4a.delegation import create_delegation
    from a4a.keys import Keys
    deleg = create_delegation(Keys(), Keys().pubkey_hex, "agent", NOW + 86400)
    assert _exp(deleg) == NOW + 86400


def test_deadline_in_the_past_still_yields_a_future_expiration():
    """An already-overdue event must not disappear immediately.

    Recipients need time to observe that it is stale.
    """
    ev = types.Intent(intent_type="service_request", category="design", need="x",
                      budget_min=0, budget_max=1, deadline=NOW - 10 * 86400).to_event()
    assert (_exp(ev) or 0) > NOW, "overdue intent received an expiration in the past"
