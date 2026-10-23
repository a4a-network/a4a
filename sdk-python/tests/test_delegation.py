import time

import pytest

from a4a.delegation import (create_delegation, delegation_target,
                            is_revocation_valid, validate_delegation)
from a4a.event import Event
from a4a.keys import Keys
from a4a.types import KIND_DELEGATION, KIND_INTENT

NOW = int(time.time())


def _setup(expiration=NOW + 86400):
    user, agent = Keys(), Keys()
    deleg = create_delegation(user, agent.pubkey_hex, "My agent", expiration)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    return user, agent, deleg, ev


def test_create_delegation_structure():
    user, agent, deleg, _ = _setup()
    assert deleg.kind == KIND_DELEGATION
    assert deleg.pubkey == user.pubkey_hex
    assert deleg.tag_value("delegate") == agent.pubkey_hex
    assert deleg.tag_value("owner") == user.pubkey_hex
    assert deleg.tag_value("d") == agent.pubkey_hex  # Addressable by delegate.
    assert deleg.verify()


def test_delegations_to_different_agents_have_distinct_slots():
    # Kind 31000 is addressable: d = delegate pubkey. Different agents occupy
    # different d slots, so delegations coexist. Replaceable kind 10001 would let
    # the second overwrite the first.
    user, agent_a, agent_b = Keys(), Keys(), Keys()
    da = create_delegation(user, agent_a.pubkey_hex, "A", NOW + 86400)
    db = create_delegation(user, agent_b.pubkey_hex, "B", NOW + 86400)
    assert da.tag_value("d") == agent_a.pubkey_hex
    assert db.tag_value("d") == agent_b.pubkey_hex
    assert da.tag_value("d") != db.tag_value("d")


def test_valid_chain_passes():
    _, _, deleg, ev = _setup()
    assert validate_delegation(ev, deleg)


@pytest.mark.parametrize("reference", ["missing", "other_owner", "malformed"])
def test_chain_requires_the_event_to_reference_the_supplied_mandate(reference):
    owner, agent, mandate, _ = _setup()
    other = create_delegation(Keys(), agent.pubkey_hex, "Other owner", NOW + 86400)
    tags = {"missing": [], "other_owner": [["delegation", other.id]],
            "malformed": [["delegation", mandate.id, "extra"]]}[reference]
    event = Event(kind=KIND_INTENT, tags=tags, content="x").sign(agent)

    assert event.verify() and mandate.verify() and other.verify()
    assert not validate_delegation(event, mandate)
    if reference == "other_owner":
        assert validate_delegation(event, other)


def test_expired_delegation_fails():
    _, _, deleg, ev = _setup(expiration=NOW - 1)
    assert not validate_delegation(ev, deleg)


def test_wrong_delegate_fails():
    _, _, deleg, _ = _setup()
    stranger = Keys()
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(stranger)
    assert not validate_delegation(ev, deleg)


def test_tampered_delegation_fails():
    _, agent, deleg, ev = _setup()
    fake_owner = Keys()
    # Attacker changes delegate to itself, invalidating the owner's signature.
    deleg.tags = [["delegate", Keys().pubkey_hex], ["owner", fake_owner.pubkey_hex],
                  ["expiration", str(NOW + 86400)]]
    assert not validate_delegation(ev, deleg)


def test_revocation_cannot_validate_when_delegation_has_no_delegate():
    owner = Keys()
    malformed = Event(
        kind=KIND_DELEGATION,
        tags=[["owner", owner.pubkey_hex], ["expiration", str(NOW + 86400)]],
        content="missing delegate").sign(owner)
    revocation = Event(
        kind=31007, tags=[], content="ambiguous revocation").sign(owner)

    assert not is_revocation_valid(revocation, malformed)


def test_delegation_is_not_valid_before_its_declared_creation_time():
    owner, agent = Keys(), Keys()
    delegation = create_delegation(
        owner, agent.pubkey_hex, "future", NOW + 86400, created_at=NOW + 100)
    event = Event(kind=KIND_INTENT, tags=[["delegation", delegation.id]], content="x").sign(agent)

    assert not validate_delegation(event, delegation, at=NOW)


def test_spoofed_owner_fails():
    """Refusal must come specifically from owner validation, not a missing coordinate.

    The previous comment claimed every other chain condition held, but the delegation
    lacked a `d` tag and failed there. The test passed even with owner validation
    COMPLETELY DISABLED, so it did not guard its stated property. An external reviewer
    found this by replacing the comparison with `True` (TEST-DEL-001).

    The coordinate is now present, leaving exactly one refusal reason.
    """
    user, agent, third_party = Keys(), Keys(), Keys()
    deleg = Event(
        kind=KIND_DELEGATION,
        tags=[["d", agent.pubkey_hex],
              ["delegate", agent.pubkey_hex],
              ["owner", third_party.pubkey_hex],
              ["expiration", str(NOW + 86400)]],
        content="spoofed owner",
    ).sign(user)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert deleg.verify()  # Delegation event signature itself is valid.
    assert not validate_delegation(ev, deleg), "spoofed owner was accepted"


def test_matching_owner_passes():
    """POSITIVE control: an honest chain must PASS.

    Without this, "always refuse" is indistinguishable from "owner validation works,"
    and the previous test would stay green with a completely broken chain.
    """
    user, agent = Keys(), Keys()
    deleg = Event(
        kind=KIND_DELEGATION,
        tags=[["d", agent.pubkey_hex],
              ["delegate", agent.pubkey_hex],
              ["owner", user.pubkey_hex],
              ["expiration", str(NOW + 86400)]],
        content="honest delegation",
    ).sign(user)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert validate_delegation(ev, deleg), "honest chain was rejected; check is vacuous"


def test_nonnumeric_expiration_fails():
    user, agent = Keys(), Keys()
    deleg = Event(kind=KIND_DELEGATION,
                  tags=[["delegate", agent.pubkey_hex], ["owner", user.pubkey_hex],
                        ["expiration", "soon"]],
                  content="malformed expiration").sign(user)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert not validate_delegation(ev, deleg)


def test_numeric_but_non_canonical_expiration_fails():
    """Reject numeric but non-canonical expiration forms such as `+1788...` and `0178...`.

    The existing test used the word "soon," which even a naive `int()` implementation
    rejects. The dangerous inputs are forms that `int()` ACCEPTS. For example,
    `int("+1788556527")` is a valid future timestamp, so an `int()`-only reader would
    treat that mandate as active.

    This is not hypothetical. On 2026-09-05 a production relay held nine mandates with
    exactly these expirations: `+1788556527`, `00`, and `05`, left by our finding-74
    probes. The relay accepted and serves them, so readers must decide strictly.
    """
    future = int(time.time()) + 86400
    for raw in (f"+{future}", f"0{future}", "00", "05", " 1788556527", "1_788_556_527",
                f"{future}.0", "1e10"):
        user, agent = Keys(), Keys()
        deleg = Event(kind=KIND_DELEGATION,
                      tags=[["d", agent.pubkey_hex], ["delegate", agent.pubkey_hex],
                            ["owner", user.pubkey_hex], ["expiration", raw]],
                      content="non-canonical expiration").sign(user)
        ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
        assert not validate_delegation(ev, deleg), f"mandate with expiration {raw!r} was accepted"


def test_canonical_future_expiration_still_works():
    """Conversely, strict parsing must preserve a normal mandate."""
    user, agent = Keys(), Keys()
    deleg = create_delegation(user, agent.pubkey_hex, "Regular agent",
                              expiration=int(time.time()) + 86400)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert validate_delegation(ev, deleg)


def test_explicit_now_is_respected():
    user, agent = Keys(), Keys()
    deleg = create_delegation(user, agent.pubkey_hex, "Retro agent", expiration=1)
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert validate_delegation(ev, deleg, now=0)   # exp=1 > now=0 is valid.
    assert not validate_delegation(ev, deleg)       # Expired by the current time.

def _delegation_with_tags(user, tags):
    """Create a delegation with arbitrary tags and a genuine owner signature."""
    return Event(kind=KIND_DELEGATION, tags=tags, content="My agent").sign(user)


def test_delegation_without_d_tag_fails():
    """Kind 31000 is addressable by `d`, which also locates revocation.

    A delegation without `d` used to pass because only `delegate` was checked. The
    paths then diverged: authorization used `delegate`, while revocation lookup used
    missing `d`. A 2026-08-31 relay probe exposed this when owner revocation did not
    clear the cache and a revoked agent kept publishing for the full TTL. This is the
    matching SDK-side gap inherited by third-party implementations.
    """
    user, agent = Keys(), Keys()
    deleg = _delegation_with_tags(user, [
        ["delegate", agent.pubkey_hex],
        ["owner", user.pubkey_hex],
        ["expiration", str(NOW + 86400)],
    ])
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert not validate_delegation(ev, deleg)


def test_delegation_with_contradictory_d_tag_fails():
    """Reject when `d` and `delegate` name different agents.

    Otherwise one tag controls authorization and the other revocation.
    """
    user, agent = Keys(), Keys()
    deleg = _delegation_with_tags(user, [
        ["d", "b" * 64],
        ["delegate", agent.pubkey_hex],
        ["owner", user.pubkey_hex],
        ["expiration", str(NOW + 86400)],
    ])
    ev = Event(kind=KIND_INTENT, tags=[["delegation", deleg.id]], content="x").sign(agent)
    assert not validate_delegation(ev, deleg)


def test_delegation_target_rejects_a_non_canonical_key():
    """Reject an uppercase, non-canonical key in delegation tags.

    This cannot be tested honestly through `validate_delegation`: the `Event` model
    cannot construct an event with a non-canonical pubkey, so the delegation would
    fail because `delegate` differs from `event.pubkey`. The test would be green for
    the wrong reason. The relay has no such event-model restriction, so the complete
    case is reachable there; see `delegation_with_upper_case_key_is_rejected`.

    Test the public function's own contract because its returned `d` goes directly
    into revocation lookup.
    """
    user, agent = Keys(), Keys()
    shouty = agent.pubkey_hex.upper()
    deleg = _delegation_with_tags(user, [
        ["d", shouty],
        ["delegate", shouty],
        ["owner", user.pubkey_hex],
        ["expiration", str(NOW + 86400)],
    ])
    assert delegation_target(deleg) is None


def test_delegation_target_returns_the_key_when_tags_agree():
    """Positive control: return the key when both tags agree.

    Without this, an implementation rejecting everything would leave all three
    negative tests above green.
    """
    _, agent, deleg, _ = _setup()
    assert delegation_target(deleg) == agent.pubkey_hex


def test_default_mandate_is_days_not_years():
    """Keep the mandate lifetime default in the SDK, not only wrappers.

    Finding 112 (2026-09-05): MCP already issued 30-day mandates while
    `Agent.register` and `ensure_registered` still used 365. A README client received
    one year even though onboarding section 6.4 requires "days, not years": short
    lifetime is the primary defense and revocation is the emergency stop. A live
    project-agent run produced a one-year expiration.
    """
    import inspect

    from a4a.agent import DEFAULT_MANDATE_DAYS, Agent

    assert 1 <= DEFAULT_MANDATE_DAYS <= 31, "default mandate must be days, not years"
    for method in (Agent.register, Agent.ensure_registered):
        default = inspect.signature(method).parameters["days"].default
        assert default == DEFAULT_MANDATE_DAYS, f"{method.__name__} uses a separate lifetime: {default}"
    renew = inspect.signature(Agent.ensure_registered).parameters["renew_before_days"].default
    assert 1 <= renew < DEFAULT_MANDATE_DAYS, "renewal must be early, but not immediate"
