"""Core triage tests: decisions use only verifiable facts."""
from a4a_agent.facts import SenderFacts
from a4a_agent.policy import Policy, decide


def _facts(**kw):
    base = dict(pubkey="ff" * 32, attested_by=(), trust=0.1, reviews=0,
                rating=0.0, connected=False)
    base.update(kw)
    return SenderFacts(**base)


def test_stranger_is_archived_by_default():
    """At cold start there are no signals, so every stranger is archived."""
    v = decide(_facts(), Policy())
    assert v.allow is False and v.reasons == ()


def test_connected_sender_always_passes():
    v = decide(_facts(connected=True), Policy())
    assert v.allow is True and "connection" in v.reasons[0].lower()


def test_attestation_from_trusted_issuer_passes():
    v = decide(_facts(attested_by=("issuer1",)), Policy(trusted_issuers=("issuer1",)))
    assert v.allow is True and "issuer1" in v.reasons[0]


def test_attestation_from_unknown_issuer_does_not_pass():
    v = decide(_facts(attested_by=("stranger",)), Policy(trusted_issuers=("issuer1",)))
    assert v.allow is False


def test_trust_path_above_baseline_passes():
    v = decide(_facts(trust=0.6), Policy(min_trust=0.5))
    assert v.allow is True


def test_baseline_trust_is_not_a_signal():
    """0.1 means "no path", not "slightly trusted", so it is not a signal."""
    v = decide(_facts(trust=0.1), Policy(min_trust=0.0))
    assert v.allow is False


def test_reviews_are_not_a_signal_unless_explicitly_required():
    """Colluding parties can create agreements and reviews for each other.

    Therefore, accepted review count is an admission signal only when the owner
    explicitly configures a threshold.
    """
    assert decide(_facts(reviews=50), Policy()).allow is False
    assert decide(_facts(reviews=50), Policy(min_reviews=10)).allow is True


def test_reasons_are_verifiable_facts_not_self_claimed_text():
    v = decide(_facts(attested_by=("issuer1",), reviews=12, rating=4.8),
               Policy(trusted_issuers=("issuer1",), min_reviews=5))
    joined = " ".join(v.reasons)
    assert "issuer1" in joined and "12" in joined


# --- Explicit distrust (result of audit fix F2) ----------------------------------

def test_explicit_distrust_overrides_every_other_signal():
    """Our direct distrust edge overrides every other admission signal."""
    distrusted = _facts(trust=0.0, connected=True, attested_by=("issuer1",),
                        reviews=99, rating=5.0)
    v = decide(distrusted, Policy(trusted_issuers=("issuer1",), min_reviews=1))
    assert v.allow is False
    assert "distrusted" in " ".join(v.reasons).lower()


# --- Attestation assurance level (internal audit 2026-08-29) --------------------

def test_min_loa_filters_weak_attestations():
    """Trusting an issuer does not mean trusting every attestation it issues.

    The same issuer may provide both a low-assurance verified social account and
    a high-assurance identity bound by a qualified signature. The policy must
    distinguish them before escalating a sender to the owner.
    """
    p = Policy(trusted_issuers=("issuer1",), min_loa="substantial")
    weak = _facts(attested_by=("issuer1",), attested_loa=("low",))
    assert decide(weak, p).allow is False

    strong = _facts(attested_by=("issuer1",), attested_loa=("high",))
    v = decide(strong, p)
    assert v.allow is True and "high" in " ".join(v.reasons)


def test_without_min_loa_any_attestation_of_a_trusted_issuer_passes():
    """Default behavior is preserved until the owner chooses a threshold."""
    p = Policy(trusted_issuers=("issuer1",))
    assert decide(_facts(attested_by=("issuer1",), attested_loa=("low",)), p).allow is True
