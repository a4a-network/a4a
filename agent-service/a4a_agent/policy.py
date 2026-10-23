"""Triage policy: escalate a request to the owner or archive it.

The decision is a pure function of verifiable facts: no network, model, or
message-body inspection, and therefore no token cost regardless of spam volume.
"""
from dataclasses import dataclass

from a4a.reputation import WOT_BASELINE
from a4a.types import LOA_ORDER

from .facts import SenderFacts

# Import WOT_BASELINE ("no path in the graph") from the SDK instead of
# duplicating it. Otherwise, the admission threshold could silently diverge from
# the calculated weight (review, A17). Its value is positive but represents no
# trust, so it cannot be an admission signal.


@dataclass(frozen=True)
class Policy:
    trusted_issuers: tuple[str, ...] = ()
    min_trust: float = 0.0
    # 0 means reviews are not an admission signal. This is the default because
    # two colluding parties can sign any number of agreements with each other.
    # The review count informs the owner but does not admit a stranger by itself.
    min_reviews: int = 0
    # Minimum attestation assurance: "" means no requirement (preserving default
    # behavior), otherwise "low", "substantial", or "high". The owner chooses
    # this threshold explicitly: trusting an issuer is different from trusting
    # every attestation it produces (internal audit 2026-08-29).
    min_loa: str = ""

    def can_allow_unconnected(self) -> bool:
        """Return whether this policy can ever admit an unconnected sender.

        This bounds triage cost: if the answer is no, collecting expensive facts
        about the sender cannot change the result. At cold start, an empty policy
        rejects every stranger, which is expected to be the common case.
        """
        return bool(self.trusted_issuers) or self.min_trust > 0.0 or self.min_reviews > 0


def _loa_at_least(actual: str, required: str) -> bool:
    """Return whether assurance meets the threshold; no threshold accepts all."""
    if not required:
        return True
    if actual not in LOA_ORDER:
        return False  # Unknown or missing assurance never meets a threshold.
    return LOA_ORDER.index(actual) >= LOA_ORDER.index(required)


@dataclass(frozen=True)
class Verdict:
    allow: bool
    reasons: tuple[str, ...]


def decide(f: SenderFacts, p: Policy) -> Verdict:
    # PLAN DEVIATION (2026-08-27): a weight of 0.0 can only originate from OUR
    # direct "distrust" edge (see audit fix F2). The owner's explicit statement
    # must override every other signal or it would be meaningless.
    if f.trust == 0.0:
        return Verdict(False, ("we explicitly distrusted this key",))
    if f.connected:
        return Verdict(True, ("a mutual connection is already established",))
    reasons: list[str] = []
    pairs = list(zip(f.attested_by, f.attested_loa or ("",) * len(f.attested_by)))
    trusted = tuple((i, loa) for i, loa in pairs if i in p.trusted_issuers
                    and _loa_at_least(loa, p.min_loa))
    if trusted:
        reasons.append("verified by issuer "
                       + ", ".join(f"{i} ({loa})" if loa else i for i, loa in trusted))
    if f.trust > WOT_BASELINE and f.trust >= p.min_trust > 0.0:
        reasons.append(f"trust path exists with weight {f.trust:.2f}")
    if p.min_reviews > 0 and f.reviews >= p.min_reviews:
        reasons.append(f"{f.reviews} accepted reviews for signed agreements, "
                       f"rating {f.rating:.1f}")
    return Verdict(bool(reasons), tuple(reasons))
