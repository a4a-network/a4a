"""The kinds requiring delegation MUST be complete relative to the registry.

Why this guard exists. `relay/config.prod.toml` contains `required_for_kinds`, the
kinds for which the relay requires a `["delegation", <id>]` tag. Anything absent
from the list can be published by a freshly generated key with no chain to its
owner. The list is therefore the boundary between traceable and untraceable event
provenance, and a missing entry is nearly impossible to spot in a row of numbers.

That happened in practice. On 2026-08-31, kinds 31033 (addressed message) and 31034
(delivery receipt) were absent. Both are published OPENLY when the sender calls
`send_private_message(wrap=False)` or `acknowledge(wrap=False)`, both can carry a
delegation tag, and both were accepted from a key without a mandate. Other omissions
in the same file had explanatory comments; these two were simply missing.

Test rule: every registry kind appears either in the enforcement list or in the
exception list BELOW with a reason. There is no silent third category.
"""
import re
from pathlib import Path

import pytest

from a4a import types

CONFIG = Path(__file__).resolve().parent.parent.parent / "relay" / "config.prod.toml"

# Production configuration is absent from the public slice: this guard compares OUR
# relay with the registry, and a foreign clone has nothing to compare. A public-slice
# run on 2026-09-04 produced four FileNotFoundError failures on a new user's first
# `pytest`. The skip is explicit and reasoned: green would otherwise mean "not tested".
pytestmark = pytest.mark.skipif(
    not CONFIG.exists(),
    reason="relay/config.prod.toml is absent from this tree (public slice); the "
           "production-relay registry guard runs in the project worktree")

#: Kinds that need NOT carry delegation and why. The reason is part of the test:
#: an unexplained exception is indistinguishable from the omitted kind in finding 55.
EXCLUDED = {
    31000: "delegation event: owner-signed and cannot itself carry the tag",
    31007: "delegation revocation: signed directly by the owner",
    31021: "identity attestation: signed by the ISSUER (KYC provider), not the agent; "
           "the issuer neither has nor should have a mandate from our owner",
    10002: "NIP-65 standard relay list: our tag would break compatibility with "
           "third-party relays",
    1059: "gift wrap: signed by an EPHEMERAL key and cannot carry delegation",
    13: "seal inside a gift wrap: never published separately to a relay",
    14: "rumor inside a gift wrap: never published to a relay at all",
}


def _required_kinds() -> set[int]:
    text = CONFIG.read_text(encoding="utf-8")
    m = re.search(r"^required_for_kinds\s*=\s*\[([^\]]*)\]", text, re.M)
    assert m, "required_for_kinds not found in config.prod.toml"
    return {int(x) for x in re.findall(r"\d+", m.group(1))}


def _registry_kinds() -> set[int]:
    return {v for n, v in vars(types).items()
            if n.startswith("KIND_") and isinstance(v, int)}


def test_every_kind_is_either_enforced_or_explicitly_excluded():
    missing = sorted(_registry_kinds() - _required_kinds() - set(EXCLUDED))
    assert not missing, (
        f"kinds {missing} neither require delegation nor have an explicit exception. "
        f"Any key can therefore publish them without a mandate, despite no decision "
        f"authorizing that. Add them to required_for_kinds or EXCLUDED with a reason")


def test_exclusions_do_not_silently_disable_enforcement():
    """Simultaneous exception and enforcement means one side was updated alone."""
    both = sorted(_required_kinds() & set(EXCLUDED))
    assert not both, f"kinds {both} are both enforced and declared exempt"


def test_enforcement_list_does_not_invent_kinds():
    phantom = sorted(_required_kinds() - _registry_kinds())
    assert not phantom, (
        f"required_for_kinds contains kinds absent from the registry: {phantom}")


def test_there_is_something_to_compare():
    """Empty sets would pass the checks above if parsing silently stopped working."""
    assert len(_required_kinds()) >= 10, "enforcement list was not parsed"
    assert len(_registry_kinds()) >= 20, "kind registry was not found"


def test_every_exclusion_carries_a_reason():
    empty = sorted(k for k, why in EXCLUDED.items() if len(why.strip()) < 20)
    assert not empty, f"exceptions without a meaningful reason: {empty}"
