"""Findings from a context-free external review of the public SDK slice (2026-09-04).

100: the writer emitted numbers longer than 19 digits that the reader (rule 7) rejected,
so an intent with a 23-digit budget_max was published and disappeared from search.
104: a forged signature in OUR slot was interpreted as "our signature is present."
107: the "mandate expired" hint was shown for the relay reason "names a different delegate."
"""
import pytest
from pydantic import ValidationError

from a4a import Agent, Keys, crypto, types
from a4a.agent import _safe_from_event
from a4a.relay import RelayError
from a4a.types import MAX_TAG_INT
from tests.fake_relay import FakeRelay


def test_writer_refuses_numbers_the_reader_cannot_parse():
    ok = types.Intent(intent_type="service_request", category="development", need="x",
                      budget_min=0, budget_max=MAX_TAG_INT, deadline=1)
    assert _safe_from_event(types.Intent, ok.to_event().sign(Keys())) is not None
    with pytest.raises(ValidationError):
        types.Intent(intent_type="service_request", category="development", need="x",
                     budget_min=0, budget_max=10 ** 23, deadline=1)
    with pytest.raises(ValidationError):
        types.Offer(intent_id="a" * 64, price=MAX_TAG_INT + 1, eta=1)
    assert MAX_TAG_INT == 10 ** 19 - 1 and len(str(MAX_TAG_INT)) == 19


async def test_forged_signature_in_our_slot_is_named_not_mistaken_for_ours():
    a, b, forger = Keys(), Keys(), Keys()
    terms = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=1, deadline=1,
                            agent_a=a.pubkey_hex, agent_b=b.pubkey_hex, sig_a="", sig_b="")
    digest = terms.digest()
    forged = terms.model_copy(update={"sig_a": crypto.sign(digest, a.privkey_hex),
                                      "sig_b": crypto.sign(digest, forger.privkey_hex)})
    async with FakeRelay() as relay:
        async with Agent([relay.url], b) as me:
            with pytest.raises(ValueError, match="signature in your slot is invalid"):
                await me.co_sign_agreement(forged)
            honest = terms.model_copy(update={"sig_a": crypto.sign(digest, a.privkey_hex)})
            me.delegation_id = "b" * 64
            new_id = await me.co_sign_agreement(honest, "a" * 64)  # control case
    assert len(new_id) == 64


@pytest.mark.parametrize("reason, expected, forbidden", [
    ("blocked: invalid or expired A4A delegation: delegation names a different delegate",
     "different key", "expired; issue"),
    ("blocked: invalid or expired A4A delegation: delegation revoked by its owner",
     "revoked the delegation", "expired; issue"),
    ("blocked: invalid or expired A4A delegation: delegation has expired or carries no expiration",
     "delegation expired", "different key"),
])
async def test_sdk_hint_follows_the_relay_reason_not_the_prefix(reason, expected, forbidden):
    async with FakeRelay(reject_reason=reason) as relay:
        async with Agent([relay.url]) as agent:
            with pytest.raises(RelayError) as info:
                await agent.request_connection("c" * 64)
    assert expected in str(info.value) and forbidden not in str(info.value)
