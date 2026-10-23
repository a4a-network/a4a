"""Reputation must validate raw event inputs and preserve agreement aliases."""
import pytest

from a4a import Agent, Keys, crypto, types
from a4a.event import Event
from a4a.reputation import (agreement_parties, compute_completion_reputation,
                            compute_delivery_reputation, compute_reputation)
from tests.fake_relay import FakeRelay

NOW = 1_900_000_000


def _agreement(a, b):
    deal = types.Agreement(intent_id='1' * 64, offer_id='2' * 64, price=1,
        currency='USD', deadline=1_700_000_000, agent_a=a.pubkey_hex,
        agent_b=b.pubkey_hex, sig_a='', sig_b='')
    deal.sig_a = crypto.sign(deal.digest(), a.privkey_hex)
    deal.sig_b = crypto.sign(deal.digest(), b.privkey_hex)
    return deal.to_event(publisher=a.pubkey_hex).sign(a)


@pytest.mark.parametrize('invalid', ['wrong_kind', 'signature'])
@pytest.mark.parametrize('strict', [False, True])
def test_review_calculator_rejects_unverified_or_wrong_kind_events(invalid, strict):
    author, subject = Keys(), Keys()
    agreement = _agreement(author, subject)
    good = Event(kind=types.KIND_REVIEW, created_at=NOW,
        tags=[['rating', '5'], ['p', subject.pubkey_hex], ['agreement', agreement.id]],
        content='review').sign(author)
    bad = good.model_copy(deep=True)
    if invalid == 'wrong_kind':
        bad.kind = 1
        bad.sign(author)
    else:
        bad.content = 'changed without signing'
    args = {'now': NOW, 'subject': subject.pubkey_hex}
    if strict:
        args['agreements'] = [agreement]
    assert compute_reputation([bad], **args).total_reviews == 0
    assert compute_reputation([good], **args).total_reviews == 1


def test_agreement_calculators_reject_invalid_outer_signature():
    a, b = Keys(), Keys()
    good = _agreement(a, b)
    bad = good.model_copy(update={'content': 'changed without signing'})
    assert types.Agreement.from_event(bad).verify_signatures()
    assert not bad.verify()
    assert agreement_parties([bad]) == {}
    assert good.id in agreement_parties([good])
    assert compute_completion_reputation([bad], [], agent=b.pubkey_hex, now=NOW).total_deals == 0
    assert compute_completion_reputation([good], [], agent=b.pubkey_hex, now=NOW).total_deals == 1


@pytest.mark.parametrize('extra', [[], ['e']])
def test_completion_accepts_valid_reference_alongside_empty_or_short_tag(extra):
    a, b = Keys(), Keys()
    agreement = _agreement(a, b)
    result = Event(kind=types.KIND_TASK_RESULT,
        tags=[extra, ['e', agreement.id]], content='completed').sign(b)
    rep = compute_completion_reputation([agreement], [result], agent=b.pubkey_hex, now=NOW)
    assert (rep.total_deals, rep.completed) == (1, 1)


@pytest.mark.parametrize('reverse', [False, True])
def test_completion_result_can_reference_any_complete_agreement_alias(reverse):
    a, b = Keys(), Keys()
    first, second = _agreement(a, b), _agreement(a, b)
    assert first.id != second.id
    assert types.Agreement.from_event(first).digest() == types.Agreement.from_event(second).digest()
    result = Event(kind=types.KIND_TASK_RESULT,
        tags=[['e', second.id]], content='completed').sign(b)
    agreements = [second, first] if reverse else [first, second]
    rep = compute_completion_reputation(agreements, [result], agent=b.pubkey_hex, now=NOW)
    assert (rep.total_deals, rep.completed, rep.score) == (1, 1, 1.0)


def test_delivery_calculator_rejects_wrong_kind_with_delivery_shaped_tags():
    sender, recipient = Keys(), Keys()
    tags = [['p', recipient.pubkey_hex], ['d', 'fixture']]
    bad = Event(kind=types.KIND_TASK_RESULT, tags=tags).sign(sender)
    good = Event(kind=types.KIND_PRIVATE_MESSAGE, tags=tags).sign(sender)
    assert compute_delivery_reputation([bad], [], agent=recipient.pubkey_hex).total_deliveries == 0
    assert compute_delivery_reputation([good], [], agent=recipient.pubkey_hex).total_deliveries == 1


async def test_agent_completion_reader_handles_empty_and_short_result_tags():
    a, b = Keys(), Keys()
    agreement = _agreement(a, b)
    result = Event(kind=types.KIND_TASK_RESULT,
        tags=[[], ['e'], ['e', agreement.id]], content='completed').sign(b)
    async with FakeRelay() as relay:
        async with Agent([relay.url], a) as publisher:
            await publisher.relay.publish(agreement)
            await publisher.relay.publish(result)
        async with Agent([relay.url], Keys()) as observer:
            rep = await observer.get_completion_reputation(b.pubkey_hex)
    assert (rep.total_deals, rep.completed) == (1, 1)
