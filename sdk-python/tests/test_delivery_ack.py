"""Delivery receipts (31034): what they prove and what they do not.

The economic perspective from review wave five asks not merely whether a receipt can be
forged, but what a decision-maker may safely infer from it.
"""


async def test_ack_from_a_stranger_is_not_proof_of_delivery():
    """A stranger can publish a receipt for the recipient, so filtering is mandatory.

    Reproduced on 2026-09-05: a stranger who knows an open message's `delivery_id`
    publishes a receipt that the node accepts (31034 requires a mandate, but no
    relationship to the delivery), and unfiltered `get_acks(did)` tells the sender it
    was delivered. The main `deliver_with_ack` path applies the filter itself; direct
    callers are exposed. This test proves BOTH that the forgery reaches the wire and
    that recipient filtering rejects it; without the latter half it proves nothing.
    """
    from a4a import Agent, Keys, types
    from a4a.event import Event
    from tests.fake_relay import FakeRelay

    sender, recipient, stranger = Keys(), Keys(), Keys()
    did = "delivery-probe"
    async with FakeRelay() as relay:
        async with Agent([relay.url], sender) as s:
            s.delegation_id = "d" * 64
            await s.send_private_message(recipient.pubkey_hex, "text",
                                         delivery_id=did, wrap=False)
            fake = Event(kind=types.KIND_ACK_RECEIPT, tags=[
                ["d", did], ["delivery", did], ["p", sender.pubkey_hex],
                ["status", "processed"], ["delegation", "d" * 64]],
                content="").sign(stranger)
            await s.relay.publish(fake)

            unfiltered = await s.get_acks(did)
            filtered = await s.get_acks(did, from_pubkey=recipient.pubkey_hex)
    assert len(unfiltered) == 1 and unfiltered[0]["acker_pubkey"] == stranger.pubkey_hex, \
        "the forgery did not reach the wire, so the test covers the wrong behavior"
    assert filtered == [], "recipient filtering admitted a stranger's receipt"
