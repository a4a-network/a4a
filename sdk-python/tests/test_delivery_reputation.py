"""Internal audit 2026-08-29: anyone could reduce delivery reputation to zero.

The denominator included ALL messages addressed to an agent, and becoming a recipient
requires no consent. Any outsider could therefore spend fifty cheap events to lower
an honest reputation from 1.00 to 0.06, while the victim could not refuse delivery.

Unlike manipulation requiring a mutually signed deal, this attack gave the victim
no defensive leverage at all.
"""
import time

from a4a import types
from a4a.event import Event
from a4a.keys import Keys
from a4a.reputation import WOT_BASELINE, compute_delivery_reputation

NOW = int(time.time())


def _delivery(sender: Keys, to: str, did: str) -> Event:
    return Event(kind=types.KIND_PRIVATE_MESSAGE,
                 tags=[["p", to], ["d", did]], content="x",
                 created_at=NOW).sign(sender)


def _ack(agent: Keys, did: str, status: str = "processed") -> Event:
    return Event(kind=types.KIND_ACK_RECEIPT,
                 tags=[["d", did], ["status", status]], content="",
                 created_at=NOW).sign(agent)


def test_one_stranger_cannot_zero_out_a_reputation():
    """One noisy sender is bounded to its share of the denominator."""
    agent, honest, spammer = Keys(), Keys(), Keys()
    msgs = [_delivery(honest, agent.pubkey_hex, f"real{i}") for i in range(3)]
    acks = [_ack(agent, f"real{i}") for i in range(3)]
    msgs += [_delivery(spammer, agent.pubkey_hex, f"spam{i}") for i in range(50)]

    rep = compute_delivery_reputation(msgs, acks)
    assert rep.score > 0.4, (
        f"fifty messages from one stranger lowered score to {rep.score:.2f}")


def test_trusted_senders_only_when_a_graph_is_given():
    """With a trust graph, evaluators choose whose deliveries enter the denominator."""
    me, agent, honest, spammer = Keys(), Keys(), Keys(), Keys()
    graph = {me.pubkey_hex: {honest.pubkey_hex: 1.0}}
    msgs = [_delivery(honest, agent.pubkey_hex, f"real{i}") for i in range(3)]
    acks = [_ack(agent, f"real{i}") for i in range(3)]
    msgs += [_delivery(spammer, agent.pubkey_hex, f"spam{i}") for i in range(500)]

    rep = compute_delivery_reputation(msgs, acks, trust_graph=graph, me=me.pubkey_hex)
    assert rep.score == 1.0, f"stranger spam entered the denominator (score={rep.score:.2f})"
    assert rep.total_deliveries == 3


def test_unacknowledged_work_still_lowers_the_score():
    """Preserve the metric: ignoring addressed work must still lower the score."""
    agent, honest = Keys(), Keys()
    msgs = [_delivery(honest, agent.pubkey_hex, f"real{i}") for i in range(4)]
    acks = [_ack(agent, "real0")]
    rep = compute_delivery_reputation(msgs, acks)
    assert rep.score < 0.5, f"unacknowledged deliveries did not lower score ({rep.score:.2f})"


def test_baseline_stranger_is_excluded_with_graph():
    """WOT_BASELINE means "no path", not "slightly trusted"."""
    me, agent, stranger = Keys(), Keys(), Keys()
    msgs = [_delivery(stranger, agent.pubkey_hex, "s1")]
    rep = compute_delivery_reputation(msgs, [], trust_graph={me.pubkey_hex: {}},
                                      me=me.pubkey_hex)
    assert rep.total_deliveries == 0, \
        f"stranger with weight {WOT_BASELINE} entered the denominator"


def test_relay_cannot_inflate_with_someone_elses_acks():
    """Same class as review F3: ACKs arrive from an UNTRUSTED relay.

    A query for receipts issued by an agent may include somebody else's. The ACK
    author must match the evaluated agent or outsiders can fabricate its rating.
    """
    agent, honest, outsider = Keys(), Keys(), Keys()
    msgs = [_delivery(honest, agent.pubkey_hex, f"real{i}") for i in range(3)]
    acks = [_ack(outsider, f"real{i}") for i in range(3)]   # NOT signed by agent
    rep = compute_delivery_reputation(msgs, acks, agent=agent.pubkey_hex)
    assert rep.processed == 0, "another author's ACKs were credited to the agent"


def test_relay_cannot_pad_with_messages_addressed_to_others():
    """Conversely, messages addressed to OTHERS must not enter this denominator.

    Otherwise a relay can lower anyone's reputation.
    """
    agent, honest, other = Keys(), Keys(), Keys()
    msgs = [_delivery(honest, agent.pubkey_hex, "real0"),
            _delivery(honest, other.pubkey_hex, "foreign0")]
    acks = [_ack(agent, "real0")]
    rep = compute_delivery_reputation(msgs, acks, agent=agent.pubkey_hex)
    assert rep.total_deliveries == 1 and rep.score == 1.0, \
        f"another recipient's delivery entered the denominator ({rep.total_deliveries} total)"


def test_unsigned_events_are_not_counted():
    """The public function accepts events from arbitrary sources."""
    agent, honest = Keys(), Keys()
    forged = Event(kind=types.KIND_ACK_RECEIPT, pubkey=agent.pubkey_hex,
                   tags=[["d", "real0"], ["status", "processed"]], created_at=NOW)
    msgs = [_delivery(honest, agent.pubkey_hex, "real0")]
    rep = compute_delivery_reputation(msgs, [forged], agent=agent.pubkey_hex)
    assert rep.processed == 0, "unsigned ACK was counted"
