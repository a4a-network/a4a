"""A4A demo: private NIP-44 delivery of a meeting summary between agents.

This is the reference example for delivering confidential content through an agent
host platform. Its MCP tool (equivalent to `a4a_send_private`) would call
`Agent.send_private_message(to_pubkey, summary)`, while the recipient side calls
`Agent.read_private_messages()`.

Scenario: after a meeting with Bob and Victor, the organizer's agent (Alice) encrypts
the summary separately for each participant's agent and publishes each envelope to a
relay. The relay forwards the events but cannot read their content; only the intended
recipient can decrypt it. The participant agents read their private inboxes and
decrypt the summary. A third agent (Outsider), who did not attend the meeting, reads
its private inbox on the same relay and receives NOTHING because the messages address
only the participants (tag ["p", to_pubkey]).

Privacy qualification (see a4a/nip44.py and specification section 7a): NIP-44 hides
the CONTENT. Since 2026-08-29, messages are also gift-wrapped by default (NIP-59,
kind 1059) and signed with a disposable key, so the relay sees neither the sender nor
the exact time. The RECIPIENT is always visible because routing requires it; this is
not anonymous forwarding. Step 3 demonstrates both halves of this guarantee on a
live event.

Requires a local relay: run docker compose up -d from the repository root.
The public network relay is wss://eu1.a4a.network; this demo uses the local relay.

Run: .venv/Scripts/python examples/private-summary-delivery.py
"""
import asyncio
import sys

from a4a import Agent, Keys
from a4a.giftwrap import KIND_GIFT_WRAP

# A Windows console may use a legacy code page, so select UTF-8 output to make the
# demo work without PYTHONIOENCODING.
if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
    sys.stdout.reconfigure(encoding="utf-8")

RELAY = "ws://localhost:8080"

MEETING_SUMMARY = (
    "Q3 pipeline sync, 2026-07-17.\n"
    "Highlights:\n"
    "- Agreed ExampleCorp contract price: USD 480,000, starting 2026-08-01.\n"
    "- Risk: supplier requests 30% prepayment; Bob will check with Finance.\n"
    "Decisions:\n"
    "- Victor will prepare a contract draft by Friday.\n"
    "- Bob will approve the prepayment with the CFO by Wednesday.\n"
    "Tasks:\n"
    "- Bob -> CFO: confirm prepayment limit (Wednesday).\n"
    "- Victor -> prepare contract draft (Friday).\n"
)


def step(n: int, title: str) -> None:
    print(f"\n--- Step {n}: {title} ---")


async def main() -> None:
    print("=== A4A: private meeting-summary delivery demo ===")

    step(0, "Initialize agents (each has independent A4A keys)")
    organizer_keys, bob_keys, victor_keys = Keys(), Keys(), Keys()
    outsider_keys = Keys()

    async with Agent([RELAY], keys=organizer_keys) as organizer, \
               Agent([RELAY], keys=bob_keys) as bob, \
               Agent([RELAY], keys=victor_keys) as victor, \
               Agent([RELAY], keys=outsider_keys) as outsider:

        print(f"organizer (Alice): {organizer.pubkey[:16]}…")
        print(f"participant (Bob): {bob.pubkey[:16]}…")
        print(f"participant (Victor): {victor.pubkey[:16]}…")
        print(f"outsider: {outsider.pubkey[:16]}… (not a meeting participant)")

        step(1, "The organizer holds a confidential meeting summary")
        print(f"summary ({len(MEETING_SUMMARY)} characters):")
        print("    " + MEETING_SUMMARY.replace("\n", "\n    ").rstrip())

        step(2, "Encrypt and deliver the summary to each participant "
                "(NIP-44 inside a NIP-59 envelope)")
        bob_msg_id = await organizer.send_private_message(bob.pubkey, MEETING_SUMMARY)
        victor_msg_id = await organizer.send_private_message(victor.pubkey, MEETING_SUMMARY)
        print(f"sent to Bob: event {bob_msg_id[:16]}…")
        print(f"sent to Victor: event {victor_msg_id[:16]}…")

        step(3, "Verify that relay content is ciphertext, not plaintext")
        # Inspect the ENVELOPE (gift-wrap, kind 1059), not kind 31033.
        #
        # The demo used to search for an addressable message and fail with
        # StopIteration. Since 2026-08-29 private messages are gift-wrapped by default,
        # signed with a disposable key, and no 31033 event exists on the relay. The
        # public example remained broken because nobody ran it; an outsider-style
        # onboarding walkthrough found the defect on 2026-09-05.
        #
        # The returned ID cannot locate the envelope either: `send_private_message`
        # returns the INNER message ID known only to the sender and recipient, while
        # the relay stores an envelope with a different ID. Query by recipient instead;
        # with fresh demo keys, there is exactly one matching envelope.
        wire_events = await organizer.relay.query(
            {"kinds": [KIND_GIFT_WRAP], "#p": [bob.pubkey]})
        if not wire_events:
            sys.exit("Envelope not found; verify that the relay is running")
        raw_event = wire_events[0]
        assert MEETING_SUMMARY not in raw_event.content, \
            "privacy failure: plaintext is visible on the relay"
        print(f"raw relay content (base64 NIP-44): {raw_event.content[:60]}…")
        print("The plaintext summary is absent; the relay cannot read its content.")
        # The second half of the guarantee: the envelope does not reveal the sender.
        assert raw_event.pubkey != organizer.pubkey, \
            "the organizer signed the envelope directly, exposing the sender"
        print(f"relay event author: {raw_event.pubkey[:16]}…; this is the envelope's "
              f"disposable key, not the organizer ({organizer.pubkey[:16]}…).")

        step(4, "Bob reads and decrypts his private inbox")
        bob_inbox = await bob.read_private_messages()
        bob_received = next(
            (m for m in bob_inbox if m["from_pubkey"] == organizer.pubkey), None)
        if bob_received is None:
            sys.exit("Bob did not receive the summary; check the relay")
        assert bob_received["content"] == MEETING_SUMMARY
        print(f"Bob decrypted the summary from {bob_received['from_pubkey'][:16]}… "
              f"(matches the original, {len(bob_received['content'])} characters)")

        step(5, "Victor reads and decrypts his private inbox")
        victor_inbox = await victor.read_private_messages()
        victor_received = next(
            (m for m in victor_inbox if m["from_pubkey"] == organizer.pubkey), None)
        if victor_received is None:
            sys.exit("Victor did not receive the summary; check the relay")
        assert victor_received["content"] == MEETING_SUMMARY
        print(f"Victor decrypted the summary from {victor_received['from_pubkey'][:16]}… "
              f"(matches the original, {len(victor_received['content'])} characters)")

        step(6, "Privacy control: Outsider reads its private inbox")
        outsider_inbox = await outsider.read_private_messages()
        if outsider_inbox:
            sys.exit("Privacy failure: an outsider received another agent's message")
        print("Outsider's inbox is empty. The summary addresses only participants "
              "(tag [\"p\", to_pubkey]), so the relay did not expose it to anyone else.")

    print("\n✅ Summary delivered privately to all participants")


if __name__ == "__main__":
    asyncio.run(main())
