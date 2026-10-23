"""Verify that the relay rejects BAD signatures after a crypto-library change.

Every other check proves that valid signatures are accepted. That is only half the truth,
and exactly the half that remains green when verification breaks: if `verify_schnorr`
starts accepting everything, those checks still pass while the relay becomes vulnerable.

This check proves the inverse property: forgeries must be rejected.
"""
import asyncio
import io
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "sdk-python"))

from a4a import types                     # noqa: E402
from a4a.agent import Agent               # noqa: E402
from a4a.event import Event               # noqa: E402
from a4a.keys import Keys                 # noqa: E402
from a4a.relay import RelayError          # noqa: E402
from live_cleanup import sweep            # noqa: E402
from node_banner import node_line              # noqa: E402

# The relay address is REQUIRED. A localhost/production default caused a false alarm after
# the 2026-09-04 release because the script silently queried the wrong node, whose logs
# showed no connection.
def _relay_from_argv() -> str:
    if len(sys.argv) < 2 or not sys.argv[1].startswith(("ws://", "wss://")):
        sys.exit(f"usage: python {sys.argv[0]} ws://host:port|wss://host; relay address "
                 "is required and intentionally has no default")
    return sys.argv[1]

URL = _relay_from_argv()

# The report must name its node. Without this line, "verified" is indistinguishable from
# "verified elsewhere," which happened twice on 2026-09-04 and 2026-09-05.
print(node_line(URL))
# Use the system temp directory rather than a hard-coded path. The old absolute path
# exposed a developer account name and either failed or wrote into the wrong home on
# every other machine.
OUT = str(pathlib.Path(tempfile.gettempdir()) / "sig_reject.txt")


async def main() -> None:
    out = []
    keys, stranger, owner = Keys(), Keys(), Keys()
    async with Agent([URL], keys=keys) as agent:
        # Keep the owner key so cleanup can remove its mandate (kind 31000). Mandates do
        # not expire from relay history and an anonymous key would leave permanent debris.
        await agent.ensure_registered(owner, "signature probe", days=1)

        def fresh() -> Event:
            ev = types.Intent(
                intent_type="service_request", category="design", need="probe",
                budget_min=0, budget_max=1,
                deadline=int(time.time()) + 3600).to_event(agent.delegation_id)
            ev.sign(keys)
            return ev

        async def expect_reject(label, mutate):
            ev = fresh()
            mutate(ev)
            try:
                await agent.relay.publish(ev)
                out.append(f"ACCEPTED (VULNERABILITY): {label}")
            except RelayError as e:
                out.append(f"rejected: {label} - {str(e)[:80]}")

        def flip_sig(ev):
            # Change one signature character: syntax remains valid, value does not.
            c = "0" if ev.sig[10] != "0" else "1"
            ev.sig = ev.sig[:10] + c + ev.sig[11:]

        def foreign_sig(ev):
            other = Event(**ev.model_dump())
            other.content = "different content"
            other.sign(stranger)
            ev.sig = other.sig

        def wrong_author(ev):
            ev.pubkey = stranger.pubkey_hex

        await expect_reject("signature with one changed character", flip_sig)
        await expect_reject("signature from another key", foreign_sig)
        await expect_reject("author replaced with another key", wrong_author)

        # Positive control: an honest event must pass.
        ev = fresh()
        try:
            await agent.relay.publish(ev)
            out.append("control: honest event accepted")
        except RelayError as e:
            out.append(f"CONTROL FAILED: honest event rejected - {e}")

    # Remove test residue. Mandates and revocations do not expire from relay history and
    # would otherwise remain permanently (internal audit, 2026-09-05).
    await sweep(URL, [keys, stranger, owner])

    io.open(OUT, "w", encoding="utf-8").write("\n".join(out) + "\n")


asyncio.run(main())
