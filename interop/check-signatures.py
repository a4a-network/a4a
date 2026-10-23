"""Offline Python/JS signature exchange; no relay, real identities or optional skip."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def no_network(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "socket.sendmsg"}:
        raise RuntimeError("signature interoperability check forbids network")


def main():
    sys.addaudithook(no_network)
    from a4a import Keys, crypto, types

    root = Path(__file__).resolve().parent
    vectors = json.loads((root / "vectors/agreement-v2.json").read_text(encoding="ascii"))
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required for the cross-language release gate")
    # Public synthetic constants, never load an owner's A4A_HOME.
    first, second = Keys("01" * 32), Keys("02" * 32)
    requests, digests = [], []
    names = {"intentId": "intent_id", "offerId": "offer_id", "agentA": "agent_a", "agentB": "agent_b"}
    for vector in vectors["cases"]:
        wire = {**vector["terms"], "intentId": "11" * 32, "offerId": "22" * 32,
                "agentA": first.pubkey_hex, "agentB": second.pubkey_hex}
        terms = {names.get(k, k): int(v) if k in ("price", "deadline") else v for k, v in wire.items()}
        digest = types.agreement_digest(**terms)
        digests.append(digest)
        requests.append({"terms": wire, "pythonSignature": crypto.sign(digest, first.privkey_hex)})
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("A4A_") and k not in {"NODE_OPTIONS", "NODE_PATH"}}
    completed = subprocess.run([node, str(root / "check-signatures.js")],
        input=json.dumps(requests), text=True, encoding="utf-8", capture_output=True,
        env=env, cwd=root, timeout=30, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode:
        raise RuntimeError("JavaScript signature check failed:\n" + completed.stderr[-2000:])
    results = json.loads(completed.stdout)
    if len(results) != len(digests):
        raise RuntimeError("signature result count mismatch")
    for result, digest in zip(results, digests):
        if (set(result) != {"digest", "signature", "pubkey"} or result["digest"] != digest
                or result["pubkey"] != second.pubkey_hex
                or not crypto.verify(digest, result["signature"], second.pubkey_hex)
                or crypto.verify("00" * 32, result["signature"], second.pubkey_hex)):
            raise RuntimeError("JS signature or independently computed digest did not verify")
    print(f"{len(results)} agreement vectors: Python -> JS and JS -> Python signatures verified offline")


if __name__ == "__main__":
    main()
