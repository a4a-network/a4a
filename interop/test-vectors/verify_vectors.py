"""Verify deterministic A4A v0.4 app/messenger test vectors against sdk-python."""
from __future__ import annotations

import json
import re
from pathlib import Path

from a4a import delegation as dlg
from a4a import files, giftwrap, nip44, types
from a4a.event import Event
from a4a.keys import Keys

HERE = Path(__file__).resolve().parent
VECTORS_FILE = HERE / "app-messenger-v0.4.json"


def parse_a4a_contact(text: str, default_relays: list[str]) -> dict | None:
    raw = (text or "").strip()
    m = re.search(r"\b(apub1[023456789acdefghjklmnpqrstuvwxyz]{58})\b", raw, re.I)
    if not m:
        return None
    apub = m.group(1).lower()
    relays_found = re.findall(r"wss?://[^\s,;\"'>)]+", raw, re.I)
    seen = []
    for r in relays_found:
        if r not in seen:
            seen.append(r)
    return {
        "apub": apub,
        "pubkey_hex": Keys._decode_bech32(apub)[1].hex(),
        "relays": seen if seen else list(default_relays),
    }


def main() -> None:
    v = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    default_relays = v["production_relays"]

    # 1. Verify keys
    for name, info in v["keys"].items():
        k = Keys(info["privkey_hex"])
        assert k.pubkey_hex == info["pubkey_hex"], f"{name} pubkey_hex mismatch"
        assert k.asec == info["asec"], f"{name} asec mismatch"
        assert k.apub == info["apub"], f"{name} apub mismatch"
        assert Keys.from_asec(info["asec"]).pubkey_hex == info["pubkey_hex"]

    alice_agent = Keys(v["keys"]["alice_agent"]["privkey_hex"])
    bob_user = Keys(v["keys"]["bob_user"]["privkey_hex"])

    # 2. Verify contact parser vectors
    for item in v["contact_parser_vectors"]:
        parsed = parse_a4a_contact(item["input"], default_relays)
        assert parsed == item["expected"], f"contact parser mismatch for {item['name']}"

    # 3. Verify delegation (kind 31000) & profile (kind 31001) & relay list (kind 10002)
    mandate = Event(**v["delegation_kind_31000"])
    assert mandate.verify_protocol(), "mandate signature invalid"
    profile_ev = Event(**v["profile_kind_31001"])
    assert profile_ev.verify_protocol(), "profile signature invalid"
    assert dlg.validate_delegation(profile_ev, mandate, now=profile_ev.created_at), "delegation chain invalid"
    profile = types.AgentProfile.from_event(profile_ev)
    assert profile.category == "consulting"

    relay_list_ev = Event(**v["relay_list_kind_10002"])
    assert relay_list_ev.verify_protocol(), "relay list signature invalid"

    # 4. Verify NIP-44 v2 direct vector
    n44 = v["nip44_v2_vector"]
    conv_key = nip44._conversation_key(alice_agent.privkey_hex, bob_user.pubkey_hex)
    assert conv_key.hex() == n44["conversation_key_hex"]
    decrypted = nip44.decrypt(n44["payload_b64"], bob_user.privkey_hex, alice_agent.pubkey_hex)
    assert decrypted == n44["plaintext"]

    # 5. Verify Gift-Wrapped Private Message (kind 14 -> 13 -> 1059)
    gwm = v["giftwrap_message_vector"]
    gw_ev = Event(**gwm["giftwrap_kind_1059"])
    unwrapped_inner = giftwrap.unwrap(gw_ev, bob_user)
    assert unwrapped_inner.model_dump() == gwm["inner_rumor_kind_14"]
    assert unwrapped_inner.tag_value("d") == gwm["delivery_id"]
    assert unwrapped_inner.tag_value("a4a_conversation") == gwm["conversation_id"]
    assert unwrapped_inner.content == n44["plaintext"]

    # 6. Verify ACKs (kind 31034 inside kind 1059)
    for status_name in ("received", "processed"):
        ack_vec = v["ack_vectors"][status_name]
        ack_gw = Event(**ack_vec["giftwrap_kind_1059"])
        ack_inner = giftwrap.unwrap(ack_gw, alice_agent)
        assert ack_inner.kind == types.KIND_ACK_RECEIPT
        ack_model = types.AckReceipt.from_event(ack_inner)
        assert ack_model.delivery_id == gwm["delivery_id"]
        assert ack_model.acked_event_id == unwrapped_inner.id
        assert ack_model.to_pubkey == alice_agent.pubkey_hex
        assert ack_model.status == status_name

    # 7. Verify Bound Reply (kind 14 with a4a_reply)
    rep = v["bound_reply_vector"]
    rep_gw = Event(**rep["giftwrap_kind_1059"])
    rep_inner = giftwrap.unwrap(rep_gw, alice_agent)
    assert rep_inner.kind == types.KIND_PRIVATE_RUMOR
    assert rep_inner.tag_value("a4a_conversation") == gwm["conversation_id"]
    reply_tags = [t for t in rep_inner.tags if t and t[0] == "a4a_reply"]
    assert reply_tags == [["a4a_reply", gwm["delivery_id"], unwrapped_inner.id]]

    # 8. Verify File Attachment (ChaCha20-Poly1305 + reference)
    fv = v["file_attachment_vector"]
    blob = bytes.fromhex(fv["encrypted_blob_hex"])
    ref = files.parse_file_reference(fv["message_content_json"])
    assert ref is not None, "file reference failed validation"
    opened = files.open_file(blob, ref)
    assert opened.decode("utf-8") == fv["plaintext_utf8"]

    print("ALL 8 A4A v0.4 APP & MESSENGER TEST VECTOR GROUPS VERIFIED SUCCESSFULLY.")


if __name__ == "__main__":
    main()
