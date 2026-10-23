/**
 * Verify all 8 deterministic A4A v0.4 app & messenger test vector groups
 * using the zero-dependency JavaScript/TypeScript reference module.
 *
 * Run:
 *   node interop/reference-ts/verify-vectors.mjs
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  KIND_ACK_RECEIPT,
  KIND_PRIVATE_RUMOR,
  encryptFileBlob,
  generateKeys,
  keysFromAsec,
  nip44ConversationKey,
  nip44Decrypt,
  nip44Encrypt,
  openFileBlob,
  parseA4AContact,
  unwrapGiftWrap,
  validateDelegation,
  verifyEvent,
  wrapEvent,
} from "./a4a-client-minimal.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectorsPath = path.resolve(__dirname, "../test-vectors/app-messenger-v0.4.json");
const v = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));

// 1. Verify keys (secp256k1 + Bech32 apub/asec)
for (const [name, info] of Object.entries(v.keys)) {
  const k = generateKeys(info.privkey_hex);
  assert.equal(k.pubkey_hex, info.pubkey_hex, `${name} pubkey_hex mismatch`);
  assert.equal(k.asec, info.asec, `${name} asec mismatch`);
  assert.equal(k.apub, info.apub, `${name} apub mismatch`);
  assert.equal(keysFromAsec(info.asec).pubkey_hex, info.pubkey_hex, `${name} from_nsec mismatch`);
}

const aliceAgent = generateKeys(v.keys.alice_agent.privkey_hex);
const bobUser = generateKeys(v.keys.bob_user.privkey_hex);

// 2. Verify contact parser vectors
for (const item of v.contact_parser_vectors) {
  const parsed = parseA4AContact(item.input, v.production_relays);
  assert.deepEqual(parsed, item.expected, `contact parser mismatch for ${item.name}`);
}

// 3. Verify Delegation (kind 31000), AgentProfile (kind 31001), and RelayList (kind 10002)
assert.equal(verifyEvent(v.delegation_kind_31000), true, "mandate signature invalid");
assert.equal(verifyEvent(v.profile_kind_31001), true, "profile signature invalid");
assert.equal(
  validateDelegation(v.profile_kind_31001, v.delegation_kind_31000, v.profile_kind_31001.created_at),
  true,
  "delegation chain invalid"
);
assert.equal(verifyEvent(v.relay_list_kind_10002), true, "relay list signature invalid");

// 4. Verify A4A E2EE v2 direct vector
const n44 = v.nip44_v2_vector;
const convKey = nip44ConversationKey(aliceAgent.privkey_hex, bobUser.pubkey_hex);
assert.equal(convKey.toString("hex"), n44.conversation_key_hex, "NIP-44 conversation key mismatch");
const reEncrypted = nip44Encrypt(
  n44.plaintext,
  aliceAgent.privkey_hex,
  bobUser.pubkey_hex,
  Buffer.from(n44.nonce_hex, "hex")
);
assert.equal(reEncrypted, n44.payload_b64, "NIP-44 deterministic encryption mismatch");
const decrypted = nip44Decrypt(n44.payload_b64, bobUser.privkey_hex, aliceAgent.pubkey_hex);
assert.equal(decrypted, n44.plaintext, "NIP-44 decryption mismatch");

// 5. Verify Gift-Wrapped Private Message (signed kind 14 -> kind 13 -> kind 1059)
const gwm = v.giftwrap_message_vector;
const unwrappedInner = unwrapGiftWrap(gwm.giftwrap_kind_1059, bobUser.privkey_hex);
assert.deepEqual(unwrappedInner, gwm.inner_rumor_kind_14, "unwrapped kind 14 mismatch");

// Also verify round-trip wrapping in JS
const roundTripWrap = wrapEvent(
  gwm.inner_rumor_kind_14,
  aliceAgent.privkey_hex,
  bobUser.pubkey_hex,
  1763592000
);
const roundTripInner = unwrapGiftWrap(roundTripWrap, bobUser.privkey_hex);
assert.deepEqual(roundTripInner, gwm.inner_rumor_kind_14, "JS wrapEvent round-trip mismatch");

// 6. Verify ACKs (kind 31034 received & processed inside kind 1059)
for (const statusName of ["received", "processed"]) {
  const ackVec = v.ack_vectors[statusName];
  const ackInner = unwrapGiftWrap(ackVec.giftwrap_kind_1059, aliceAgent.privkey_hex);
  assert.equal(ackInner.kind, KIND_ACK_RECEIPT);
  assert.equal(ackInner.tags.find((t) => t[0] === "d")?.[1], gwm.delivery_id);
  assert.equal(ackInner.tags.find((t) => t[0] === "e")?.[1], unwrappedInner.id);
  assert.equal(ackInner.tags.find((t) => t[0] === "p")?.[1], aliceAgent.pubkey_hex);
  assert.equal(ackInner.tags.find((t) => t[0] === "status")?.[1], statusName);
}

// 7. Verify Bound Reply (kind 14 with a4a_conversation & a4a_reply)
const rep = v.bound_reply_vector;
const repInner = unwrapGiftWrap(rep.giftwrap_kind_1059, aliceAgent.privkey_hex);
assert.equal(repInner.kind, KIND_PRIVATE_RUMOR);
assert.equal(repInner.tags.find((t) => t[0] === "a4a_conversation")?.[1], gwm.conversation_id);
const replyTag = repInner.tags.find((t) => t[0] === "a4a_reply");
assert.deepEqual(replyTag, ["a4a_reply", gwm.delivery_id, unwrappedInner.id]);

// 8. Verify Encrypted File Attachment (a4a-chacha20poly1305-v1 + NIP-98)
const fv = v.file_attachment_vector;
const blobBuf = Buffer.from(fv.encrypted_blob_hex, "hex");
const parsedRef = JSON.parse(fv.message_content_json).a4a_file;
const openedBytes = openFileBlob(blobBuf, parsedRef);
assert.equal(openedBytes.toString("utf8"), fv.plaintext_utf8);
const reEncBlob = encryptFileBlob(
  Buffer.from(fv.plaintext_utf8, "utf8"),
  fv.key_hex,
  Buffer.from(fv.nonce_hex, "hex")
);
assert.equal(reEncBlob.blob.toString("hex"), fv.encrypted_blob_hex);
assert.equal(reEncBlob.sha256, fv.encrypted_blob_sha256);
for (const gw of [fv.gateway_upload, fv.gateway_fetch]) {
  assert.equal(gw.authorization_header.startsWith("Nostr "), true);
  const authEv = JSON.parse(Buffer.from(gw.authorization_header.slice(6), "base64").toString("utf8"));
  assert.equal(authEv.kind, 27235);
  assert.equal(verifyEvent(authEv), true);
}

console.log("ALL 8 A4A v0.4 TEST VECTOR GROUPS VERIFIED IN JAVASCRIPT/TYPESCRIPT (ZERO DEPENDENCIES).");
