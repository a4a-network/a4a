// Minimal Node.js A4A client written ONLY from the specification:
//   a4a-master-spec.md (sections 6.1 and 8.1-8.5) and
//   docs/spec/a4a-protocol-v0.4.md (sections 1, 1.1, and 1.2).
// The Python SDK and relay source were not consulted. The experiment is designed to
// expose places where the specification cannot guide an independent client to a deal.
'use strict';

const { schnorr } = require('@noble/curves/secp256k1.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { bytesToHex, hexToBytes, utf8ToBytes } = require('@noble/hashes/utils.js');
const WebSocket = require('ws');
const crypto = require('crypto');

// --- Keys ------------------------------------------------------------------------------

// Recover a public key from a stored secret. A counterparty address must survive a
// restart or the second command will come from a different agent.
function pubkeyOf(secretHex) {
  return bytesToHex(schnorr.getPublicKey(hexToBytes(secretHex)));
}

function newKeys() {
  const sk = schnorr.utils.randomSecretKey();
  return { sk, pk: bytesToHex(schnorr.getPublicKey(sk)) };
}

// --- Event (master specification section 6.1) ----------------------------------
// id = sha256(serialize([0, pubkey, created_at, kind, tags, content]))
// sig is a Schnorr signature by pubkey over id.

function eventId(ev) {
  const serialized = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

function signEvent(ev, keys) {
  const full = { ...ev, pubkey: keys.pk, created_at: ev.created_at ?? Math.floor(Date.now() / 1000) };
  full.id = eventId(full);
  full.sig = bytesToHex(schnorr.sign(hexToBytes(full.id), keys.sk));
  return full;
}

// --- Agreement digest (v0.4 section 1.1) ----------------------------------------------
// canonical = ["a4a-agreement-v2", intent_id, offer_id, price, currency, deadline,
//              agent_a, agent_b]
// price is a string, deadline is a number, and separators contain no spaces.
// digest = sha256(sha256(tag) || sha256(tag) || canonical), tag = "a4a/agreement/v2".

const AGREEMENT_TAG = 'a4a/agreement/v2';

function taggedHash(tag, message) {
  const h = sha256(utf8ToBytes(tag));
  return sha256(new Uint8Array([...h, ...h, ...message]));
}

const AGREEMENT_ESCAPES = {
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r',
};

function agreementString(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field}: expected a primitive string`);
  // Match UTF-16 code units, including both halves of pairs and isolated surrogates.
  return '"' + value.replace(/["\\\x00-\x1f\x7f-\uffff]/g, (ch) =>
    AGREEMENT_ESCAPES[ch] || `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`) + '"';
}

function agreementCanonical({ intentId, offerId, price, currency, deadline, agentA, agentB }) {
  return '[' + [
    agreementString('a4a-agreement-v2', 'version'),
    agreementString(intentId, 'intentId'), agreementString(offerId, 'offerId'),
    agreementString(uint(price, 'price'), 'price'), agreementString(currency, 'currency'),
    uint(deadline, 'deadline'),
    agreementString(agentA, 'agentA'), agreementString(agentB, 'agentB'),
  ].join(',') + ']';
}

function agreementDigest(terms) {
  return bytesToHex(taggedHash(AGREEMENT_TAG, utf8ToBytes(agreementCanonical(terms))));
}

function signDigest(digestHex, keys) {
  // Section 1.1 signs the 32 digest BYTES, not their hexadecimal representation.
  return bytesToHex(schnorr.sign(hexToBytes(digestHex), keys.sk));
}

function verifyDigest(sigHex, digestHex, pubkeyHex) {
  return schnorr.verify(hexToBytes(sigHex), hexToBytes(digestHex), hexToBytes(pubkeyHex));
}

// --- Canonical numbers (section 1.1, rule 7) -------------------------------------------

const CANONICAL_UINT = /^(0|[1-9][0-9]{0,18})$/;

function uint(value, field) {
  if (!['string', 'bigint', 'number'].includes(typeof value)) {
    throw new TypeError(`${field}: expected a decimal string, BigInt or safe Number`);
  }
  if (typeof value === 'number' &&
      (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0))) {
    throw new RangeError(`${field}: expected a nonnegative safe integer (not negative zero)`);
  }
  const s = String(value);
  if (!CANONICAL_UINT.test(s)) throw new Error(`${field}: non-canonical number ${s}`);
  return s;
}

// --- Relay connection (section 1.1.1: OK / CLOSED / NOTICE) ------------------

class Relay {
  constructor(url) { this.url = url; this.pending = new Map(); this.subs = new Map(); }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on('open', resolve);
      this.ws.on('error', reject);
      this.ws.on('message', (raw) => this._onMessage(JSON.parse(raw.toString())));
    });
  }

  _onMessage(msg) {
    const [type] = msg;
    if (type === 'OK') {
      const waiter = this.pending.get(msg[1]);
      if (waiter) { this.pending.delete(msg[1]); waiter.resolve({ ok: msg[2], reason: msg[3] || '' }); }
    } else if (type === 'EVENT') {
      const sub = this.subs.get(msg[1]);
      if (sub) sub.events.push(msg[2]);
    } else if (type === 'EOSE') {
      const sub = this.subs.get(msg[1]);
      if (sub) { this.subs.delete(msg[1]); sub.resolve(sub.events); }
    } else if (type === 'CLOSED') {
      // Section 1.1.1: CLOSED is never followed by EOSE; waiting only for EOSE hangs.
      const sub = this.subs.get(msg[1]);
      if (sub) { this.subs.delete(msg[1]); sub.reject(new Error(`subscription rejected: ${msg[2]}`)); }
    } else if (type === 'NOTICE') {
      console.log(`  [NOTICE] ${msg[1]}`);
    }
  }

  publish(ev) {
    return new Promise((resolve, reject) => {
      this.pending.set(ev.id, { resolve, reject });
      this.ws.send(JSON.stringify(['EVENT', ev]));
      setTimeout(() => {
        if (this.pending.delete(ev.id)) reject(new Error('relay did not return OK within 10s'));
      }, 10000);
    });
  }

  query(filter) {
    const sid = crypto.randomBytes(8).toString('hex');
    return new Promise((resolve, reject) => {
      this.subs.set(sid, { events: [], resolve, reject });
      this.ws.send(JSON.stringify(['REQ', sid, filter]));
      setTimeout(() => {
        if (this.subs.delete(sid)) reject(new Error('no EOSE within 10s'));
      }, 10000);
    });
  }

  close() { this.ws.close(); }
}

// --- A4A events (master specification section 8) ---------------------------------------

const uuid = () => crypto.randomBytes(16).toString('hex');

function delegation(ownerKeys, agentPubkey, name, expiration) {
  // Section 1.2: `d` is mandatory and must equal `delegate`.
  return signEvent({
    kind: 31000,
    tags: [
      ['d', agentPubkey],
      ['delegate', agentPubkey],
      ['owner', ownerKeys.pk],
      ['name', name],
      ['expiration', uint(expiration, 'expiration')],
    ],
    content: 'Delegate discovery and deal authority to the agent',
  }, ownerKeys);
}

function intent(agentKeys, delegationId, o) {
  // Section 8.3: expiration = deadline + 30 days; it does not carry tag history.
  return signEvent({
    kind: 31002,
    tags: [
      ['intent_type', o.type], ['category', o.category], ['need', o.need],
      ['budget_min', uint(o.budgetMin, 'budget_min')],
      ['budget_max', uint(o.budgetMax, 'budget_max')],
      ['currency', o.currency],
      ['deadline', uint(o.deadline, 'deadline')],
      ['language', 'ru'],
      ['t', `a4a:cat:${o.category}`], ['t', `a4a:type:${o.type}`], ['t', 'a4a:lang:ru'],
      ['delegation', delegationId],
      ['expiration', uint(o.deadline + 30 * 86400, 'expiration')],
      ['d', uuid()],
    ],
    content: o.text ?? '',
  }, agentKeys);
}

function offer(agentKeys, delegationId, o) {
  return signEvent({
    kind: 31003,
    tags: [
      ['intent', o.intentId], ['e', o.intentId],
      ['price', uint(o.price, 'price'), o.currency],
      ['eta', uint(o.eta, 'eta')],
      ['delegation', delegationId],
      ['expiration', uint(Math.floor(Date.now() / 1000) + 90 * 86400, 'expiration')],
      ['d', uuid()],
    ],
    content: o.text ?? '',
  }, agentKeys);
}

function agreement(publisherKeys, delegationId, o) {
  // v0.4 sections 1.1 and 1.2: sig_a and sig_b are ALWAYS present, with an empty
  // string for a missing signature. status=agreed appears even in a half-signed event;
  // delegation_a and delegation_b identify the parties' mandates.
  return signEvent({
    kind: 31004,
    tags: [
      ['intent', o.intentId], ['offer', o.offerId],
      ['price', uint(o.price, 'price'), o.currency],
      ['deadline', uint(o.deadline, 'deadline')],
      ['agent_a', o.agentA], ['agent_b', o.agentB],
      ['p', o.agentA], ['p', o.agentB],
      ['sig_a', o.sigA ?? ''], ['sig_b', o.sigB ?? ''],
      ['status', 'agreed'],
      ['delegation', delegationId],
      ['delegation_a', o.delegationA], ['delegation_b', o.delegationB],
      ['d', uuid()],
    ],
    content: 'Agreement terms recorded',
  }, publisherKeys);
}

const tagValue = (ev, name) => (ev.tags.find((t) => t[0] === name) || [])[1];
const tagFull = (ev, name) => ev.tags.find((t) => t[0] === name);

module.exports = {
  newKeys, pubkeyOf, eventId, signEvent, agreementCanonical, agreementDigest, signDigest, verifyDigest,
  Relay, delegation, intent, offer, agreement, tagValue, tagFull, uint, AGREEMENT_TAG,
  taggedHash, bytesToHex, sha256, utf8ToBytes,
};
