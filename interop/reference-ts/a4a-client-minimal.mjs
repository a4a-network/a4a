/**
 * A4A v0.4 Minimal Reference Implementation (JavaScript / TypeScript ESM)
 * Zero external dependencies on Node.js 20+ (uses standard BigInt secp256k1 + node:crypto).
 *
 * Implements:
 * 1. secp256k1 x-only keys, BIP-340 Schnorr sign/verify, ECDH raw x-coordinate
 * 2. Bech32 (apub / asec) encoding and decoding + universal parseA4AContact()
 * 3. Canonical A4A / Nostr Event ID (SHA-256) and signature verification
 * 4. A4A E2EE v2 encryption & decryption (HKDF-SHA256 + power-of-two padding + ChaCha20 + HMAC-SHA256)
 * 5. A4A Gift Wrap (signed kind 14 PrivateRumor -> kind 13 Seal -> kind 1059 GiftWrap)
 * 6. A4A Delegation Mandate (kind 31000), AgentProfile (kind 31001), RelayList (kind 10002), AckReceipt (kind 31034)
 * 7. Encrypted file blobs (a4a-chacha20poly1305-v1 AEAD) + NIP-98 HTTP Auth (kind 27235)
 */
import crypto from "node:crypto";

export const DEFAULT_RELAYS = [
  "wss://eu1.a4a.network",
  "wss://us1.a4a.network",
  "wss://sg1.a4a.network",
  "wss://kz1.a4a.network",
  "wss://ru1.a4a.network",
  "wss://ru2.a4a.network",
];

export const KIND_SEAL = 13;
export const KIND_PRIVATE_RUMOR = 14;
export const KIND_GIFT_WRAP = 1059;
export const KIND_RELAY_LIST = 10002;
export const KIND_HTTP_AUTH = 27235;
export const KIND_DELEGATION = 31000;
export const KIND_AGENT_PROFILE = 31001;
export const KIND_ACK_RECEIPT = 31034;

export const FILE_ENC_SCHEME = "a4a-chacha20poly1305-v1";

// --- 1. secp256k1 & BIP-340 Schnorr (Pure BigInt) -------------------------

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G = { x: GX, y: GY };

function mod(a, m = P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m = P) {
  let res = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return res;
}

function modInv(a, m = P) {
  return modPow(a, m - 2n, m);
}

function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === p2.x) {
    if (p1.y !== p2.y || p1.y === 0n) return null;
    const lam = mod(3n * p1.x * p1.x * modInv(2n * p1.y));
    const x3 = mod(lam * lam - 2n * p1.x);
    return { x: x3, y: mod(lam * (p1.x - x3) - p1.y) };
  }
  const lam = mod((p2.y - p1.y) * modInv(p2.x - p1.x));
  const x3 = mod(lam * lam - p1.x - p2.x);
  return { x: x3, y: mod(lam * (p1.x - x3) - p1.y) };
}

function pointMul(pt, scalar) {
  let k = mod(scalar, N);
  if (k === 0n || !pt) return null;
  let res = null;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) res = pointAdd(res, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return res;
}

function liftXEven(xHexOrBig) {
  const x = typeof xHexOrBig === "bigint" ? xHexOrBig : BigInt("0x" + xHexOrBig);
  if (x <= 0n || x >= P) throw new Error("invalid x coordinate");
  const c = mod(modPow(x, 3n) + 7n);
  const y = modPow(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) throw new Error("point not on secp256k1 curve");
  return { x, y: (y & 1n) === 0n ? y : P - y };
}

function numTo32Hex(n) {
  return n.toString(16).padStart(64, "0");
}

function taggedHash(tag, ...buffers) {
  const tagHash = crypto.createHash("sha256").update(tag, "utf8").digest();
  const h = crypto.createHash("sha256").update(tagHash).update(tagHash);
  for (const b of buffers) h.update(b);
  return h.digest();
}

export function getPublicKeyHex(privkeyHex) {
  const d0 = BigInt("0x" + privkeyHex);
  if (d0 <= 0n || d0 >= N) throw new Error("invalid private key");
  const pt = pointMul(G, d0);
  return numTo32Hex(pt.x);
}

export function schnorrSign(msgHashHex, privkeyHex, auxRandHex = null) {
  const d0 = BigInt("0x" + privkeyHex);
  if (d0 <= 0n || d0 >= N) throw new Error("invalid private key");
  const Ppt = pointMul(G, d0);
  const d = (Ppt.y & 1n) === 0n ? d0 : N - d0;
  const pxBuf = Buffer.from(numTo32Hex(Ppt.x), "hex");
  const dBuf = Buffer.from(numTo32Hex(d), "hex");
  const mBuf = Buffer.from(msgHashHex, "hex");
  const aBuf = auxRandHex ? Buffer.from(auxRandHex, "hex") : crypto.randomBytes(32);
  const tHash = taggedHash("BIP0340/aux", aBuf);
  const tBuf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) tBuf[i] = dBuf[i] ^ tHash[i];
  const rand = taggedHash("BIP0340/nonce", tBuf, pxBuf, mBuf);
  const k0 = BigInt("0x" + rand.toString("hex")) % N;
  if (k0 === 0n) throw new Error("nonce k0 is zero");
  const R = pointMul(G, k0);
  const k = (R.y & 1n) === 0n ? k0 : N - k0;
  const rxBuf = Buffer.from(numTo32Hex(R.x), "hex");
  const eHash = taggedHash("BIP0340/challenge", rxBuf, pxBuf, mBuf);
  const e = BigInt("0x" + eHash.toString("hex")) % N;
  const s = (k + e * d) % N;
  return numTo32Hex(R.x) + numTo32Hex(s);
}

export function schnorrVerify(msgHashHex, pubkeyHex, sigHex) {
  try {
    if (!/^[0-9a-f]{64}$/.test(pubkeyHex) || !/^[0-9a-f]{128}$/.test(sigHex)) return false;
    const Ppt = liftXEven(pubkeyHex);
    const r = BigInt("0x" + sigHex.slice(0, 64));
    const s = BigInt("0x" + sigHex.slice(64, 128));
    if (r >= P || s >= N) return false;
    const rxBuf = Buffer.from(sigHex.slice(0, 64), "hex");
    const pxBuf = Buffer.from(pubkeyHex, "hex");
    const mBuf = Buffer.from(msgHashHex, "hex");
    const eHash = taggedHash("BIP0340/challenge", rxBuf, pxBuf, mBuf);
    const e = BigInt("0x" + eHash.toString("hex")) % N;
    const sG = pointMul(G, s);
    const eP = pointMul({ x: Ppt.x, y: P - Ppt.y }, e);
    const R = pointAdd(sG, eP);
    if (!R || (R.y & 1n) !== 0n || R.x !== r) return false;
    return true;
  } catch {
    return false;
  }
}

// --- 2. Bech32 (apub / asec) & Contact Parser -----------------------------

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) throw new Error("invalid bit value");
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error("invalid bech32 padding");
  }
  return ret;
}

export function encodeBech32(hrp, hexData) {
  const bytes = Buffer.from(hexData, "hex");
  const data5 = convertBits(bytes, 8, 5, true);
  const values = bech32HrpExpand(hrp).concat(data5);
  const polymod = bech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  return hrp + "1" + data5.concat(checksum).map((d) => BECH32_CHARSET[d]).join("");
}

export function decodeBech32(str) {
  const s = String(str).toLowerCase();
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length) throw new Error("invalid bech32 string");
  const hrp = s.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < s.length; i++) {
    const d = BECH32_CHARSET.indexOf(s[i]);
    if (d === -1) throw new Error("invalid bech32 character");
    data.push(d);
  }
  if (bech32Polymod(bech32HrpExpand(hrp).concat(data)) !== 1) {
    throw new Error("invalid bech32 checksum");
  }
  const bytes = Buffer.from(convertBits(data.slice(0, -6), 5, 8, false));
  return { prefix: hrp, hex: bytes.toString("hex"), bytes };
}

export function generateKeys(privkeyHex = null) {
  const priv = (privkeyHex || crypto.randomBytes(32).toString("hex")).toLowerCase();
  const pub = getPublicKeyHex(priv);
  return {
    privkey_hex: priv,
    pubkey_hex: pub,
    asec: encodeBech32("asec", priv),
    apub: encodeBech32("apub", pub),
  };
}

export function keysFromAsec(asec) {
  const { prefix, hex } = decodeBech32(asec);
  if (prefix !== "asec" || hex.length !== 64) throw new Error("expected 32-byte asec");
  return generateKeys(hex);
}

export function parseA4AContact(input, defaultRelays = DEFAULT_RELAYS) {
  const raw = String(input || "").trim();
  const m = raw.match(/\b(apub1[023456789acdefghjklmnpqrstuvwxyz]{58})\b/i);
  if (!m) return null;
  const apub = m[1].toLowerCase();
  const { prefix, hex } = decodeBech32(apub);
  if (prefix !== "apub" || hex.length !== 64) return null;
  const foundRelays = raw.match(/wss?:\/\/[^\s,;"'>)]+/gi) || [];
  const uniqueRelays = [...new Set(foundRelays)];
  return {
    apub,
    pubkey_hex: hex,
    relays: uniqueRelays.length ? uniqueRelays : [...defaultRelays],
  };
}

// --- 3. Event Serialization, Signing & Protocol Validation ----------------

export function computeEventId(ev) {
  const canonical = JSON.stringify([
    0,
    ev.pubkey,
    ev.created_at,
    ev.kind,
    ev.tags,
    ev.content,
  ]);
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

export function signEvent(unsignedEvent, privkeyHex) {
  const pubkey = getPublicKeyHex(privkeyHex);
  const ev = {
    kind: unsignedEvent.kind,
    pubkey,
    created_at: unsignedEvent.created_at ?? Math.floor(Date.now() / 1000),
    tags: unsignedEvent.tags || [],
    content: unsignedEvent.content ?? "",
  };
  const id = computeEventId(ev);
  const sig = schnorrSign(id, privkeyHex);
  return { ...ev, id, sig };
}

export function verifyEvent(ev) {
  if (!ev || typeof ev !== "object") return false;
  if (computeEventId(ev) !== ev.id) return false;
  return schnorrVerify(ev.id, ev.pubkey, ev.sig);
}

export function validateDelegation(event, mandate, now = null) {
  if (!verifyEvent(event) || !verifyEvent(mandate)) return false;
  if (mandate.kind !== KIND_DELEGATION) return false;
  const dTag = mandate.tags.find((t) => t[0] === "d")?.[1];
  const delTag = mandate.tags.find((t) => t[0] === "delegate")?.[1];
  const expTag = mandate.tags.find((t) => t[0] === "expiration")?.[1];
  if (!dTag || dTag !== delTag || delTag !== event.pubkey) return false;
  if (!expTag) return false;
  const exp = Number(expTag);
  const checkTime = now ?? event.created_at;
  if (!Number.isFinite(exp) || exp <= checkTime) return false;
  const evDelId = event.tags.find((t) => t[0] === "delegation")?.[1];
  return evDelId === mandate.id;
}

// --- 4. A4A E2EE v2 Encryption & Decryption ---------------------------------

export function nip44ConversationKey(privkeyHex, pubkeyHex) {
  const priv = BigInt("0x" + privkeyHex);
  const pubPt = liftXEven(pubkeyHex);
  const sharedPt = pointMul(pubPt, priv);
  if (!sharedPt) throw new Error("ECDH failed");
  const sharedX = Buffer.from(numTo32Hex(sharedPt.x), "hex");
  return crypto.createHmac("sha256", Buffer.from("nip44-v2", "utf8")).update(sharedX).digest();
}

function hkdfExpand(prk, info, length) {
  const chunks = [];
  let t = Buffer.alloc(0);
  let counter = 1;
  let total = 0;
  while (total < length) {
    t = crypto
      .createHmac("sha256", prk)
      .update(Buffer.concat([t, info, Buffer.from([counter])]))
      .digest();
    chunks.push(t);
    total += t.length;
    counter++;
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function nip44MessageKeys(convKey, nonce32) {
  if (convKey.length !== 32 || nonce32.length !== 32) throw new Error("invalid key/nonce length");
  const okm = hkdfExpand(convKey, nonce32, 76);
  return {
    chachaKey: okm.subarray(0, 32),
    chachaNonce: okm.subarray(32, 44),
    hmacKey: okm.subarray(44, 76),
  };
}

function calcPaddedLen(unpaddedLen) {
  if (unpaddedLen <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(unpaddedLen - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower >> 3;
  return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1);
}

function nip44Pad(plaintext) {
  const raw = Buffer.from(plaintext, "utf8");
  if (raw.length < 1 || raw.length > 65535) throw new Error("invalid plaintext length");
  const paddedLen = calcPaddedLen(raw.length);
  const out = Buffer.alloc(2 + paddedLen, 0);
  out.writeUInt16BE(raw.length, 0);
  raw.copy(out, 2);
  return out;
}

function nip44Unpad(padded) {
  if (padded.length < 2) throw new Error("invalid padding");
  const unpaddedLen = padded.readUInt16BE(0);
  const unpadded = padded.subarray(2, 2 + unpaddedLen);
  if (
    unpaddedLen === 0 ||
    unpadded.length !== unpaddedLen ||
    padded.length !== 2 + calcPaddedLen(unpaddedLen)
  ) {
    throw new Error("invalid padding");
  }
  for (let i = 2 + unpaddedLen; i < padded.length; i++) {
    if (padded[i] !== 0) throw new Error("non-zero padding byte");
  }
  return unpadded.toString("utf8");
}

function chacha20Raw(key32, nonce12, data) {
  const iv16 = Buffer.concat([Buffer.alloc(4, 0), nonce12]);
  const cipher = crypto.createCipheriv("chacha20", key32, iv16);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function nip44Encrypt(plaintext, senderPrivkeyHex, recipientPubkeyHex, nonce32 = null) {
  const convKey = nip44ConversationKey(senderPrivkeyHex, recipientPubkeyHex);
  const nonce = nonce32 ? Buffer.from(nonce32) : crypto.randomBytes(32);
  const { chachaKey, chachaNonce, hmacKey } = nip44MessageKeys(convKey, nonce);
  const padded = nip44Pad(plaintext);
  const ciphertext = chacha20Raw(chachaKey, chachaNonce, padded);
  const mac = crypto
    .createHmac("sha256", hmacKey)
    .update(Buffer.concat([nonce, ciphertext]))
    .digest();
  return Buffer.concat([Buffer.from([0x02]), nonce, ciphertext, mac]).toString("base64");
}

export function nip44Decrypt(payloadB64, recipientPrivkeyHex, senderPubkeyHex) {
  if (!payloadB64 || payloadB64[0] === "#" || payloadB64.length < 132) {
    throw new Error("invalid NIP-44 payload");
  }
  const data = Buffer.from(payloadB64, "base64");
  if (data.length < 99 || data[0] !== 0x02) throw new Error("unsupported NIP-44 version");
  const nonce = data.subarray(1, 33);
  const ciphertext = data.subarray(33, data.length - 32);
  const mac = data.subarray(data.length - 32);
  const convKey = nip44ConversationKey(recipientPrivkeyHex, senderPubkeyHex);
  const { chachaKey, chachaNonce, hmacKey } = nip44MessageKeys(convKey, nonce);
  const expectedMac = crypto
    .createHmac("sha256", hmacKey)
    .update(Buffer.concat([nonce, ciphertext]))
    .digest();
  if (!crypto.timingSafeEqual(expectedMac, mac)) throw new Error("NIP-44 MAC mismatch");
  const padded = chacha20Raw(chachaKey, chachaNonce, ciphertext);
  return nip44Unpad(padded);
}

// --- 5. Gift Wrap (Signed kind 14 -> kind 13 -> kind 1059) ----------------

export function wrapEvent(innerSignedEvent, senderPrivkeyHex, recipientPubkeyHex, expiration) {
  if (!verifyEvent(innerSignedEvent)) {
    throw new Error("inner event must be signed and valid before gift-wrapping");
  }
  const senderPub = getPublicKeyHex(senderPrivkeyHex);
  if (innerSignedEvent.pubkey !== senderPub) {
    throw new Error("inner event pubkey must match sender key");
  }
  const now = Math.floor(Date.now() / 1000);
  const jitter = () => now - crypto.randomInt(0, 172801);
  const sealPlaintext = JSON.stringify(innerSignedEvent);
  const sealContent = nip44Encrypt(sealPlaintext, senderPrivkeyHex, recipientPubkeyHex);
  const seal = signEvent(
    {
      kind: KIND_SEAL,
      created_at: jitter(),
      tags: [],
      content: sealContent,
    },
    senderPrivkeyHex
  );

  const ephemeralPriv = crypto.randomBytes(32).toString("hex");
  const wrapContent = nip44Encrypt(JSON.stringify(seal), ephemeralPriv, recipientPubkeyHex);
  return signEvent(
    {
      kind: KIND_GIFT_WRAP,
      created_at: jitter(),
      tags: [
        ["p", recipientPubkeyHex],
        ["expiration", String(expiration)],
      ],
      content: wrapContent,
    },
    ephemeralPriv
  );
}

export function unwrapGiftWrap(outerEvent, recipientPrivkeyHex) {
  if (!outerEvent || outerEvent.kind !== KIND_GIFT_WRAP || !verifyEvent(outerEvent)) {
    throw new Error("invalid outer kind 1059 gift wrap");
  }
  const recipientPub = getPublicKeyHex(recipientPrivkeyHex);
  const pTags = outerEvent.tags.filter((t) => t[0] === "p").map((t) => t[1]);
  if (pTags.length !== 1 || pTags[0] !== recipientPub) {
    throw new Error("gift wrap p tag does not match recipient");
  }
  const sealJson = nip44Decrypt(outerEvent.content, recipientPrivkeyHex, outerEvent.pubkey);
  const seal = JSON.parse(sealJson);
  if (seal.kind !== KIND_SEAL || (seal.tags && seal.tags.length > 0) || !verifyEvent(seal)) {
    throw new Error("invalid kind 13 seal inside gift wrap");
  }
  const innerJson = nip44Decrypt(seal.content, recipientPrivkeyHex, seal.pubkey);
  const inner = JSON.parse(innerJson);
  if (inner.pubkey !== seal.pubkey || !verifyEvent(inner)) {
    throw new Error("inner rumor signature or pubkey mismatch");
  }
  if (inner.kind === KIND_PRIVATE_RUMOR) {
    const innerP = inner.tags.filter((t) => t[0] === "p").map((t) => t[1]);
    if (innerP.length !== 1 || innerP[0] !== recipientPub) {
      throw new Error("inner rumor p tag mismatch");
    }
  }
  return inner;
}

// --- 6.Encrypted File Blobs (a4a-chacha20poly1305-v1) ---------------------

export function encryptFileBlob(plaintextBytes, keyHex = null, nonce12Bytes = null) {
  const key = keyHex ? Buffer.from(keyHex, "hex") : crypto.randomBytes(32);
  const nonce = nonce12Bytes ? Buffer.from(nonce12Bytes) : crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(FILE_ENC_SCHEME, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([nonce, ct, tag]);
  const sha256 = crypto.createHash("sha256").update(blob).digest("hex");
  return { blob, sha256, keyHex: key.toString("hex"), enc: FILE_ENC_SCHEME };
}

export function openFileBlob(blobBytes, fileRef) {
  if (!fileRef || fileRef.enc !== FILE_ENC_SCHEME) {
    throw new Error("unsupported file encryption scheme");
  }
  const actualSha = crypto.createHash("sha256").update(blobBytes).digest("hex");
  if (actualSha !== fileRef.sha256.toLowerCase()) {
    throw new Error("encrypted file blob SHA-256 mismatch");
  }
  const buf = Buffer.from(blobBytes);
  if (buf.length < 28) throw new Error("encrypted blob too short");
  const nonce = buf.subarray(0, 12);
  const ct = buf.subarray(12, buf.length - 16);
  const tag = buf.subarray(buf.length - 16);
  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305",
    Buffer.from(fileRef.key, "hex"),
    nonce,
    { authTagLength: 16 }
  );
  decipher.setAAD(Buffer.from(FILE_ENC_SCHEME, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
