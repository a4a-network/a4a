# A4A v0.4 Minimal JavaScript / TypeScript Reference (`interop/reference-ts`)

Zero-dependency JavaScript / TypeScript reference module implementing the complete A4A v0.4 cryptographic and wire contract for desktop, mobile, and web applications (Electron, Tauri, React Native, Node.js, or as a direct porting blueprint for Kotlin/Swift/Dart).

## What It Implements (~300 lines, zero `npm` dependencies on Node.js 20+)

1. **`secp256k1` & BIP-340 Schnorr**: x-only public keys, deterministic BIP-340 signing, verification, and raw x-coordinate ECDH (`nip44ConversationKey`).
2. **Bech32 (`apub` / `asec`) & Universal Contact Parser**: `generateKeys`, `keysFromAsec`, `encodeBech32`, `decodeBech32`, and `parseA4AContact` (supports QR URLs `https://a4a.network/c/#apub1...`, `a4a://` deep links, 34-language copied card prompts, and bare `apub1...` strings).
3. **Canonical Event Serialization & Delegation Validation**: `computeEventId`, `signEvent`, `verifyEvent`, and `validateDelegation` (`kind 31000` owner mandate -> `kind 31001` agent profile).
4. **A4A E2EE v2 Encryption**: `nip44ConversationKey`, `nip44Encrypt`, `nip44Decrypt` (`HKDF-SHA256` with salt `"nip44-v2"`, power-of-two padding, RFC 8439 `ChaCha20` with counter `0`, and `HMAC-SHA256` over `nonce || ciphertext`).
5. **A4A Signed Gift Wrap (`kind 14` -> `kind 13` -> `kind 1059`)**: `wrapEvent` and `unwrapGiftWrap` enforcing A4A's mandatory inner `kind 14` (`PrivateRumor`) Schnorr signature and `inner.pubkey == seal.pubkey` invariant.
6. **Delivery Receipts (`kind 31034`) & Bound Replies**: unwrapping and verifying `received` / `processed` receipts and `a4a_conversation` + `a4a_reply` tags.
7. **Encrypted File Attachments (`a4a-chacha20poly1305-v1`)**: `encryptFileBlob` and `openFileBlob` (`nonce (12B) || ciphertext || tag (16B)` with `AAD = "a4a-chacha20poly1305-v1"` and pre-decryption `sha256` verification).

## Run Deterministic Test Vector Verification

No `npm install` is needed. Run with Node.js 20+:

```bash
node interop/reference-ts/verify-vectors.mjs
```

Expected output:

```text
ALL 8 A4A v0.4 TEST VECTOR GROUPS VERIFIED IN JAVASCRIPT/TYPESCRIPT (ZERO DEPENDENCIES).
```
