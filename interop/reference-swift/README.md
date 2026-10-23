# A4A Reference Implementation — Swift (iOS 16+ / iPhone / iPad / macOS 13+)

This directory provides a self-contained **Swift 5.9+** reference implementation of the **A4A v0.4** client cryptography and wire formats (`A4AClientMinimal.swift`) for native **iPhone, iPad, and macOS** applications.

## What is Included in `A4AClientMinimal.swift`

1. **A4A Bech32 Bech32 (`A4ABech32`)** — pure-Swift encoding and decoding of `asec1...` and `apub1...` keys, plus hex helpers (`Data(a4aHex:)`, `.a4aHex`).
2. **A4A E2EE v2 (`A4ANip44`)** — power-of-two length-prefixed padding (`calcPaddedLen`, `pad`, `unpad`), `HKDF-Extract` (`salt = "nip44-v2"`) + `HKDF-Expand` (76-byte output), RFC 8439 `ChaCha20` stream cipher, and constant-time `CryptoKit.HMAC<SHA256>` verification.
3. **Pluggable `Secp256k1Provider` Protocol** — clean 4-method interface (`xOnlyPublicKey`, `sharedSecretX`, `signSchnorr`, `verifySchnorr`) designed to plug directly into [`GigaBitcoin/secp256k1.swift`](https://github.com/GigaBitcoin/secp256k1.swift) (`libsecp256k1` via Swift Package Manager) on iOS and macOS.

## Adding to an iOS / macOS Xcode Project

1. Copy [`A4AClientMinimal.swift`](A4AClientMinimal.swift) into your Xcode target or Swift package.
2. Add `https://github.com/GigaBitcoin/secp256k1.swift` via **File → Add Package Dependencies…** in Xcode and implement `Secp256k1Provider`.
3. Store user and agent secret keys in the iOS / macOS **Keychain** (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
4. Verify your target against the cross-language test vectors in [`../test_vectors.json`](../test_vectors.json).
