# A4A v0.4 Minimal Kotlin / JVM Reference (`interop/reference-kotlin`)

Single-file, zero-dependency reference implementation of A4A v0.4 cryptographic primitives, contact parsing, A4A E2EE v2 / A4A Sealed Envelope signed Gift Wrap envelopes, and `a4a-chacha20poly1305-v1` file encryption for Android (`minSdk 28+`) and Kotlin/Java JVM applications.

## Files

- [`A4AClientMinimal.kt`](A4AClientMinimal.kt) — drop-in Kotlin object (`package network.a4a.interop`) using standard JDK / Android SDK classes (`java.math.BigInteger`, `javax.crypto.Cipher`, `javax.crypto.Mac`, `java.security.MessageDigest`, `java.util.Base64`). No external crypto libraries required.
- [`VerifyVectorsJvm.java`](VerifyVectorsJvm.java) — standalone JVM test runner that verifies the deterministic vectors in [`../test-vectors/app-messenger-v0.4.json`](../test-vectors/app-messenger-v0.4.json) directly with `java` (OpenJDK 17+).

## Verify Vectors on Any JVM (OpenJDK 17+)

```bash
java interop/reference-kotlin/VerifyVectorsJvm.java
```

Expected output:

```text
ALL A4A v0.4 JVM / KOTLIN CRYPTO & ENVELOPE VECTORS VERIFIED SUCCESSFULLY.
```
