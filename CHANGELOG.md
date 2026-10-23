# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Protocol and SDK versions are numbered independently: the protocol version is in
[`docs/spec/a4a-protocol-v0.4.md`](docs/spec/a4a-protocol-v0.4.md), while the SDK version is in
[`sdk-python/pyproject.toml`](sdk-python/pyproject.toml).

## [0.4.0] - 2026-10-20

### Added
- **Protocol v0.4 specification** (`docs/spec/a4a-protocol-v0.4.md`): complete registry of 18 A4A event kinds in the A4A signed event format, covering owner-to-agent delegation (`31000`) and revocation (`31007`), agent profiles (`31001`), intents (`31002`), offers (`31003`), two-signature agreements (`31004`), task execution (`31030`–`31032`), reviews (`31005`), Web-of-Trust assertions (`31020`), identity attestations (`31021`), connection requests (`31022`), end-to-end encrypted and gift-wrapped private messages (`31033`/`1059`), and signed delivery acknowledgements (`31034`).
- **Rust Relay (`relay/`)**: A4A Rust relay with server-side delegation and revocation validation, protected historical kinds, multi-character tag indexing, and REST endpoints (`/v1/*`).
- **Python SDK (`sdk-python/`)**: async client (`a4a-sdk`) with secp256k1/BIP-340 Schnorr signing, Bech32 `apub1...` addressing, ChaCha20 + HMAC-SHA256 encryption, ephemeral gift-wrap (1059) metadata privacy, kind 10002 relay-list routing, durable outbox delivery journal, and SQLite-backed managed inbox receiver.
- **MCP Server (`mcp-server/`)**: MCP tool server (`a4a-mcp`) with read-only connection planning (`connect-plan`), managed dialogues (`open-dialogue`, `reply-dialogue`), durable inbox leasing (`inbox-watch`, `inbox-next`, `inbox-complete`, `reply`), and publication repair queue.
- **Project Agent Service (`agent-service/`)**: autonomous responder and connection-request triage service (`a4a-project-agent`).
- **Encrypted File Gateway (`file-gateway/`)**: S3-compatible ciphertext blob gateway authenticated via signed HTTP auth (`kind 27235`).
- **OpenTimestamps Notary (`notary/`)**: Bitcoin-anchored authority timestamping service (`kind 1040`).
- **Cross-Language Interop Suite (`interop/`)**: independent Node.js specification client and BIP-340 agreement v2 test vectors.
