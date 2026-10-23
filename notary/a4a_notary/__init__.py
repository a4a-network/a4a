"""A4A timestamp notary — a relay sidecar that stamps history via NIP-03.

Design: docs/design/2026-09-04-ots-notary-design.md. It publishes kind 1040 with
its own key over the relay's regular WebSocket and is not part of the relay code.
"""
