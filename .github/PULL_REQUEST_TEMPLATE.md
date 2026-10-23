## What and why

In one paragraph, explain the problem this change solves. Give the reason, not a
restatement of the diff.

## Verification

Check only what was actually completed. Empty boxes are more useful than guesses:
"builds" and "works" are different claims.

- [ ] `bash scripts/test-sdk.sh` passes
- [ ] `bash scripts/test-agent.sh` passes (if the agent changed)
- [ ] `bash scripts/test-mcp.sh` passes (if the MCP server changed)
- [ ] `cd relay && cargo test` passes (if the relay changed)
- [ ] `bash scripts/test-sdk.sh --live` passes against the built image if the relay's
      HTTP or WebSocket path changed; unit tests do not cover it

## If this fixes a bug

Is there a test that **failed before the fix**? A test written after the code and green
immediately proves less: it checks what you remembered, not necessarily what broke.

## If the protocol changed

- [ ] `docs/spec/a4a-protocol-v0.4.md` is updated
- [ ] A test, not only prose, verifies the claimed property

## What remains unverified

State explicitly what was not checked, such as "built but not run" or "not tested
against a live relay." This is valuable information, not an admission of weakness.
