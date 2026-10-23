---
name: Protocol change
about: A new event kind, tag, or validation rule that changes compatibility
labels: protocol
---

> Other implementations rely on the protocol, so this template asks for more detail
> than usual. Changing an event format once is cheaper than changing it after clients
> depend on it.

## Proposal

State the event kind, tags, and validation rule concisely.

## Problem this solves

Explain what is impossible or unnecessarily difficult today. A real example is more
valuable than an abstract description.

## Why existing mechanisms are insufficient

See [`docs/spec/a4a-protocol-v0.4.md`](../../docs/spec/a4a-protocol-v0.4.md) for the
current protocol surface.

## Compatibility

- Does it break existing events or clients?
- What does a client unaware of the change observe?
- Does it require new relay behavior? By default, no: the relay recognizes exactly two
  A4A event kinds and clients validate everything else.

## Verification

Name the assertion and the test that will verify it. A property that cannot be tested
does not enter the specification; this project has already paid for that mistake.
