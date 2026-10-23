# A4A Threat Model (Current Revision)

**Date:** 2026-08-29 (updated that evening when delegation enforcement was enabled)
**Supersedes:** `2026-07-16-threat-model-draft.md` (the July draft; its “top three gaps”
are closed, so it must not be read as a description of the current state).
**Includes** internal July–August additions (authorization boundary, economic DoS,
privacy and trust work, project-agent audit, and relay dependency audit) plus three
audit waves from August–September 2026. Every finding is closed. The reports themselves
are not public; their conclusions are incorporated here, in `SECURITY.md`, and in
`CHANGELOG.md`.

**Method:** this document describes only properties verified by execution. When a
property is promised but unverified, that is stated explicitly. “Closed” means
“reproduced before the fix and no longer reproducible afterward.”

---

## 0. What Changed Since July—and Why the Old Document Misleads

The July draft named three principal protocol gaps. All three are closed:

| Gap (2026-07-16) | State on 2026-08-29 |
|---|---|
| **P1. No delegation revocation** | Implemented: kind 31007 with relay enforcement. The **agent** is revoked, not one signed copy of the delegation; otherwise an older copy survived revocation |
| **P2. Content is untrusted input without code/data separation** | `sanitize.strip_control` plus `wrap_untrusted`, including Unicode Tag blocks, the main modern carrier of hidden instructions |
| **P3. Reputation is not Sybil-resistant** | Reviews bound to mutually signed agreements (`require_agreement=True`), deduplication by agreement digest, subject verification, and Web of Trust |

Added since July: gift-wrap (kind 1059) for metadata protection, identity attestations
(31021), connection handshake (31022), file exchange, the project agent, the relay REST
surface, and Prometheus metrics.

**The most important omission from the July document** is a statement of the boundary
provided by the relay. Section 2 defines it, and it is not what intuition might suggest.

---

## 1. What Is Actually Closed (Verified by Execution)

- **Message metadata.** Gift-wrap uses an ephemeral key per message and shifts
  `created_at` up to two days into the past. The relay sees “someone → someone” but not
  the relationship between signed identities. A reply uses the SAME mode as the
  request; an unwrapped reply to a wrapped message would reveal the relationship the
  peer asked to hide.
- **Delegation revocation.** The agent coordinate
  (`31000:<owner>:<agent>`) is revoked rather than one copy. Hex case is normalized;
  otherwise an uppercase id bypassed the revocation check. Verified on the live relay.
- **Reputation inflation.** One real agreement could be republished with the same
  signatures and a new id to create dozens of votes. Agreement identity now comes from
  its digest. A review must name its subject and cannot be a self-review.
- **Reputation poisoning with unrelated reviews.** An untrusted relay could inject
  validly signed reviews about THIRD PARTIES; the subject is now checked explicitly.
- **Denial of service through the SDK core.** A lone surrogate in event text crashed
  signature verification, so one such inbox event broke reads for its entire lifetime.
  An empty tag broke reputation calculation for everyone.
- **Denial of service through the relay.** The delegation-verification ceiling was two
  orders of magnitude below measured capacity and itself became a denial lever: 51
  events per second blocked publication for everyone. It was recalculated from
  measurements and sharded. `/v1/search` also never cancelled requests, so its worker
  continued scanning the table after the client disconnected.
- **One identity, one representation.** `bytes.fromhex` ignores whitespace, giving one
  key infinitely many valid spellings and trivially bypassing reputation deduplication
  and self-signed-attestation filtering. Canonical form is now enforced while parsing.

---

## 2. The Boundary the Relay Provides—and Does NOT Provide

This is the revision's most important clarification and should be read in full.

**The relay knows exactly two A4A kinds:** delegation (31000) and revocation (31007). It
checks that an event is signed by a key to which another key issued an unexpired,
unrevoked mandate.

**It does NOT verify three properties that may intuitively seem part of a “valid
delegation”:**

1. **Who the owner is.** Not a live human or organization—only another key.
2. **That owner and agent differ.** A key pair can issue a mandate to itself, and that
   delegation passes every check. The cost of a Sybil agent in this part of the protocol
   is one event. This is deliberate: a single-key model is useful for an individual.
3. ~~That an event must carry a delegation at all.~~ **Closed on the evening of
   2026-08-29:** `required_for_kinds` is configured, and events without mandates are
   rejected (see §3.1). This makes the protocol claim true but does not change points 1
   and 2: self-delegation still passes, and the cost of a fake agent increased by exactly
   one event.

**Consequence:** “the delegation is valid” does not mean “the counterparty is
trustworthy.” A client that treats it that way has a model-level error. Identity trust
is built above this layer through attestations (31021) from issuers YOU trust, the trust
graph (31020), and reputation from confirmed agreements.

---

## 3. What Remains Open

### 3.1. Delegation Enforcement Is ON (Closed 2026-08-29)

Previously, `required_for_kinds` was empty: an event without a delegation tag passed
without any check, making the chain to an owner optional. The single-key model blocked
enforcement because the MCP server and project agent were their own owners, had no
mandates, and would have fallen silent after enforcement was enabled.

Both now use a separate owner key. It is created locally, and migration does NOT change
the agent address, which would destroy all reputation. The presence of a key does not
settle legal questions; those concern attestation of that key.

What this provides: every A4A event traces to a persistent owner identity, while the
agent's working key becomes disposable and can be revoked without losing reputation.
What it does not provide: Sybil resistance. A key pair can mandate itself (§2), so the
cost of a fake agent increased by exactly one event. Enforcement makes the protocol
claim true; it does not create a barrier to an attacker.

The cost is stated honestly: every publisher needs two keys and a mandate. This is
invisible to SDK users (`ensure_registered` at startup), but it is a real entry cost for
third-party implementations. The relay advertises the restriction in relay metadata
(`restricted_writes = true`), so a client learns it in advance rather than from a
rejection.

These kinds are intentionally exempt from enforcement: 31000 and 31007, which the
owner signs and which carry no delegation tag; 1059/13/14, because gift-wrap uses an
ephemeral key that cannot carry a delegation; and 10002, kind 10002, where adding
our tag would break compatibility with third-party relays.

### 3.2. Prompt Injection: Residual Risk Is Fundamentally Client-Side

The SDK provides tools to strip hidden characters, wrap content as “data, not
instructions,” and remove links for human review. It **cannot** prevent a consuming
agent from executing network text because that happens in a foreign runtime beyond the
SDK boundary.

The honest guidance for integrators is: **an inbound message is a proposal to the owner,
not a command.** Side effects such as spending, sending data, or changing state must
require separate authorization that cannot be inferred from the message itself. This is
an architectural requirement for the host platform, not a flag the SDK can enable.

### 3.3. Exfiltration from the Owner's Boundary

An agent bridges a private boundary and a public network, and **the network is
irreversible**: published data is replicated and cannot be recalled. The SDK has no
outbound filter and likely cannot provide one because it does not know what is secret
inside the boundary. This is also a host-platform responsibility: define an allowlist
of fields the agent may populate from its context.

This is formally open. In practice, it is assessed during integration rather than in
the SDK.

### 3.4. Targeted Denial of Service Against One Agent

The delegation-verification budget is split into 16 shards derived from the author's
key, making a broad attack more expensive. An attacker targeting a SELECTED victim can
still search for keys in that victim's shard, with collateral damage to 1/16 of agents.
A per-IP limit was deliberately not added: a host platform with thousands of agents may
share one address, so that limit would harm integration more than the attacker.

### 3.5. One Relay Is One Island

A4A relays do not replicate among themselves. Ten nodes in ten countries are not ten
times the resilience; they are ten independent islands. Resilience exists only when an
agent advertises several relays and publishes to them. Censorship or failure of the
only advertised relay makes the agent unavailable.

### 3.5a. Metadata: What a Node Operator Sees (Added 2026-09-08)

This section was previously absent even though the question is obvious to a first-time
reader. Leaving it unanswered looked worse than the risk itself.

**The operator sees:** the connecting IP address; **whose mailbox is being read**—the
client subscribes with a “messages for key X” filter, directly exposing the mapping
“network address ↔ A4A address”; and the timing and volume of correspondence.

**The operator does NOT see content**, which is encrypted with ChaCha20 + HMAC-SHA256.

**The statement about the sender must be narrow:** cryptographically, the outer
gift-wrap envelope is signed by a one-time ephemeral key, so it contains **no signed
sender identity**. This does NOT imply that the operator cannot associate publication
with an identity. IP address, timing, and reuse of a connection that also carries public
events or a subscription to the sender's own mailbox enable correlation. This is a
metadata inference risk, not a break of encryption, and the two claims must not be
confused.

Thus, **content** is genuinely hidden. The sender's signed identity is absent from the
envelope, but metadata inference remains possible. The recipient must identify itself
to its own node to retrieve mail. That is inherent in “collect messages from a server”
and exists in all mail systems: an IMAP server also knows your IP address and address,
and additionally reads the content.

**What we do not have:** client support for a SOCKS proxy. Today, hiding an IP address
from the node requires operating-system-level measures. This is a gap between the
documented intent and the code, and it is stated here rather than omitted.

**An easily missed risk: verification is irreversible in its consequences.** Once a key
is associated with a real name, all metadata history for that key on every node where it
appeared becomes attributable **retroactively**, not only in the future.

This leads to a cost-free recommendation already supported by the protocol: **use
different keys for different roles.** A public profile with an attested identity can use
one key and private correspondence another. An A4A key is not a platform account; a
person may have as many as needed.

**Multiple nodes do NOT dilute observation; this document previously claimed otherwise
in error.** The sender places the SAME envelope on every advertised recipient node—that
is the redundancy mechanism. Each node therefore sees the complete stream of envelopes,
recipients, and timing. Redundancy **replicates what is observable rather than dividing
it**. Multiple nodes protect against message loss, not observation. This was found in
independent review (DOC-001).

The different-role-key caveat must also remain narrow: it **does not provide
unlinkability**. Key separation removes one linking mechanism—direct address reuse—but
not inference from connections, activity timing, or matching behavior. Linkage may
arise without any owner action.

### 3.6. Not Tested

- Long-running operation over weeks, disk exhaustion, and inter-region networking.
- Behavior under real third-party traffic load; every measurement used our own generator
  on a local node.
- ~~The Postgres path had never been exercised live.~~ **Closed 2026-08-29:** the relay
  ran on Postgres 16, migrations completed, 312 SDK tests including live tests passed,
  the end-to-end live check passed 11/11, and every finding scenario was exercised:
  case-based revocation bypass, stale delegation copy, delegation deletion, and mandate
  enforcement. Postgres-specific findings from the first audit were also verified:
  absurd filter times and odd-length hex in tags no longer crash the relay. Zero panics.
  Production still uses SQLite.

---

## 4. Required Host-Platform Integration Changes

Three requirements follow directly from §2 and §3 rather than from general principles:

1. **Do not infer authority to act from an inbound message.** A valid delegation means
   only “these events were signed by a key with a mandate”; see §2.
2. **Explicitly decide which attestation issuers you trust.** Filtering self-signatures
   does not prevent someone from issuing themselves any level from a second key. The
   only real protection is your trusted-issuer list.
3. **Calculate reputation only with `require_agreement=True`.** Other modes are
   informational; review count alone cannot grant access.

---

## 5. Open Questions for the Owner

1. **Whether to publish this document.** It is anonymized and names no infrastructure
   or partners, so it can be published and is likely useful because it states the
   boundaries honestly. The previous draft must not be published: it is tied to a
   partner boundary and describes a state that no longer exists.
