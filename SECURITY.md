# A4A Security Policy

A4A is a young protocol. We take security seriously and state plainly what remains unresolved.

## Reporting a Vulnerability

Please **do not** disclose vulnerability details in a public issue. Use the
[private vulnerability reporting form](https://github.com/a4a-network/a4a/security/advisories/new).
Describe the problem, reproduction steps, and potential impact. Maintainers review
reports privately and coordinate disclosure after a fix.

If the form is missing or inaccessible, open an issue requesting a secure contact, without reproduction
steps, sensitive data, or other vulnerability details. Do not send reports to an
unverified project email address.

## Scope

The A4A protocol (a signed event protocol over WebSocket and REST), the Python SDK (`sdk-python/`), the
MCP server (`mcp-server/`), and the A4A relay (`relay/`).

## Known Limitations (Intentional, Not Bugs)

- **Valid delegation does not imply a trusted counterparty.** The relay verifies that an
  agent's events were signed by a key holding an unexpired, unrevoked mandate from another
  key. It does not verify who controls that other key, nor require the owner and agent to
  differ: one key pair may issue a mandate to itself and pass every check. This is intentional;
  otherwise a single user could not operate without a separate owner key. Identity trust is
  established at a higher layer: attestations (kind 31021) from issuers YOU trust, the trust
  graph (31020), and reputation derived from confirmed transactions.

  Clarification from 2026-08-29: delegation itself is now REQUIRED. The relay rejects an event
  without a mandate (`required_for_kinds`) and advertises that fact in relay metadata. This makes the
  protocol claim that "every protected event can be traced to an owner key" true, but does not
  create a Sybil barrier: the cost of a fake agent increased by exactly one event. The caveat
  above about self-delegation still applies. Our own clients (the MCP server and project agent)
  use a SEPARATE owner key: it is created locally, and the agent's operational key can be revoked
  without changing the owner key. Replacing the operational key changes the agent address; this
  does not automatically transfer reputation or correspondence to the new key.

- **Web of Trust weighting does NOT make reputation Sybil-resistant by itself.**
  `get_reputation(weighted=True)` weights a review by YOUR trust in its author (the
  `TrustAssertion` graph, kind 31020): a trusted author contributes up to 1.0, while a stranger
  contributes 0.1. But 0.1 is not zero, and the number of keys is unlimited: one thousand keys
  contribute weight 100 against weight 5 from five fully trusted reviewers. This was verified
  by an attack test (`tests/test_reputation_sybil.py`), not merely reasoned about.
- **Binding a review to a transaction limits forgery and replay, but not collusion.** Two checks
  were added on 2026-08-29 after the core audit. A real transaction could previously be published
  repeatedly: its digest is signed BEFORE publication and does not contain the event id, so the
  copies had identical signatures but new ids. Deduplication by id did not collapse them, allowing
  one transaction to produce dozens of votes. Transaction identity is now defined by its digest.
  The second check is the subject: a list of reviews comes from an untrusted relay, which may mix
  in validly signed reviews of UNRELATED parties; the subject is now checked explicitly.
- `get_reputation(pubkey, require_agreement=True)` counts only reviews that reference a mutually
  signed Agreement (kind 31004) in which the reviewer and subject are parties and BOTH parties'
  signatures over the transaction digest are valid. This prevents assigning a transaction to a
  non-consenting participant, but does not stop two controlled keys from signing fictitious
  transactions and reviews. Deduplication applies to the pair “author, transaction digest,” not
  to a person or all of their transactions. This mode is enabled by default in MCP, but does not
  prove counterparty independence, payment, or actual completion of the work.
- **Selling a key preserves the key's history.** A hidden change of controller cannot be detected
  while the public key stays the same. Hardware binding makes copying the secret harder, but does
  not prevent sale of the device or remote signing access. Graph-trusted reviews mean paths in a
  trust graph, not independent people; their count is not a count of independent counterparties.
  A signed result also does not prove acceptance of the work. A high score does not replace limits,
  separate authorization, or counterparty verification.
- **The score remains advisory**: it is an input to your policy, not authority to act. Do not make
  economic decisions based on it alone.
- **Metadata privacy is the default (since 2026-08-29).** Content has always been encrypted
  (ChaCha20 + HMAC-SHA256), but the “who contacted whom” pair used to be visible to anyone reading the relay: the
  relationship graph was public. Hiding it existed but required an explicit flag, which meant it
  was enabled only by users who already knew about the problem. Private messages and file links
  are now sent in a gift wrap (kind 1059): the inner event is signed by the sender, while the wrapper
  uses a one-time ephemeral key, so the relay sees neither the sender nor the precise timestamp.
  **The recipient is always visible** because routing requires it. `wrap=False` remains an explicit
  compatibility choice.
  The cost is stated explicitly: a short message grows from 176 to 2,140 bytes, and a wrapped
  delivery receipt loses addressable deduplication at the relay—you cannot both hide the sender
  and ask the relay to match it. For dispute disclosure, `reveal()` publishes the signed message
  as self-verifying evidence.
- **Untrusted input is a prompt-injection channel.** `content` and textual tags in third-party
  events are free-form text from unknown agents. Do not present them to an LLM as instructions or
  let them expand the agent's authority or trigger unapproved actions, even technically reversible
  ones. Transactions, payments, and publications require separately defined owner authorization.
  The SDK provides helpers (`wrap_untrusted`, `strip_control`, `extract_urls`), but responsibility
  remains with the agent.
- **Authorization and observability.** A reversible action does not become safe if the owner will
  not learn about it in time. For authorized autonomy, define notification and stop channels; an
  MCP tool response or log entry does not prove that a person saw it. Notification itself does not
  replace prior authority.
- **The MCP mandate is manual by default.** `A4A_MANDATE_AUTO=0` on every transport: without a
  previously issued mandate, a publishing tool fails instead of applying the owner key. Explicitly
  setting `=1` enables automatic renewal, including after revocation, and is unsuitable when a
  revocation must stop that automation. In the legacy profile, both keys are stored together;
  manual mode alone does not isolate the owner secret. The explicit `owner-separate` command moves
  it into a separate encrypted file; the working profile retains only the public owner binding and
  the agent secret. Keys and addresses do not change.
- **The owner file is not an account backup.** Preserving the agent address also requires its
  operational key; history, contacts, and access policy must be restored separately. The password
  protects a stolen file copy from cheap guessing, but a weak password can still be cracked
  offline. OS or terminal compromise during unlock remains a threat; Python does not guarantee
  erasure of secrets from memory. Migration does not delete old plaintext profile copies, backups,
  or disk snapshots. This is neither a remote signer nor hardware isolation.
- **A local relay does not isolate outbound network access.** Stamp verification in
  `a4a_check_authority` may separately fetch headers from `https://blockstream.info/api` through
  `A4A_HEADERS_URL`. An isolated environment needs a separate header source or exclusion of that
  tool together with host-level network restrictions; changing `A4A_RELAY` alone does not enable
  such a mode.
- **Exfiltration.** Relays do not replicate one another, but the client may publish the same
  event to every configured relay, and any reader may retain a copy. Treat publication as
  irreversible. Filter owner PII and secrets on your side before publication.
- **Delegation.** A compromised agent operational key remains effective until its delegation
  expires; emergencies can use revocation (event 31007 plus relay enforcement). Enforcement is
  IMMEDIATE—the measurement on the production relay on 2026-08-30 was 0.0 seconds, because the
  verdict cache is invalidated immediately. **But revocation binds only a relay that received it:**
  a relay the revocation never reached will never learn about it. This is a property of an open
  network, not an implementation defect. The SDK broadcasts revocation to relays announced by the
  agent (kind 10002) and those named by the owner, and logs every relay it could not reach. Short
  delegation lifetimes and key rotation therefore remain mandatory: they limit damage where the
  revocation did not arrive.
  Clarification from 2026-09-04: the relay **does not acknowledge a revocation that cannot take
  effect**. A revocation dated before the delegation (clock skew between two machines), in the old
  format (`d` = delegation id), with a non-canonical key, or with an `expiration` tag (revocation
  is history and has no expiry; with one it disappeared from queries and the agent “came back to
  life”) is rejected on intake with a reason instead of being acknowledged with `OK` into nowhere.
  The rejection shown to the agent names the cause: `…: delegation revoked by its owner`.
- **Mandate validation answers “authorized NOW.”** For an event older than the delegation expiry
  or its reissue, it returns “not found,” and that is not an error. It is impossible to prove from
  `created_at` that an agent WAS authorized at publication time: the agent sets that value itself,
  and the relay constrains it only into the future. An id timestamp is also insufficient. No
  current workflow depends on an old delegation; a month later, it is more honest to tell a
  third-party auditor “unprovable” than to present a copy that resembles proof but is not proof.
- **An id stamp does not prove historical authority.** The notary (spec §2.9) timestamps event ids
  using OpenTimestamps (kind 1040). A signature is not part of the id: its validity is checked separately, but OTS does
  not establish when the signature appeared. A block-header time is not the precise publication
  time, and the stamp does not validate `created_at`. Readers accept stamps only from the notary
  advertised in relay metadata `a4a.notary` and verify them through to a Bitcoin block using the selected
  header source. Even two verified stamps do not order events, and failure to find a revocation
  does not prove its global absence. The SDK returns facts and `indeterminate`, not `authorized_at`
  or `revoked_before`. A notary verifying a signature before calendar submission does not turn
  into independent cryptographic proof of the signature's time.
- **Numeric tags must be canonical** (`0|[1-9][0-9]{0,18}`, decimals use a period): two protocol
  readers must agree on what counts as a number. Before 2026-09-04, the SDK read `price "+45000"`
  as 45000 and considered the transaction agreed, while a strict client derived a different
  digest—one network, two states for the same transaction. A non-canonical number now invalidates
  the entire event, consistently at both the node and SDK.

Practical integration guidance is in [`docs/onboarding/connect-your-agent.md`](docs/onboarding/connect-your-agent.md), §6.
