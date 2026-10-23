# Read-only counterparty evidence

Prerelease API reference; begin with [safe connection](safe-connect.md).
This report explains provenance and sampling limits. It is not a fraud score,
KYC enrollment, escrow, identity guarantee or monitoring schedule. It changes no
rating math, permissions, contact policy or mandate. No private messages are read
and no public events are published.

## Calls and scope

MCP: `a4a_get_counterparty_evidence(pubkey, days=30)`. Supply a canonical lowercase
hex public key and `days` in 1..365, default 30. The tool neither initializes nor
accesses the local identity file. An updated MCP process needs a normal restart
to expose new tools; this is not a profile migration.

SDK, inside an already configured `Agent` context:

```python
report = await agent.get_counterparty_evidence(
    peer_pubkey, window_days=30, limit=200, reviewer_limit=5,
    trusted_issuers=(),
)
```

`a4a.evidence.analyze_counterparty` also analyzes collected Events offline and
still verifies signatures. Network collection uses the agent's own configured relays
— **every one of them**, not just the first — and never subject-advertised URLs.

The lookup is therefore visible to **each configured relay**, because the same query
goes to all of them. This document previously said "the primary relay"; that was true
before fan-out and is not true now. If you would rather a particular operator not see
whom you are asking about, configure fewer relays for that agent: the protocol has no
way to hide a query from a node you send it to.

## Fields and limits

- `reviews_received`: agreement-backed reviews, distinct reviewer keys, star counts,
  top-one/top-three concentration, peak rolling 24-hour count and bounded reviewers.
- `reviewer_activity` / `authored_review_activity`: signed rating statements in an
  outgoing sample, not proven transactions, independent people or proof of collusion.
- `agreements`: distinct mutually signed agreement digests and zero-price counts.
  Re-publication does not add agreements; zero price is not an abuse verdict.
- `identity`: sampled issuer statements and observed owner bindings. A mandate
  alone is insufficient: a target-signed event must reference it. Multiple observed
  owners remain visible; these are not exclusive ownership or current-controller proofs.
- `window`: author-declared timestamps, not independently observed publication time
  or account age.
- `coverage`: `relay_scope` (a single node or the configured set), `relays_configured`
  and `relays_responded_at_least` — the latter counts nodes that **actually answered**,
  taken as the minimum across queries, because a configured but unreachable node
  brings nothing and must not be counted as reach. Also caps, possible truncation,
  unresolved agreements,
  queried reviewers and identity subjects. It marks network completeness unknown,
  even after EOSE. Reads are not atomic. Signature/structure discards are counted;
  `connection_dropped_events` describes connection-wide loss, not necessarily just
  that query, and marks possible truncation.

Default queries inspect at most 201 events each **per relay**, so a standard query
against the maximum of sixteen configured nodes inspects up to 3216 and marks possible
truncation. The per-analysis ceiling stays at 200 after merging and de-duplication.
At most five reviewer profiles are sampled, without recursive graph crawling. SDK
per-query limits are 1..1000, `reviewer_limit` is 0..10, outgoing reviewer samples are
capped at 500 each / 5000 total. The collection deadline is 45 seconds, separate
from initial connection timeout. Refusal or timeout of **all** configured relays fails the report, not a reassuring
zero. A partial outage does not: the report is produced from the nodes that answered,
and `relays_responded_at_least` says how few that was. Read that number before trusting
the numbers above it. Every inspected EVENT counts, including invalid signatures.
`RelayClient.query_bounded` returns inspection counts and truncation in `QueryResult`;
legacy `query()` still returns a list.

Output omits free text, personal names, document references, URLs and arbitrary
tag values. Public keys, bounded event references, fixed labels and numbers remain.
Absent evidence is not good standing. Signatures are not proof of payment, real
work, independent humans or an uncompromised key; copied/sold keys keep history.

## Owner-configured trust

`A4A_TRUSTED_ISSUERS` accepts at most 32 comma-separated canonical hex public keys.
Empty/unset means no trusted issuers; malformed entries (including empty elements
in a nonempty list) fail before network access. The owner independently vets and
configures issuers. Neither a counterparty nor tool arguments may change MCP policy.
This is not an OS sandbox: protect the launch configuration using normal host
permissions if the model has shell/write access.

Account/domain control is separate from person/organization claims. An issuer
signature is not proof its advertised checks happened. `trusted_issuer` means local
policy trusts that key, not absolute KYC. Expiry is checked, but general credential
revocation/status is not implemented. The latest sampled statement is selected
before expiry validation, so a newer expired statement cannot resurrect an older
unexpired claim. No distinct verified-owner count or population baseline exists.
Do not grant spending, execution or secret access based on this report.
