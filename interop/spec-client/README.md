# Specification-Only Client — Interoperability Guard

An independent Node.js A4A implementation written **only from the specification**:
`a4a-master-spec.md` and `docs/spec/a4a-protocol-v0.4.md`. The authors did not inspect
`sdk-python/` or `relay/`, and changes here **must not** rely on those implementations;
that separation is the point. The only shared code is a BIP-340 library.

## Why This Is in the Repository

An internal test cannot reliably detect divergence between specification and code
because it is written by the same people with the same assumptions as the code. Here,
the relationship is reversed: if the specification stops matching reality, this
implementation breaks rather than ours.

The first run on 2026-09-05 found three specification gaps, not code defects: it did not
say where agreement currency came from, what became the agreement deadline, and the two
documents disagreed on the event-lifetime formula. All three were corrected in the text,
not the code.

## Run It

### Offline agreement-v2 Check

Node.js >=20.19.0 is required by the pinned `@noble/*` versions. With dependencies
already installed, neither network access nor a relay is required:

```bash
cd interop/spec-client
npm --offline --ignore-scripts test
```

Versions are pinned in `package-lock.json`, which was created offline without install
scripts. With a populated npm cache, prepare dependencies using
`npm ci --offline --ignore-scripts --no-audit --no-fund`. Without the cache, that step
fails rather than falling back to a network installation.

`npm test` runs only `agreement.test.js` through `node:test`: fixed canonical UTF-8
bytes and digests from `../vectors/agreement-v2.json`, Unicode and surrogates, numeric
boundaries and invalid types, the previous ASCII digest, and the unchanged A4A event
ID format. Tag-forwarding checks in `counterpart.js` use only stub dependencies, with no
sockets, key writes, or real publications.

`agreementCanonical(terms)` returns a canonical ASCII string without a BOM or trailing
newline. `agreementDigest(terms)` hashes its UTF-8 bytes under the existing
`a4a/agreement/v2` domain. `price` and `deadline` accept canonical decimal strings or
`BigInt` in the range 0..9999999999999999999. `Number` is accepted only for safe,
non-negative integers other than `-0`. Other text fields require primitive strings. Tag
values must not be pre-converted through `Number`.

### Live Scenarios

These require installed dependencies and a running relay (`docker compose up -d` from
the repository root). They publish events and are **not part of `npm test`**:

```bash
cd interop/spec-client
node deal.js ws://localhost:8080        # end-to-end agreement with two signatures
node negative.js ws://localhost:8080    # node rejections promised by the specification
```

`deal.js` runs the complete path: both parties' mandates → Intent → faceted search →
Offer → half-signed agreement → the counterparty discovers it, **computes the digest
independently**, verifies the other signature, and publishes the complete version → the
initiator verifies both signatures. Every place where the specification lacked a unique
answer is printed as `GUESS`; those are findings for the next textual review.

`negative.js` tests the inverse side: a delegation without `d`, a non-canonical expiry,
and a malformed subscription filter. “Everything accepted” proves nothing if the node
accepts anything.

Both scenarios **clean up after themselves**; otherwise every run would leave mandates
on the network that nobody could delete.

### Running Against the Production Node

The scenarios work there too. On 2026-09-05, the end-to-end agreement and all six
negative controls matched the test environment, and the database returned to its
initial counters. But **cleanup has an unavoidable cost**: a deletion event (kind 5)
cannot itself be deleted, so every run leaves one such event PER USED KEY forever. A
production measurement found 66 such events from 66 disposable keys after one week of
testing, covering 126 deleted events.

Therefore, **run scenarios in the test environment**. Reserve the production node for
properties the test environment cannot show: retention configuration, the notary, TLS,
and live history. A production run must be deliberate rather than “just in case,” and
should be rare.

## CI Boundary

The offline agreement-v2 check is intended as a mandatory CI gate for format and
specification changes. Prepare dependencies before it starts; the check itself neither
accesses the network nor publishes events. Live `deal.js`, `negative.js`, and
`counterpart.js` remain separate manual scenarios rather than part of this gate.

## Byte-for-Byte Properties It Checks

* `sha256("a4a/agreement/v2")` and the §1.1 reference-example digest; both vectors
  matched on the first attempt without corrections;
* a Schnorr signature over the 32 digest bytes rather than its hex representation;
* numeric canonical form `0|[1-9][0-9]{0,18}` when constructing events;
* `sig_a`/`sig_b` are always present, with an empty string for a missing signature;
* the complete agreement is a new event with a new `id`, which subsequent references
  must use;
* our Python SDK reads an agreement constructed here as concluded, verified separately.
