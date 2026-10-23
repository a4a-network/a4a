# A4A Time Notary

A sidecar beside the relay, requiring REST `/v1/history` with a **`page=2`** response.
Once per hour it collects **history** events (kinds 31000, 31007, 31004, 31005, 31020,
and 31021) by **node receipt time**, not `created_at`, so backdated events remain covered.
It verifies each signature, builds a Merkle tree, submits the root to public
OpenTimestamps calendars, and, once a calendar proves inclusion in a Bitcoin block,
publishes a OpenTimestamps kind 1040 for each event. This proves that the event existed **no
later than** the block time. The public boundaries appear below and in specification
§2.8.

What the notary does NOT do: it does not modify relay code, timestamp Intents, Offers,
or tasks, publish pending timestamps, or prove a lower time bound.

## Container runtime contents

Images built from this source keep CPython and the hash-locked notary libraries,
but omit pip, setuptools, wheel and ensurepip. Build backends and installers are
used in preparation stages only. The final image copies the checked, cleaned
filesystem rather than inheriting installer-bearing layers. Dependency changes
require rebuilding the image; local virtual-environment installation is unchanged.
The runtime remains UID 10001 with state in `/data`, and preserves the notices
for the third-party libraries it actually includes.

## Run Beside the Relay

```yaml
# docker-compose fragment beside the relay service
notary:
  image: a4a-notary:0.1.4
  restart: unless-stopped
  environment:
    A4A_RELAY_URL: ws://relay:8080            # internal relay address
    A4A_RELAY_PUBLIC_URL: wss://eu1.a4a.network   # address in the kind 1040 `e` tag
    A4A_NOTARY_INTERVAL: "3600"
  volumes:
    - notary-data:/data                       # notary key (0600) and state
```

On first start, the service creates a key and prints its pubkey to the log. **Put that
pubkey in the relay configuration** as `[a4a] notary_pubkey = "<hex>"`; the relay then
advertises it as relay metadata `a4a.notary`. Without this, readers reject the timestamps because
any key can publish kind 1040 and arbitrary authors cannot be trusted. Treat the notary
key like an identity key: keep it outside Git and only in the volume.

`A4A_RELAY_URL` is the node's WebSocket address. REST uses the same host (`ws://` →
`http://`, `wss://` → `https://`). A relay without `/v1/history` produces a logged error
that names the version rather than a silent skip.

**Working-version compatibility.** The 2026-09-05 change is not yet deployed. This code
requires paginated responses shaped as
`{"version":2,"rows":[...],"next_cursor":...}`. Older images, including `0.1.4` above,
use the previous seconds-only cursor. During an upgrade, update the relay first and the
notary second; new images are released separately. Never connect a new notary to the old
response format: it fails explicitly instead of silently missing events.

Each page is limited to 2 MiB and may contain fewer events than requested. After a
batch, both `first_seen` and `first_seen_id` are persisted; the next cycle continues
within the same second when necessary. Migrating an old database does not delete batches
or leaves: the last second is read again and known ids are not timestamped twice. When
manually rewinding the cursor time, also reset `first_seen_id` with
`Store.set_cursor(T)`. The node clock must not move backward; after a backward clock
correction, rewind the cursor to the affected second.

Variables: `A4A_RELAY_URL`, `A4A_RELAY_PUBLIC_URL`, `A4A_NOTARY_KEY_FILE`,
`A4A_NOTARY_DB`, `A4A_NOTARY_INTERVAL`, and comma-separated `A4A_OTS_CALENDARS` (the four
public OpenTimestamps project calendars by default).

## Key Rotation (Planned or After Compromise)

1. Stop the notary, rename `notary.key` to `notary.key.retired-<date>`, and restart. The
   first start creates a new key and prints its pubkey.
2. In the relay configuration, put the new key in `notary_pubkey` and the old key in
   `notary_retired` with `until` equal to the time of the last block timestamped by the
   old key (from the `finalized` log) plus one hour of margin. After compromise, use the
   time of the last block *before* detection. Restart the relay and verify relay metadata
   `a4a.notary_retired`.
3. The new key publishes batches that were waiting for a block under the old key because
   storage is not bound to a key. Readers reject old-key timestamps whose block is later
   than `until`; a timestamp for a past block cannot be forged. Such events must be
   **timestamped again with the new key**: delete both their leaves and batch records
   from storage (`DELETE FROM leaves WHERE batch_id IN (…); DELETE FROM batches WHERE id
   IN (…)`, using batch numbers from the log—the same id set gives the same unique root)
   and rewind the `first_seen` cursor. The next pass collects them again. Residual risk:
   the compromised old key remains acceptable only for blocks no later than the
   published `until` boundary; an incorrect boundary expands its trust window.

## How Long to Wait—Observation, Not a Promise

For the first live batch on 2026-09-04, the root was submitted at 06:41, the Alice
calendar included it in a Bitcoin transaction, and Esplora showed block 965428 confirmed
at about 08:40. The calendar returned the completed proof only during the 09:37 pass:
**2 hours 56 minutes** from submission to kind 1040. A second batch submitted at 06:51
took 2 hours 46 minutes. Before that, the calendar returned 404 “Timestamped by
transaction …”, retaining the proof until several confirmations. This is a property of
public calendars; the specification's “1–3 hours” comes from this measurement.

## What the Log Shows

- `batch: N leaves, root …, calendars [...]` — root accepted; no kind 1040 yet;
- `pass: {'collected': 0, 'finalized': 1, 'published': N}` — block found and timestamps
  published, usually 1–3 hours after the batch;
- `calendar X rejected root: <type>: <text>` — exact rejection reason; one responding
  calendar is sufficient;
- `calendars did not respond` — batch not stored; the next pass retries;
- `watchdog: published 1040 — N, relay returns M, missing K` — the relay returned OK,
  but REQ cannot find the timestamps because kind 1040 is not protected or the relay
  reached its per-author ceiling. In `run_once`, this is the `missing` field.

## Verification

```
cd notary && python -m pytest -q          # tree, calendars (forgeries), storage, cycle
```

`tests/test_crosscheck_sdk.py` reads our timestamps through the SDK parser
(`a4a.timestamp`): two independent implementations parse one file, so a format mismatch
fails here first.

Live run against any relay: `A4A_RELAY_URL=ws://localhost:8083 python -m a4a_notary
--once` performs one pass and stores state in `A4A_NOTARY_DB`.

## Dependencies and License

The `a4a-notary` code is distributed under MIT. The root project license text is
included in [`LICENSE`](LICENSE) and in the package wheel/sdist. This does not change
dependency licenses. The SDK does not depend on `opentimestamps`; it contains its own
`.ots` parser.

`opentimestamps` is installed separately rather than copied into our Python package.
The verified local 0.4.5 wheel contains
`opentimestamps-0.4.5.dist-info/LICENSE`, granting LGPL-3.0-or-later (version 3 or any
later version); its short metadata field says `LGPL3`. The complete upstream
[LICENSE](https://github.com/opentimestamps/python-opentimestamps/blob/master/LICENSE)
contains that grant and the LGPL text. Files under `licenses/` contain reference copies
of LGPL-3.0 and GPL-3.0 but do not replace the complete upstream LICENSE and its own
notice.

For source code that merely references the dependency, no additional copy of the
upstream license is added here. Before releasing a binary or container candidate that
includes the library itself, verify the complete LICENSE, notices, GPL/LGPL texts, and
applicable source-availability and library-replacement terms for that specific artifact.
The `Dockerfile` arranges to copy reference texts into `/app/licenses`, but that does not
verify the contents of the finished image. Running the dependency as a separate process
does not by itself demonstrate LGPL compliance. See
[`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md).
