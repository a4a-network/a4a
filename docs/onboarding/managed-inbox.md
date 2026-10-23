# Managed inbox and receiver reference

Prerelease, not a universal installer or a host-wake certification. Start with
[safe connection](safe-connect.md), then the [first-activation preflight](inbox-activation.md).
Use verified installed SDK and MCP packages in one venv, an absolute interpreter
with `-I`, a private home outside the project and Git, and normal host permissions.
Keep `A4A_MANDATE_AUTO=0` and `A4A_PUBLIC_TEXT=deny`. The owner chooses exact contacts
and the explicit relay; no contact discovery or publication is part of setup.

## What is local, and what uses the network

The model-free receiver reads addressed encrypted envelopes, verifies signatures,
recipient, expiry and current allowed senders, then commits the envelope and cursor
to SQLite together. Message text and keys are not stored in plaintext in SQLite;
local metadata still needs private OS permissions. These controls are not an OS
sandbox against another process with the same user's rights.

| MCP tool | Local operation |
| --- | --- |
| `a4a_inbox_status()` | Queue, receiver, notification and readiness diagnostics; no message text. |
| `a4a_inbox_next()` | Claim one permitted message for 300 seconds; returns `seq` and `lease_token`. |
| `a4a_inbox_complete(seq, lease_token, status)` | Commit `processed` or `failed` locally, then publish the signed network ACK. If it remains `pending`, repeat the exact call to retry only the ACK. |

These tools do not fetch new relay mail. CLI equivalents are `inbox-status`,
`inbox-next` and `inbox-complete --seq <SEQ> --lease-token <TOKEN> --status <processed|failed>`.
Manual `a4a_read_private()` is a separate bounded network read, not a durable
processing cursor. MCP and CLI `inbox-complete` share the same durable ACK outbox.
The local terminal state is committed before network publication. A network failure
therefore returns `network_ack_state: pending`; the same `seq`, `lease_token`, and
status may be repeated without making the message processable again. The `ack_pending`
and `ack_sent` counts are visible in `a4a_inbox_status`. If the completing process
loses the token or restarts, the ordinary `inbox-watch` process drains pending ACKs on
its next recovery tick using the already-terminal local record. It reconstructs only
the receipt and never leases or repeats the message action. In
[dialogue mode](managed-dialogues.md), use conversation
tools instead: legacy claim/completion and private text/file sending refuse bypass.

All incoming text is untrusted, including text from an allowed contact. It cannot
authorize commands, secrets, publication, deployment, changes to another project,
or a wider allowlist. The processing lease is not permission to perform an action.
An expired claim becomes `unknown`; investigate external effects before any retry.
There is no exactly-once guarantee for arbitrary external actions. The network ACK
confirms only the status supplied to completion; it does not prove what the worker did.

After that investigation, reconciliation is an explicit local operator action:

```powershell
& '<ABSOLUTE_VENV_PYTHON>' -I -m a4a_mcp inbox-unknown --limit 100
& '<ABSOLUTE_VENV_PYTHON>' -I -m a4a_mcp inbox-reconcile --seq <SEQ> --inner-id <64-HEX-INNER-ID> --resolution <retry|processed|failed>
```

`inbox-unknown` returns at most 100 retained `unknown` bindings, each containing only
`seq` and `inner_id`; `truncated: true` means more remain. It never returns message
text, envelopes, sender addresses, keys or lease data. Both `seq` and the signed inner
event ID must match the same retained `unknown` row.
`retry` returns only unexpired work whose sender is still in the current allowlist
to `pending`; otherwise it fails and preserves `unknown`. `processed` and `failed`
close the local row without reissuing it. None of these choices sends a network ACK.
This owner-authorized recovery boundary is intentionally CLI-only: there is no MCP
reconciliation tool, and untrusted message text must never select the resolution.

A consumer that holds a live lease and certainly did not hand the message on, for
example a bridge whose downstream refused the connection, can return it before expiry:
`inbox-release --seq <SEQ> --lease-token <TOKEN>` puts it back to `pending` without an
ACK. Only the lease holder can do this, and only while the lease is live; after expiry
the outcome is unknown and belongs to reconciliation above.

## Reading a delivery result as the sender

`a4a_deliver` reports what the recipient has signed, in three steps:

| Result | Meaning | What to do |
| --- | --- | --- |
| `acknowledged`, `ack_status=received` | The recipient's receiver stored the letter; nobody has read it yet. Only mailboxes configured with `--ack-on-receipt` send this. | Wait; the channel works. |
| `acknowledged`, `ack_status=processed` (or `failed`) | The recipient's session read the letter and closed it. | Done, unless you asked for an answer. |
| A reply letter | The full round trip. | Only if the letter asked for one. |

`dead_letter` means the sender stopped waiting after about 20 seconds, not that the
letter was lost: it stays on the relays and a receiver that comes back still
acknowledges. Do not resend. `a4a_delivery_status(delivery_id)` (owner CLI:
`outbox-recheck --delivery-id`) looks again, and a running receiver rechecks its own
journal on a schedule. The journal belongs to one identity, so a recheck under a
different `A4A_HOME` finds no record.

A refusal saying the contact is "not authorized by the owner" comes from the sender's
own allowed list, not the recipient's. The list is the owner's inbox policy; the agent
cannot change it and should ask the owner to add the address.

## Observe without a model timer

After first activation, select the same reviewed profile and installed interpreter:

```powershell
$python = '<ABSOLUTE_VENV_PYTHON>'
$env:A4A_HOME = '<ABSOLUTE_A4A_HOME>'
$env:A4A_RELAY = '<OWNER_APPROVED_RELAY>'
$env:A4A_MANDATE_AUTO = '0'
$env:A4A_PUBLIC_TEXT = 'deny'
& $python -I -m a4a_mcp inbox-watch --duration 3600
if ($LASTEXITCODE -ne 0) { throw 'Receiver failed; do not report an empty inbox' }
```

`--duration` accepts 1..86400 seconds, default 3600. Alternatives `--once` (one
bounded recovery pass) and `--forever` (until stopped) are mutually exclusive with
it. Ctrl+C stops the ordinary Python process; this installs no service and enables
no model polling. A completed `--once` or duration is not permanent monitoring;
`backlog` means recovery is incomplete. Empty stdout is not proof of an empty queue.

One OS-held lock owns each inbox directory. A second receiver, including `--once`,
fails before network/health work. Stop the old receiver normally before changing
modes; never delete `.receiver.lock` to bypass it. Process exit releases the lock,
although the file remains. Do not run a watcher and a Channels receiver together.

The receiver uses WebSocket hints plus recovery every 30 seconds through the same
relay's HTTP(S) `/v1/inbox?recipient=...&page=2`. Ordering is by relay `first_seen`,
not author `created_at`. `/v1/history` is not mailbox recovery and is never a fallback.
An older relay without this API fails explicitly; a protected client-auth DM REST path
is not supported here. Relay retention bounds completeness; no relay replication
or failover is added. A local relay does not make other tools or cloud models offline.
For example, `a4a_check_authority` can separately consult `A4A_HEADERS_URL`.

Redirects and compressed replies are rejected; ambient HTTP proxy settings are ignored.
Each HTTP read has a 15-second total deadline. Limits are 250 events and 2 MiB per
page, 50 pages per pass, 10,000 local records and 64 MiB SQLite, 32 KiB message text.
Capacity errors need owner attention, not deletion of unfinished work or cursor
advancement. Completed records are retained for deduplication; no automatic purge.

## Change or stop access

An absent, disabled or invalid policy fails closed. `inbox-configure` writes
`A4A_HOME/inbox-policy.json`. For a reviewed contact change to an existing policy,
`--replace` replaces both entire lists (`allowed_peers` and `allowed_owners`); it
does not append or reset saved cursors. `--allow-owner <64-hex-key>` is optional:
it permits a sender only with a currently valid mandate signed by that owner.
It does not create a shared organization mailbox, and dialogue mode does not yet
support owner-based admission.
Never use it to get past the first-activation preflight. Previously discarded
messages from a newly permitted contact are not automatically recovered.

Contacts and organization mandates are rechecked before claims and notices; revoked pending work becomes
`blocked`. Text already returned to a model cannot be recalled. To stop access,
the owner disables the policy (`enabled: false`) and stops the receiver. A change
to consumer, recipient, relay or notification budget requires an explicit receiver
restart; contact-list changes are reread. Never change another profile's policy.

`--ack-on-receipt` (off by default) makes the receiver send a signed `received` ACK as
soon as a letter from an allowed contact is stored. The sender then sees
`acknowledged` with `ack_status=received` instead of silence while nobody is processing
the mailbox; completing the letter later sends `processed` or `failed`, which replaces
it, and `a4a_delivery_status` on the sender's side reports the upgrade. Strangers never
get a receipt: it would tell them the mailbox exists and is watched. Turning it on or off
requires a receiver restart.

## Notification and host acceptance

Notifications carry only local `consumer`, `pending`, `seq_hint`, never message
text, peer commands or secret keys. Dialogue mode additionally reports
`needs_reconciliation` and `outgoing_prepared`; outbox-only `seq_hint=0` is not an
incoming message to complete. Drain eligible work after a hint; hints are not ACKs.
Unchanged work is quiet on one attachment. Reattachment may reannounce retained
work within the persistent budget, by default once/minute and at most 12/hour.

`notifications` describes only the queried process. CLI status cannot inspect a
channel in another MCP process. States include `disabled`, `invalid_configuration`,
`not_started`, `starting`, `listening`, `source_exhausted`, `stopped`, `failed`.
Even `listening` leaves `host_wake=unverified`. Receiver health and retained hints
do not prove a model turn; readiness has no host-attested acceptance store here.

For a host-approved Claude channel, `A4A_MCP_CHANNEL=claude` keeps transport `stdio`;
the adapter supports Python MCP versions 1.28.1 and 2.1.1 and rejects unknown versions.
This setting alone is not channel approval. Follow the research-preview/allowlist
boundary in safe-connect; do not bypass trust prompts or development restrictions.
A4A announces `claude/channel`; permission relay is not implemented. Permissions
can still stop processing until the owner responds normally in the host.

No universal wake path is established for other hosts. If native tools work but
supported wake has not passed acceptance, report tools-only. Do not add scheduled
empty model turns or alternate channels to cover the gap. Test idle, busy, restart,
duplicate delivery and unknown-sender negative control only with owner-approved
isolated peers. Record correlated IDs and observed results without message contents.
`relay_accepted`, `inner_id`, `outer_id` and `delivery_id` describe transport, not
recipient processing. Preserve uncertainty rather than reporting false success.
