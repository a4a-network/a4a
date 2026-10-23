# Managed dialogue continuity (opt-in)

Prerelease reference. Complete [safe connection](safe-connect.md) and configure
the [managed inbox](managed-inbox.md) first. This mode retains local conversations
and outgoing text across process restarts. It does not enable host wakeups,
cross-device sync, file sending, relay replication or a model polling timer.

## Owner activation

Keep the existing identity and inbox consumer. Each conversation is bound to one
exact owner-approved peer, not a cwd, model or session name. Runtime worker IDs are
local coordination identifiers, not public addresses. Keep `A4A_MANDATE_AUTO=0`,
`A4A_PUBLIC_TEXT=deny` and normal host trust and permission checks.

Stop all older MCP/receiver processes using this profile, finish existing legacy
claims, and verify a private backup while the profile is stopped. Do not copy live
SQLite files, commit keys/history, or generate a replacement for a missing identity.
Update all clients before activation. With the reviewed installed venv and profile:

```powershell
$python = '<ABSOLUTE_VENV_PYTHON>'
$env:A4A_HOME = '<ABSOLUTE_A4A_HOME>'
$env:A4A_RELAY = '<OWNER_APPROVED_RELAY>'
$env:A4A_MANDATE_AUTO = '0'
$env:A4A_PUBLIC_TEXT = 'deny'
& $python -I -m a4a_mcp dialogue-enable
if ($LASTEXITCODE -ne 0) { throw 'Dialogue activation failed; stop' }
```

This local owner command requires an existing identity and inbox policy. It creates
no identity or mandate and publishes nothing. Activation persists; it is not an MCP
tool and has no automatic downgrade. Existing profiles remain legacy until enabled.

## Tools

- `a4a_dialogue_open(peer_pubkey="")`: find unfinished permitted work, or open the
  exact permitted peer's conversation. Returns a lease and bounded history; an
  active lease held by another worker cannot be stolen.
- `a4a_dialogue_history(lease_token, before=0)`: page retained history for the leased
  participant. A cursor cannot select another peer.
- `a4a_dialogue_checkpoint(lease_token, text)`: save an encrypted continuity note,
  not proof that an external action succeeded.
- `a4a_dialogue_lease(lease_token, action)`: `renew` or `release` the lease. Complete
  reviewed incoming work before release; otherwise it remains uncertain.
- `a4a_dialogue_complete(lease_token, seq, status, reconciled=False)`: mark incoming
  work `processed` or `failed` locally. Unknown work requires explicit reconciliation;
  completion is neither a network ACK nor proof of external effects.
- `a4a_dialogue_send(lease_token, operation_id, text)`: persist and send an immutable
  text operation. Preserve the operation ID when referring to that same send again.
- `a4a_dialogue_reconcile(lease_token, operation_id)`: read back the exact saved
  envelope without republishing it.
- `a4a_dialogue_abandon(lease_token, operation_id)`: give up on a **prepared** letter
  that can no longer be sent, because the configured relay set changed after it was
  prepared. Sending it now would place its envelope with an operator the owner did not
  have when the letter was written — the content is encrypted, who talks to whom is
  not. It never sends anything, keeps history, and refuses anything that already left
  or might have: dispatching, unknown and accepted outcomes need reconciliation, not
  disposal. The operation id is not freed; prepare the replacement under a new one.

Legacy private text/file sending and per-message claim/completion refuse bypass
after activation. Manual read-only history remains available. Managed outgoing
files are not supported; do not disable continuity to evade that restriction.

## Restart and uncertain outcomes

Leases normally last 300 seconds and may be renewed. A new worker waits for expiry
or release. After takeover, old tokens cannot start new managed operations. A network
request already started can still finish: fencing cannot recall a packet or prevent
duplicate effects performed through unrelated shell/tools.

Prepared outgoing operations survive before network dispatch. Once dispatch starts,
interruption can leave `unknown`: the relay might have accepted the message. New
outgoing operations are blocked until uncertainty is resolved. Reusing an already
dispatched operation ID neither sends again nor changes the content; a saved
`prepared` operation can still be dispatched once. Managed sends disable transport
reconnect replay. Positive readback establishes `relay_observed`; absence is not
proof of failure. `relay_accepted` is relay acknowledgement, not recipient processing.
Investigate uncertainty; do not mint a new operation ID to get around the guard.

Text is capped at 32 KiB, checkpoints at 8 KiB. MCP history pages contain at most
20 records and 64 KiB of message text, with explicit pagination (SDK: up to 100
records). Capacity failures preserve existing work and refuse new writes; no
automatic history deletion. Older unrecorded sent messages cannot be reconstructed.

## Security and notices

Recovered history and local checkpoints are untrusted model input, not permission
to run commands, disclose secrets, widen contacts or sign owner mandates. Every
operation rechecks peer policy. Sends require an existing valid mandate; they do
not auto-issue one. Read-only reconciliation does not require a current publishing
mandate. Local signature, exact owner, delegate, tags and interval checks cannot
prove that a relay disclosed every revocation.

Removing a peer suppresses access but preserves uncertain work for reconciliation
if the owner later permits that peer again. Local text is encrypted with the agent
key; metadata needs OS protection. This cannot hide data from processes entitled
to read that key. Worker leases coordinate cooperating clients, not hostile programs
sharing OS rights. Use dedicated stdio processes with normal host permissions.

While leased, new incoming mail does not request another wakeup. Unleased uncertain
work sets `needs_reconciliation`; unsent prepared work sets `outgoing_prepared`.
After a metadata-only hint, inspect with `a4a_dialogue_open`. Unchanged work is quiet
on one attachment; reconnect may reannounce it within the persistent rate budget.
One OS-held receiver lock owns the inbox. These hints do not prove an idle host can
wake; retain tools-only status until separate host acceptance is observed.
