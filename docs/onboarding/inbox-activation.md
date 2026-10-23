# First activation of an existing identity's inbox

Prerelease reference, not an installer. Complete [safe connection](safe-connect.md)
first: verified installed SDK and MCP in one venv, an absolute interpreter with
`-I`, normal host permissions, and a permanent private `A4A_HOME` outside Git and
the project. This procedure does not create an identity, issue a mandate, start a
receiver, or establish host wake support. New identity creation needs separate
owner approval; a missing existing identity must be restored, not replaced.

The owner chooses the exact contacts and relay: `wss://` with normal TLS checks,
or `ws://` on loopback for an isolated local test. Keep `A4A_MANDATE_AUTO=0` and
`A4A_PUBLIC_TEXT=deny`. No publication, new contacts, permission bypass or model
polling is authorized by this guide. Incoming text remains untrusted.

## FIRST-ACTIVATION only

Stop all processes using this profile and exclude concurrent configuration or
receiver startup throughout this operation. The preflight is not a race lock.
Replace every `<...>` below with a reviewed value. `project-a` is a generic durable
consumer name; use the installation's agreed consumer. A different identity in
`project-b` needs its own private home and consumer, never a copied working home.
Public keys must be exactly 64 lowercase hex characters, selected by the owner.

Any entry named `inbox-policy.json` OR `inbox` stops this procedure, including an
empty directory, broken link or junction. Enumerate entry names without following
their contents or link targets; unreadable directories also stop the operation.
Do not remove, rename or replace existing state to make this example run.

```powershell
$python = '<ABSOLUTE_VENV_PYTHON>'
$env:A4A_HOME = '<ABSOLUTE_A4A_HOME>'
$env:A4A_RELAY = '<OWNER_APPROVED_RELAY>'
$env:A4A_MANDATE_AUTO = '0'
$env:A4A_PUBLIC_TEXT = 'deny'
$expectedPubkey = '<EXPECTED_EXISTING_AGENT_PUBKEY>'
$allowedPeer = '<OWNER_APPROVED_PEER_PUBKEY>'
if ($expectedPubkey -cnotmatch '^[0-9a-f]{64}$' -or $allowedPeer -cnotmatch '^[0-9a-f]{64}$') { throw 'Exact owner-approved keys required; stop' }
$existingInbox = @(Get-ChildItem -LiteralPath $env:A4A_HOME -Force -ErrorAction Stop |
    Where-Object { $_.Name -in @('inbox-policy.json', 'inbox') })
if ($existingInbox.Count -ne 0) { throw 'FIRST-ACTIVATION: existing inbox state; stop for manual reconciliation' }
if (-not (Test-Path -LiteralPath "$env:A4A_HOME/identity.json" -PathType Leaf)) { throw 'Existing identity missing; stop' }
$address = (& $python -I -m a4a_mcp address) -join "`n"
if ($LASTEXITCODE -ne 0 -or $address -cnotmatch ('(?m)^pubkey \(hex\): ' + [regex]::Escape($expectedPubkey) + '$')) { throw 'Existing address mismatch; stop' }
& $python -I -m a4a_mcp inbox-configure --consumer project-a --allow-peer $allowedPeer
if ($LASTEXITCODE -ne 0) { throw 'Inbox configuration failed; stop' }
& $python -I -m a4a_mcp inbox-status
if ($LASTEXITCODE -ne 0) { throw 'Inbox status unavailable; stop' }
```

Repeat `--allow-peer` only for additional exact owner-approved contacts. Omitting
it creates an empty allowlist, not wildcard access. A successful status call must
not mask a failed configuration command. Configuration grants no publishing
mandate and does not renew one. Expiry requires the owner's separate decision.

### Existing queue: stop

If preflight finds a policy or `inbox`, do not continue FIRST-ACTIVATION. Arrange a
separate, manual **read-only** reconciliation with the owner: inspect the policy
(`recipient`, `consumer`, `relay`, `allowed_peers`, `start_after`), queue `metadata`
(`schema`, `recipient`, `consumer`, and `receiver` state), message states (`pending`,
`processing`, `unknown`, and completed), the saved cursor in `cursors` (`relay`, `stamp`,
`event_id`), and its relationship to relay history.
Do not read message contents for this reconciliation. An empty directory, a link, or
unavailable metadata also means stop; it is not permission to recreate the queue.
Do not reset the cursor or states, delete the policy/directory/database, rename anything
to bypass preflight, or apply `--replace`. Resuming an existing queue requires separate
approval after state-preserving reconciliation, not a repeat of this block.

### The `first_seen` boundary

Without `--start-after`, `inbox-configure` writes `int(time.time())` to the policy: the
whole Unix second from the local clock at configuration time. This starting point is used
only when creating a new queue cursor for a relay; an existing cursor and `pending` messages
are preserved. Therefore, omitting the flag alone **does not guarantee that old mail is
excluded**, even if the policy file was absent but the queue remained.

The boundary applies to `first_seen` (the relay's event receipt time), not the message's
`created_at`. The initial cursor `(start_after, "")` selects `(first_seen, event ID)` pairs
strictly greater than itself, so it includes events received **during the same second**,
including events received shortly before the configuration command. This is not a precise
consent-instant boundary. The relay returns completed seconds; events from the current second
become available later. Before activation, compare participant and relay clocks, and do not
promise local-time exclusion when clocks disagree.

A relay migration must preserve `first_seen` for old events, not only their IDs: IDs alone
cannot preserve the boundary and saved cursor. Reimporting with a new `first_seen` can present
old mail as new. If preservation of `(event ID, first_seen)` pairs is not confirmed, stop for
manual reconciliation; do not bypass the discrepancy by resetting the cursor or configuring
the inbox again.

## Next step

Use the [managed inbox reference](managed-inbox.md) for receiver operation,
local claim/completion and acceptance limits. A configured policy alone is not
automatic delivery. Verify native tools in the intended host before reporting
tools-only; wake remains unverified until the separate idle/busy/restart tests pass.
