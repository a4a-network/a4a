# Optional owner-key separation

Prerelease local storage hardening, not a new identity, hardware signer, recovery
service or account-sale defense. Start with [safe connection](safe-connect.md).
No profile migrates automatically; legacy profiles keep their existing behavior.

## Before migration

- Use an existing profile with distinct agent and owner keys and a matching public
  owner binding. This command does not initialize a new owner.
- Stop all MCP/receiver processes using the profile. Older processes do not reload
  code or join the new writer lock and may retain plaintext secrets in memory.
- Verify a private backup while the profile is stopped. The backup still contains
  plaintext keys; protect it outside Git, chat and cloud-synced folders.
- Select an existing private directory outside `A4A_HOME` and every repository or
  cloud-synced folder. The vault must be a NEW absolute file path with no links or
  reparse points. Prefer offline/removable storage unavailable to the agent except
  during this explicit owner operation. Keep `A4A_MANDATE_AUTO=0`.

## Owner commands

Use the owner's interactive terminal and the verified installed venv interpreter.
These placeholders are not working profile paths. Never pass a passphrase through
the model, command arguments, environment variables or scripts.

```powershell
$python = '<ABSOLUTE_VENV_PYTHON>'
$env:A4A_HOME = '<ABSOLUTE_A4A_HOME>'
$env:A4A_MANDATE_AUTO = '0'
$env:A4A_PUBLIC_TEXT = 'deny'
& $python -I -m a4a_mcp owner-separate --owner-file '<NEW_ABSOLUTE_OWNER_VAULT_FILE>'
if ($LASTEXITCODE -ne 0) { throw 'Separation failed; inspect retained state before retry' }
```

Enter and confirm a strong unique random passphrase, at least 16 normalized
characters; length alone is not entropy. Piped input and iasecure echoing fallback
are refused. Store the passphrase separately in a password manager or protected
offline record. No password-reset service exists; loss can make the vault unrecoverable.

The command writes an encrypted vault, authenticates a readback, then atomically
replaces `identity.json` without `owner_privkey_hex`. It preserves the agent secret,
both public keys and unrelated metadata; it never publishes or overwrites an
existing vault. After failure/interruption, retain any created vault and inspect
the source. Retry with a new destination only if the original still contains the
owner key. Do not assume a partial vault is valid or delete the working profile.
Filesystem/hardware failure can still require backup recovery.

Subsequent mandate issuance is a separate owner-approved publishing action. With
the same profile and interpreter and the vault created above:

```powershell
$env:A4A_RELAY = '<OWNER_APPROVED_RELAY>'
& $python -I -m a4a_mcp issue-mandate --owner-file '<ABSOLUTE_OWNER_VAULT_FILE>' --days 1
if ($LASTEXITCODE -ne 0) { throw 'Mandate issuance failed; stop' }
```

Unlike separation, issue-mandate **publishes an owner-signed event** (or reuses an
eligible existing mandate). It prompts once, verifies the vault matches the profile
and uses the owner key only in that CLI process. The relay must be explicitly chosen:
normal TLS for `wss://`, loopback only for a local `ws://` test. An unmigrated legacy
profile's command without `--owner-file` can load/create a co-located owner key; a
migrated profile refuses that path and automatic registration. Restart updated MCP
processes after migration. Valid existing mandates need only the public owner binding;
ordinary MCP calls do not unlock the vault. Never bypass normal host permissions.

## Format and limits

Version 1 uses Scrypt (N=131072, r=8, p=1, 32-byte derived key, roughly 128 MiB per
operation) and AES-256-GCM with a random 16-byte salt and 12-byte nonce. Authenticated
metadata binds version, algorithm and owner public key; binary fields use canonical
base64. Passwords use NFKC normalization, at most 1024 UTF-8 bytes afterward. This is
an A4A local format, **not encrypted-key**. A stolen vault permits offline password guesses.

ACLs are checked before secret-bearing temporary writes. The same OS user, an
administrator or a compromised terminal can still access keys during unlock; Python
cannot guarantee zeroization. Old plaintext backups, snapshots and running processes
are not erased. The vault alone cannot recover the agent's address, private-message
keys, conversation history or inbox policy: protect and test those backups separately.
Migration adds no wakeup, model polling, cross-device handoff or reputation transfer.
