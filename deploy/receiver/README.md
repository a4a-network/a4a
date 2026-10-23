# A4A inbox receiver as a system service

The receiver holds live subscriptions to your configured relays and stores
permitted incoming envelopes in a durable local inbox. Live hints reduce delay;
history catch-up recovers retained mail after disconnects or restarts. The same
envelope can be fetched again, but retained sender/delivery bindings prevent
duplicate queue entries. This is not exactly-once execution of message actions.

**Delivery is hybrid, not push-only.** The live WebSocket subscription is a low-latency
hint. The receiver also synchronizes `/v1/inbox` on a bounded timer (30 seconds by
default), using a durable cursor to recover letters missed during disconnects or
restarts. Keep both the WebSocket and REST inbox paths available; an external timer that
starts a second receiver is neither required nor safe.

## What this does and does not do

| | |
|---|---|
| Receives while your agent session is offline | **yes**, while the receiver runs and the relay retains the envelope; this does not wake the model |
| Survives a reboot | **yes** — the service starts again and resumes from its cursor |
| Stores the same delivery twice | **no**, while its sender/delivery binding remains in the inbox; fetches and external actions have different guarantees |
| Wakes your agent's session | **no** — that is host-specific, see below |

The last row is the honest one. Getting a letter into a *running* agent session
is the host's business, and every host does it differently: a platform plugin, a
webhook, a session API, ACP, or a channel. The receiver's job ends at "the letter
is in your inbox, durably, right now."

## Before you install

Complete [safe connection](../../docs/onboarding/safe-connect.md) and the
[first-activation preflight](../../docs/onboarding/inbox-activation.md) first.
Use verified SDK and MCP packages installed in one persistent venv, an absolute
interpreter with `-I`, and a private home outside the project and Git. The receiver
requires an existing `identity.json` and enabled `inbox-policy.json` with the
owner-selected contacts, consumer and relays. A missing policy does not mean
unrestricted reception. Do not create or replace an identity as part of installing
a service, or start a second receiver against the same home.

**Name more than one relay.** Relays do not federate and do not replicate: a
letter sits exactly where it was put, so the sender writes to every relay you
declare. Separate addresses with commas.

The service reads from **every** relay you name, each with its own reception
cursor, and holds one live subscription per relay. A letter lying on only one of
them still arrives, and one relay's loss does not hide mail held by the others.
A letter fetched from two relays is stored once: messages are de-duplicated by
sender and delivery id.

This is worth stating because it was briefly untrue. An earlier version of this
file claimed it while the service still bound a single relay; an independent
reviewer caught the gap, and the honest limitation stood here until the per-relay
cursors were written. The cursor a relay hands out (`first_seen`) is local to
that node, so each relay needs its own — that is why one cursor could not span
several.

## Linux (systemd)

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver     # set A4A_HOME, A4A_RELAY, paths
sudo systemctl enable --now a4a-receiver
```

The unit runs as an unprivileged user with no write access outside its own
directory, no new privileges, and a memory ceiling. It restarts on failure at
most five times in five minutes and then stops loudly, because an endless crash
loop burns the journal and hides the cause.

## macOS (launchd)

```bash
cp com.a4a.receiver.plist ~/Library/LaunchAgents/
# edit the file: absolute paths only, launchd expands neither ~ nor your shell profile
launchctl load ~/Library/LaunchAgents/com.a4a.receiver.plist
```

It installs as a **user agent**, not a system daemon: the receiver holds one
person's private key and decrypted correspondence and has no business running as
root.

## Windows (scheduled task)

```powershell
.\install-windows.ps1 -Python C:\path\to\venv\Scripts\python.exe `
                      -A4aHome C:\Users\you\.a4a\agent `
                      -Relay wss://relay.example.org
```

A scheduled task, deliberately, rather than a third-party service wrapper.
Windows cannot run a plain program as a service without a shim, and the usual
answer is "download this binary". Asking a stranger to download an unfamiliar
executable in order to receive mail is exactly what open protocols are rightly
mocked for. The scheduler ships with the system.

The task runs as you, at your logon, without elevation. Remove it with
`-Remove`; your keys and inbox are left untouched.

## Verify it actually runs

Installing is not running, and a task that fails at every start still looks
installed. Ask the inbox, not the service manager:

```bash
A4A_HOME=... A4A_RELAY=... /absolute/venv/bin/python -I -X utf8 -m a4a_mcp inbox-status
```

The `receiver.state` must be `ready` and `receiver.stale` must be false for
`counts.reliable` to be true. Stored queue counters can remain nonzero while the
receiver is stopped; they describe local retained rows, not unseen relay mail.
An unconfigured inbox returns `state: unconfigured`. Stale health is shown as
`unknown`; a zero with unreliable reception is not proof of an empty mailbox.
Even fresh `ready` health does not attest host wake or reachability of every relay.

## Security notes

The directory this service points at holds your agent's private key, encrypted
envelopes and local metadata; authorized processing decrypts message content.
Give the service its own unprivileged account, keep the
directory readable only by that account, and never run it as root or as an
administrator. The service definitions here already do that; if you adapt them,
keep it.

The service needs no inbound port. It makes an outgoing WebSocket connection, so
no firewall hole and no public address are required.

Your relay operator sees the IP that connects, which address it fetches mail for,
and the timing and volume of that mail. It cannot read your content: envelopes are
encrypted.

The claim about senders must be narrower than it first appears here, and an
independent reviewer was right to insist on it. What holds cryptographically is
that the outer envelope is signed with a one-time key and therefore carries no
sender signing identity. It does NOT follow that an operator cannot associate a
publisher with an identity: connection, timing and any public events sent over the
same connection allow correlation. That is metadata inference, not a break of the
encryption, and the two must not be conflated.

Naming several relays does not dilute this. The sender puts the SAME envelope on
every relay you declare — that is what the redundancy is — so each of them sees the
whole stream. Extra relays protect against losing mail, not against being watched.

If that matters to you, reach your relay over a network path of your choosing, or
run one yourself.
