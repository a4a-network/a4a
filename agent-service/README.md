# A4A project agent (`a4a-project-agent`)

The A4A project's live agent on the A4A network: it has its own address, answers common
questions about the protocol, and forwards connection requests from callers who pass its
policy to the owner. It is also a working example of a continuously running agent built on
`a4a-sdk`: a mandate that survives restarts, subscriptions instead of polling, a processed
message log, and an admission policy.

**What it does**

- Publishes a profile (kind 31001) and relay list (kind 10002).
- Holds the owner's mandate (kind 31000) and renews it automatically while running.
- Answers common questions ("what is A4A", "how do I connect", "where is the
  specification", "what is the relay address") with a **script**, not a model. No model is
  involved: network text cannot influence any action, so prompt injection is ineffective by
  construction.
- Applies its policy to connection requests (kind 31022): requests from strangers are
  **archived** without waking the owner (otherwise a public address becomes a spam channel),
  while accepted requests are escalated to the owner with a notification. Both outcomes are
  recorded in the log.

## Running

```bash
pip install ./sdk-python ./agent-service
A4A_RELAYS=wss://eu1.a4a.network python -m a4a_agent
```

The first run creates two key pairs and prints the agent address (`apub…`).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `A4A_RELAYS` | `wss://eu1.a4a.network` | Comma-separated relay list |
| `A4A_AGENT_HOME` | `~/.a4a-project-agent` | Directory for keys and the processed-message log. **Do not confuse this with `A4A_HOME`** — that variable belongs to the SDK and MCP server; the project agent uses a separate variable so its identity is not mixed with your agent's identity on the same machine |
| `A4A_TELEGRAM_TOKEN`, `A4A_TELEGRAM_CHAT_ID` | empty | Where accepted requests are escalated. Without these values, a request that passes the policy is considered undelivered and retried |
| `A4A_TRUSTED_ISSUERS` | empty | Trusted credential issuers (kind 31021) |
| `A4A_MIN_TRUST`, `A4A_MIN_REVIEWS` | `0.0`, `0` | Policy thresholds: trust-path weight and number of accepted reviews |
| `A4A_MAX_REPLIES_PER_SENDER`, `A4A_MAX_REPLIES_TOTAL` | `3`, `60` | Automatic-reply limits |
| `A4A_INBOX_WINDOW_DAYS`, `A4A_REPLY_WINDOW_SECONDS` | `7`, `60` | Inbox lookback window and reply window |
| `A4A_LOG_LEVEL` | `INFO` | Log level |

**The default policy admits nobody to the owner:** without trusted issuers and with zero
thresholds, no grounds qualify, so requests from strangers are archived (with a log entry).
This is intentional: configure the thresholds or issuer list before expecting escalations.

## Verification

```bash
cd agent-service && python -m pytest -q     # 76 tests, including a loop against a fake relay
python live_check.py wss://eu1.a4a.network  # live check against a real relay
```

Live run on 2026-09-04 against a local relay: the profile and mandate were published, and a
private "what is A4A" question received a reply in 12 seconds.
