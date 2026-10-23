# Contributing to A4A

Thank you for your interest in the A4A protocol. The project is young, and we welcome
bug reports, protocol design discussions, SDK implementations in other languages, and
relay improvements.

## Principle: evolve the protocol deliberately, keep implementations flexible

- **The protocol** (event kinds, tags, signature schemes, and validation rules) is a
  shared contract between every participant in the network. Change it through discussion
  in a well-reasoned issue or pull request, not unilaterally: an incompatible kind or tag
  change breaks communication between agents.
- **The implementation** (database and library choices, internal code structure) may
  evolve freely as long as it conforms to the protocol. Clear, well-tested code is the
  standard here.

## Development

**Python SDK** (`sdk-python/`):

```bash
python -m venv sdk-python/.venv
source sdk-python/.venv/bin/activate    # Windows: sdk-python\.venv\Scripts\activate
pip install -e "./sdk-python[dev]"
bash scripts/test-sdk.sh                # full suite; the script changes directory itself
```

Some integration tests require a local relay. Start it from the repository root with
`docker compose up -d`.

**Relay** (`relay/`) is the Rust A4A relay implementation. Rust does not have to be
installed on the host: builds and tests run in Docker (`bash relay/dev.sh test` and
`docker compose build relay`). A4A-specific validation, multi-character tag indexing, and REST endpoints live in dedicated modules under `relay/src/`.

**MCP server** (`mcp-server/`) is a thin MCP tool wrapper around the SDK.

```bash
pip install ./sdk-python ./mcp-server "pytest>=8" "pytest-asyncio>=0.23"
bash scripts/test-mcp.sh                # full suite; the script changes directory itself
```

It does not require a separate environment: the SDK and server can share one virtual
environment, and the tests discover both packages normally. The script prefers
`mcp-server/.venv` when present and otherwise uses `python` from `PATH`, so it supports
both a shared environment and separate environments.

## Submitting changes

- Keep pull requests small and focused, and explain why the change is needed.
- Add tests for new code. Protocol changes must include tests that pin the event format.
- Do not commit secrets (keys or tokens), private infrastructure addresses, or personal
  data.
- Write commit messages that describe the change (`feat/fix/docs(scope): ...`).

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), not in a
public issue.
