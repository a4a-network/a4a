#!/usr/bin/env bash
# Run MCP server tests from ANY working directory.
#
# System Python cannot import `a4a`, so use mcp-server/.venv, which contains both
# `a4a-sdk` and `mcp`. If pytest is absent from the venv:
# .venv/Scripts/python.exe -m pip install "pytest>=8" "pytest-asyncio>=0.23"
#
#   bash scripts/test-mcp.sh
set -euo pipefail

cd "$(dirname "$0")/../mcp-server"

if [[ -x .venv/Scripts/python.exe ]]; then       # Windows
    exec .venv/Scripts/python.exe -m pytest -q "$@"
elif [[ -x .venv/bin/python ]]; then             # POSIX
    exec .venv/bin/python -m pytest -q "$@"
fi

# A contributor following the README may have installed everything in one venv and have
# no mcp-server/.venv. Fall back to PATH; pytest will report any missing packages.
if command -v python >/dev/null 2>&1; then
    echo "mcp-server/.venv is absent; using Python from PATH: $(command -v python)" >&2
    exec python -m pytest -q "$@"
fi
echo "no interpreter found in mcp-server/.venv or PATH; create an environment (uv sync / python -m venv)" >&2
exit 1
