#!/usr/bin/env bash
# Run project-agent tests from ANY working directory.
#
# Use agent-service/.venv because system Python has neither `a4a` nor pytest.
# If the environment does not exist, create it with:
#   python -m venv agent-service/.venv
#   agent-service/.venv/Scripts/python.exe -m pip install -e sdk-python \
#       pytest pytest-asyncio httpx
#
#   bash scripts/test-agent.sh
set -euo pipefail

cd "$(dirname "$0")/../agent-service"

if [[ -x .venv/Scripts/python.exe ]]; then       # Windows
    exec .venv/Scripts/python.exe -m pytest -q "$@"
elif [[ -x .venv/bin/python ]]; then             # POSIX
    exec .venv/bin/python -m pytest -q "$@"
fi

echo "no interpreter found in agent-service/.venv; create the environment" >&2
exit 1
