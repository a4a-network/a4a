#!/usr/bin/env bash
# Run offline SDK tests from ANY working directory.
#
# Why this script exists: pytest started at the repository root does not find the
# `tests` package and produces dozens of false import errors. It looks like a regression
# but is only a working-directory artifact. The shell retains its working directory
# across calls, so every new session repeats the mistake. This script changes directory.
#
#   bash scripts/test-sdk.sh              # offline tests (no live relay)
#   bash scripts/test-sdk.sh --live       # include tests against a live relay
#
# Two files (fork_integration and relay_integration) require a running relay
# and are therefore excluded from the default run.
#
# WHY THE INTERPRETER COMES FROM .venv RATHER THAN PATH.
# The system Python does not have the `a4a` package. Tests still appeared green because
# pytest ran inside sdk-python, whose adjacent a4a/ directory entered the import path.
# But the child-crash test launches a process with `-I`, and isolated mode EXCLUDES the
# working directory FROM THE IMPORT PATH. The child still inherits the directory
# (verified: os.getcwd() matches) but sys.path omits it. It then failed with
# ModuleNotFoundError: a4a, reported as `CompletedProcess... returncode 1`, which looked
# like a code defect. test-mcp.sh preferred .venv from the start; only this script
# differed. Verified 2026-09-14.
set -euo pipefail

cd "$(dirname "$0")/../sdk-python"

PY=python
for candidate in .venv/Scripts/python.exe .venv/bin/python ../mcp-server/.venv/Scripts/python.exe; do
    if [[ -x "$candidate" ]]; then PY="$candidate"; break; fi
done

# Resolve absolute paths differently for two distinct cases. A candidate path is relative
# to sdk-python, whereas fallback `python` comes from PATH and is unrelated to this
# directory. Prefixing the latter with pwd would print a nonexistent path.
case "$PY" in
    */*) PY_ABS="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")" ;;
    *)   PY_ABS="$(command -v "$PY" || echo "$PY")" ;;
esac

# Silent package substitution from the working directory hid the defect above. If the
# selected interpreter cannot import `a4a` IN ISOLATION, fail with an explanation rather
# than one opaque red result after ninety seconds.
#
# Print installation advice with ABSOLUTE paths. A relative `pip install -e sdk-python`
# was wrong after the script had already entered sdk-python, and the interpreter path was
# wrong from the repository root. Advice must be safe to paste without adjustment.
if ! "$PY" -I -c "import a4a" 2>/dev/null; then
    printf 'STOP: interpreter cannot import a4a in isolated mode (-I): %s
' "$PY_ABS" >&2
    echo "Tests that spawn an isolated child would report a false code failure." >&2
    printf 'Install the SDK in this environment: "%s" -m pip install -e "%s"
' "$PY_ABS" "$(pwd)" >&2
    exit 2
fi

# This check proves only that the package can be imported. It does not prove the installed
# package matches the working copy and must not be cited as such evidence.

# Forward all arguments. Previously `test-sdk.sh -k name` silently ran the ENTIRE suite,
# making a requested selection appear complete while ignoring it. That is the same class
# of silent failure as working-directory package substitution.
if [[ "${1:-}" == "--live" ]]; then
    shift
    exec "$PY" -m pytest -q --integration "$@"
fi

exec "$PY" -m pytest -q \
    --ignore=tests/test_fork_integration.py \
    --ignore=tests/test_relay_integration.py "$@"
