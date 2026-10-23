"""The live test launcher must actually opt in to integration tests."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


def launch(tmp_path, *arguments):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("the SDK test launcher requires bash")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "test-sdk.sh").write_bytes((ROOT / "scripts/test-sdk.sh").read_bytes())
    interpreter = tmp_path / "sdk-python/.venv/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text(
        '#!/usr/bin/env bash\n'
        'if [[ "${1:-}" == "-I" ]]; then exit 0; fi\n'
        'printf "%s\\n" "$@"\n', encoding="utf-8", newline="\n")
    interpreter.chmod(0o755)
    result = subprocess.run(  # unguarded-launch: fixture-owned shell and echo-only interpreter; no product Python is executed
        [bash, "scripts/test-sdk.sh", *arguments], cwd=tmp_path,
        env=dict(os.environ), capture_output=True, text=True, check=True,
    )
    return result.stdout.splitlines()


def test_live_launcher_enables_integration_and_forwards_selection(tmp_path):
    arguments = launch(tmp_path, "--live", "-k", "selected_case")
    assert arguments == ["-m", "pytest", "-q", "--integration", "-k", "selected_case"]


def test_offline_launcher_keeps_integration_opt_in(tmp_path):
    arguments = launch(tmp_path, "-k", "selected_case")
    assert "--integration" not in arguments
    assert arguments[-2:] == ["-k", "selected_case"]
    assert "--ignore=tests/test_fork_integration.py" in arguments
    assert "--ignore=tests/test_relay_trust.py" not in arguments
