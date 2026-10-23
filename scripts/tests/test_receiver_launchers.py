"""Receiver launchers must load installed code despite untrusted module shadows."""
import configparser
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import venv

import pytest


ROOT = Path(__file__).resolve().parents[2]


def launcher_args(platform):
    receiver = ROOT / "deploy" / "receiver"
    if platform == "systemd":
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(receiver / "a4a-receiver.service", encoding="utf-8")
        return shlex.split(unit["Service"]["ExecStart"])[1:]
    if platform == "launchd":
        return plistlib.loads((receiver / "com.a4a.receiver.plist").read_bytes())["ProgramArguments"][1:]
    script = (receiver / "install-windows.ps1").read_text(encoding="utf-8")
    command = re.search(r'& \$\(Quote \$Python\) (.+?) \*>>', script)
    assert command is not None, "Missing generated receiver invocation"
    return shlex.split(command[1])


def test_systemd_start_limits_are_unit_settings():
    unit = configparser.ConfigParser(interpolation=None, strict=False)
    unit.read(ROOT / "deploy/receiver/a4a-receiver.service", encoding="utf-8")
    assert unit["Unit"]["StartLimitIntervalSec"] == "300"
    assert unit["Unit"]["StartLimitBurst"] == "5"
    assert "StartLimitIntervalSec" not in unit["Service"]
    assert "StartLimitBurst" not in unit["Service"]


@pytest.fixture(scope="module")
def installed_module(tmp_path_factory):
    root = tmp_path_factory.mktemp("receiver-installed-code")
    environment = root / "venv"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site = Path(subprocess.check_output(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True, timeout=30).strip())
    # A harmless installed stand-in records resolution and explicit profile env;
    # the real MCP CLI is additionally exercised in the retained offline probes.
    (site / "a4a_mcp.py").write_text(
        "import json, os\nprint(json.dumps({'installed': True, 'home': os.environ['A4A_HOME']}))\n",
        encoding="utf-8")
    shadow = root / "untrusted"
    shadow.mkdir()
    (shadow / "a4a_mcp.py").write_text("raise SystemExit('untrusted module executed')\n", encoding="utf-8")
    return root, python, shadow


@pytest.mark.parametrize("platform", ["systemd", "launchd", "windows"])
@pytest.mark.parametrize("shadow_source", ["cwd", "pythonpath"])
def test_receiver_uses_installed_module_not_untrusted_shadow(installed_module, platform, shadow_source):
    root, python, shadow = installed_module
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["A4A_HOME"] = str(root / "private-profile")
    if shadow_source == "pythonpath":
        env["PYTHONPATH"] = str(shadow)
    result = subprocess.run(
        [str(python), *launcher_args(platform)],
        cwd=shadow if shadow_source == "cwd" else root,
        env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"installed": True, "home": env["A4A_HOME"]}
