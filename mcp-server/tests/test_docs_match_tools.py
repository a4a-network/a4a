"""Keep the documented MCP tool inventory synchronized with the implementation.

Onboarding is the first thing an external developer reads and the primary place
where they discover the server's capabilities. A stale list is actively harmful:
an omitted tool looks unavailable, while a phantom tool looks broken.

On 2026-08-29 the inventory grew from 11 to 22 tools in one day and the document
was updated by hand. This check makes subsequent drift visible.
"""
import asyncio
import inspect
import json
import re
import subprocess

from _mcp_compat import is_error
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

ROOT = Path(__file__).resolve().parent.parent.parent
SERVER = ROOT / "mcp-server" / "a4a_mcp" / "server.py"
ONBOARDING = ROOT / "docs" / "onboarding" / "connect-your-agent.md"
README = ROOT / "mcp-server" / "README.md"


def _tools_in_code() -> set[str]:
    return set(re.findall(r"^async def (a4a_\w+)", SERVER.read_text(encoding="utf-8"),
                          re.M))


def _tools_in_doc() -> set[str]:
    return set(re.findall(r"`(a4a_\w+)`", ONBOARDING.read_text(encoding="utf-8")))


def test_every_tool_is_documented():
    missing = sorted(_tools_in_code() - _tools_in_doc())
    assert not missing, (
        f"tools exist in code but are absent from onboarding: {missing}. "
        f"A connected agent cannot discover them")


def test_documentation_does_not_promise_missing_tools():
    """A documented but missing tool is a promise that fails during use."""
    phantom = sorted(_tools_in_doc() - _tools_in_code())
    assert not phantom, f"onboarding names tools that do not exist: {phantom}"


def test_there_is_something_to_compare():
    """Guard against both inventory checks passing vacuously on empty sets."""
    assert len(_tools_in_code()) >= 20, "no tools found in code; comparison is vacuous"
    assert len(_tools_in_doc()) >= 20, "no tools found in docs; comparison is vacuous"


def test_stated_registered_tool_count_matches_reality():
    """Keep the prose claim about registered tools aligned with the inventory."""
    stated = re.search(
        r"(?:registers|\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u0443\u0435\u0442)\s+(\d+)\s+(?:tools?|\u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442\w*)",
        ONBOARDING.read_text(encoding="utf-8"),
        re.I,
    )
    assert stated, "the documented registered-tool count disappeared"
    assert int(stated.group(1)) == len(_tools_in_code()), (
        f"docs state {stated.group(1)}, code contains {len(_tools_in_code())}")


def _stdio_example():
    blocks = re.findall(r"```json\s*\n(.*?)```", README.read_text(encoding="utf-8"), re.S)
    examples = [json.loads(block) for block in blocks]
    return next(example["mcpServers"]["a4a"] for example in examples if "mcpServers" in example)


def test_stdio_example_uses_an_explicit_venv_and_manual_mandate():
    config = _stdio_example()
    assert config["command"] == "<ABSOLUTE_VENV_PYTHON>"
    assert config["args"] == ["-I", "-m", "a4a_mcp"]
    assert config["env"]["A4A_MANDATE_AUTO"] == "0"
    assert config["env"]["A4A_MANDATE_DAYS"] == "1"
    assert config["env"]["A4A_MCP_TRANSPORT"] == "stdio"
    assert config["env"]["A4A_PUBLIC_TEXT"] == "deny"
    assert config["env"]["A4A_HOME"] == "<ABSOLUTE_A4A_HOME>"


@pytest.mark.parametrize("example", ["claude-command", "stdio-json", "owner-command"])
def test_readme_connection_examples_require_an_owner_approved_relay(example):
    expected = "<OWNER_APPROVED_RELAY>"
    text = README.read_text(encoding="utf-8")
    if example == "stdio-json":
        urls = [_stdio_example()["env"]["A4A_RELAY"]]
    elif example == "claude-command":
        urls = re.findall(r'--env "A4A_RELAY=([^"\n]+)"', text)
    else:
        urls = re.findall(r'^\$env:A4A_RELAY\s*=\s*"([^"\n]+)"\s*$', text, re.M)
    assert urls == [expected], f"{example}: use the same explicit relay placeholder"


def test_readme_interpreter_works_outside_the_repository(tmp_path, monkeypatch):
    config = _stdio_example()
    assert config["command"] == "<ABSOLUTE_VENV_PYTHON>"
    config["command"] = sys.executable
    assert Path(config["command"]).is_absolute()
    assert Path(config["command"]).is_file()
    home = tmp_path / "identity"
    unrelated_home = tmp_path / "unrelated-profile"
    monkeypatch.setenv("A4A_HOME", str(unrelated_home))
    # Address and unconfigured status are local; no live relay is needed.
    env = {**get_default_environment(), **config["env"],
           "A4A_HOME": str(home), "HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
           "A4A_RELAY": "ws://127.0.0.1:1"}
    imports = subprocess.run(
        [config["command"], "-I", "-c",
         "import json, sys, a4a, a4a_mcp; from importlib.metadata import version; "
         "print(json.dumps({'isolated': sys.flags.isolated, "
         "'paths': [a4a.__file__, a4a_mcp.__file__], "
         "'versions': [version('a4a-sdk'), version('a4a-mcp')]}))"],
        cwd=tmp_path, env=env, text=True, encoding="utf-8", capture_output=True, timeout=30)
    assert imports.returncode == 0, imports.stderr
    installed = json.loads(imports.stdout)
    assert installed["isolated"] == 1
    assert all(installed["versions"]), "Both distributions must be installed"
    assert all(Path(path).is_file() and not Path(path).is_relative_to(tmp_path)
               for path in installed["paths"])
    assert not home.exists(), "Imports must not create an identity"
    result = subprocess.run([config["command"], *config["args"], "address"], cwd=tmp_path,
                            env=env, text=True, encoding="utf-8", capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    address = re.search(r"(?m)^pubkey \(hex\): ([0-9a-f]{64})$", result.stdout)
    assert address, result.stdout
    identity_file = home / "identity.json"
    identity_before = identity_file.read_bytes()

    async def check_tools():
        parameters = StdioServerParameters(command=config["command"], args=config["args"],
                                           env=env, cwd=str(tmp_path))
        async with asyncio.timeout(30):
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    assert {tool.name for tool in listed.tools} == _tools_in_code()
                    current = await session.call_tool("a4a_my_address", {})
                    assert not is_error(current)
                    text = "\n".join(item.text for item in current.content if item.type == "text")
                    assert address[1] in text and env["A4A_RELAY"] in text
                    status = await session.call_tool("a4a_inbox_status", {})
                    assert not is_error(status)

    asyncio.run(check_tools())
    assert identity_file.read_bytes() == identity_before
    assert not (home / "inbox-policy.json").exists()
    assert not (tmp_path / ".a4a").exists()
    assert not unrelated_home.exists(), "Do not inherit an ambient profile"


def test_local_relay_advice_names_the_separate_header_source():
    text = README.read_text(encoding="utf-8")
    before_http = text.split("## Connect over HTTP", 1)[0]
    assert "A4A_HEADERS_URL" in before_http and "https://blockstream.info/api" in before_http
    assert "a4a_check_authority" in before_http


def test_private_send_argument_example_matches_tool_signature():
    from a4a_mcp import server

    section = README.read_text(encoding="utf-8").split("### Private Send Arguments", 1)[1]
    block = re.search(r"```json\s*\n(.*?)```", section, re.S)
    assert block, "private send arguments must have a JSON example"
    arguments = json.loads(block.group(1))
    assert set(arguments) == {"to_pubkey", "text", "new_letter"}
    assert arguments["new_letter"] is True, "reliable delivery must declare new-letter intent"
    inspect.signature(server.a4a_deliver).bind(**arguments)
    assert "For `a4a_send_private`, omit `new_letter`." in section
    private_arguments = {key: value for key, value in arguments.items() if key != "new_letter"}
    assert set(private_arguments) == {"to_pubkey", "text"}
    inspect.signature(server.a4a_send_private).bind(**private_arguments)
