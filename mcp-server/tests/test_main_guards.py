"""Direct negative controls for CLI guards that must fail before side effects."""
import sys

import pytest

from a4a_mcp import __main__ as entry


def test_missing_environment_flag_uses_its_declared_default(monkeypatch):
    monkeypatch.delenv("A4A_SYNTHETIC_FLAG", raising=False)

    assert entry._env_flag("A4A_SYNTHETIC_FLAG", True) is True
    assert entry._env_flag("A4A_SYNTHETIC_FLAG", False) is False


def test_http_without_either_supported_settings_api_fails_loudly(monkeypatch):
    async def rejects_keyword_settings(**_options):
        raise TypeError("synthetic old MCP API")

    entry._load_server()  # Initialize only after the suite installed its boundary.
    monkeypatch.setattr(entry.mcp, "run_streamable_http_async", rejects_keyword_settings)
    monkeypatch.setattr(entry.mcp, "settings", None, raising=False)

    with pytest.raises(RuntimeError, match="accepts HTTP configuration"):
        entry._run_http()


@pytest.mark.parametrize("channel,transport", [("other", "stdio"), ("claude", "http")])
def test_channel_mode_rejects_unsupported_channel_or_transport(
        monkeypatch, channel, transport):
    monkeypatch.setattr(sys, "argv", ["a4a_mcp"])
    monkeypatch.setenv("A4A_MCP_CHANNEL", channel)
    monkeypatch.setenv("A4A_MCP_TRANSPORT", transport)
    entry._load_server()  # Production keeps installer commands import-light.
    monkeypatch.setattr(entry.mcp, "run",
                        lambda **_kwargs: pytest.fail("invalid channel reached MCP runtime"))

    with pytest.raises(SystemExit, match="A4A_MCP_CHANNEL"):
        entry.cli_main()


@pytest.mark.parametrize("days", [0, 366])
def test_issue_mandate_rejects_days_before_loading_any_key(monkeypatch, days):
    from a4a_mcp import identity

    def forbidden():
        pytest.fail("invalid mandate lifetime loaded a private key")

    monkeypatch.setattr(identity, "load_or_create_identity", forbidden)
    monkeypatch.setattr(identity, "load_or_create_owner_identity", forbidden)

    with pytest.raises(ValueError, match="mandate days must be 1..365"):
        entry._admin(["issue-mandate", "--days", str(days)])
