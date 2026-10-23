"""Local connection plans and conservative readiness, never installation or consent."""
import ipaddress
import json
import math
from decimal import Decimal
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit


def _plain(value):
    return (type(value) is str and 0 < len(value) <= 4096 and value.isprintable()
            and "${" not in value)


def _absolute(value, field):
    if not _plain(value):
        raise ValueError(f"{field} must be an explicit absolute local path without interpolation")
    path = Path(value)
    if (value.replace("\\", "/").startswith("//")
            or path.anchor.replace("\\", "/").startswith("//")
            or not path.is_absolute() or ".." in path.parts):
        raise ValueError(f"{field} must be an explicit absolute local path without interpolation")
    return path


def _relay(value):
    error = "relay must use wss or numeric loopback ws, without credentials, query or fragment"
    if not _plain(value) or any(c.isspace() or c == "\\" for c in value):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"ws", "wss"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.netloc.endswith(":")):
            raise ValueError(error)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError(error)
        if parsed.scheme == "ws" and not ipaddress.ip_address(parsed.hostname).is_loopback:
            raise ValueError(error)
    except ValueError:
        raise ValueError(error) from None
    return value


def _host_config(client, project, entry):
    """Serialize project-local configuration, without reading or writing settings."""
    if client == "codex":
        # JSON basic strings are also TOML basic strings for these printable inputs.
        # Keep Unicode literal: JSON surrogate pairs are not valid TOML escapes.
        quote = lambda value: json.dumps(value, ensure_ascii=False)
        content = ("[mcp_servers.a4a]\ncommand = " + quote(entry["command"])
                   + "\nargs = " + quote(entry["args"]) + "\n\n[mcp_servers.a4a.env]\n"
                   + "".join(f"{key} = {quote(value)}\n" for key, value in entry["env"].items()))
        path, format_name = project / ".codex/config.toml", "toml"
    elif client == "cursor":
        content = json.dumps({"mcpServers": {"a4a": {"type": "stdio", **entry}}},
                             ensure_ascii=False, indent=2) + "\n"
        path, format_name = project / ".cursor/mcp.json", "json"
    elif client in {"kimi", "kimi-code"}:
        content = json.dumps({"mcpServers": {"a4a": entry}},
                             ensure_ascii=False, indent=2) + "\n"
        path, format_name = project / ".kimi-code/mcp.json", "json"
    elif client in {"gemini", "antigravity", "agy"}:
        content = json.dumps({"mcpServers": {"a4a": entry}},
                             ensure_ascii=False, indent=2) + "\n"
        path, format_name = project / ".mcp.json", "json"
    else:
        return None
    return {"path": str(path), "format": format_name, "content": content,
            "scope": "project", "operation": "merge_missing_a4a_only",
            "requires_project_trust": client == "codex"}


def merge_host_config(plan, existing_text):
    """Return a proposal preserving other settings; never read or write a file.

    Refuse a conflicting A4A entry, duplicate JSON keys or a configuration that
    cannot be parsed losslessly. The caller owns backup, review and applying the
    proposal with normal host permissions; this function never grants consent.
    """
    configuration = plan.get("host_configuration")
    if not configuration or type(existing_text) is not str or len(existing_text) > 2 * 1024 * 1024:
        raise ValueError("a supported project configuration and bounded text are required")
    client = plan["client"]
    desired = plan["mcp_server"]
    if client == "cursor":
        desired = {"type": "stdio", **desired}

    try:
        if client == "codex":
            document = tomllib.loads(existing_text)
            servers = document.get("mcp_servers", {})
        else:
            document = validate_json_config(existing_text)
            if type(document) is not dict:
                raise ValueError("configuration must be an object")
            servers = document.get("mcpServers", {})
        if type(servers) is not dict:
            raise ValueError("MCP servers must be an object")
        if "a4a" in servers:
            if servers["a4a"] != desired:
                raise ValueError("existing A4A entry differs; reconcile it without replacing identity")
            return existing_text
        if client == "codex":
            proposal = existing_text + ("\n\n" if existing_text else "") + configuration["content"]
            tomllib.loads(proposal)  # Inline/sealed tables may prevent safe append.
            return proposal
        document["mcpServers"] = {**servers, "a4a": desired}
        return json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("configuration is not valid for a preserving merge") from exc


def validate_json_config(text):
    """Parse strict JSON without changing any numeric value or duplicate field."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate configuration key')
            result[key] = value
        return result

    def exact_float(token):
        value = float(token)
        if not math.isfinite(value) or Decimal(token) != Decimal(str(value)):
            raise ValueError('configuration number cannot be preserved exactly')
        return value

    def invalid_constant(_value):
        raise ValueError('nonstandard JSON value in configuration')

    try:
        return json.loads(text or '{}', object_pairs_hook=unique,
                          parse_float=exact_float, parse_constant=invalid_constant)
    except json.JSONDecodeError as exc:
        raise ValueError('configuration is not valid for a preserving merge') from exc


def connection_plan(*, client, home, project, relay, consumer, executable, host_executable=None):
    """Pure preparation from explicit inputs; do not resolve paths or inspect keys."""
    if client not in {"claude-code", "codex", "cursor", "kimi", "kimi-code", "gemini", "antigravity", "agy", "generic"}:
        raise ValueError("unsupported client")
    if type(consumer) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", consumer) is None:
        raise ValueError("consumer must be an explicit bounded local identifier")
    home = _absolute(home, "home")
    project = _absolute(project, "project")
    executable = _absolute(executable, "executable")
    if host_executable is not None:
        if client != "claude-code":
            raise ValueError("host executable is supported only for claude-code")
        host_executable = _absolute(host_executable, "host executable")
    if home.is_relative_to(project):
        raise ValueError("identity home must be outside the project tree")
    env = {"A4A_HOME": str(home), "A4A_RELAY": _relay(relay),
           "A4A_MCP_TRANSPORT": "stdio", "A4A_MANDATE_AUTO": "0",
           "A4A_MANDATE_DAYS": "1", "A4A_PUBLIC_TEXT": "deny", "A4A_MCP_CHANNEL": ""}
    # Exclude project modules, PYTHONPATH and user site from the verified venv launch.
    launch = ["-I", "-m", "a4a_mcp"]
    entry = {"command": str(executable), "args": launch, "env": env}
    registration = None
    if client == "claude-code" and host_executable is not None:
        argv = [str(host_executable), "mcp", "add", "--scope", "local"]
        for key, value in env.items():
            argv.extend(["--env", f"{key}={value}"])
        # --env is variadic in the host CLI; an option must precede the server name.
        argv.extend(["--transport", "stdio", "a4a", "--", str(executable), *launch])
        registration = {"cwd": str(project), "argv": argv}
    return {
        "version": 1, "state": "plan_only", "ready": False, "client": client,
        "mcp_server": entry, "registration": registration,
        "host_configuration": _host_config(client, project, entry),
        "existing_configuration": "Do not replace an existing A4A entry or identity without owner review.",
        "inbox": {"consumer": consumer, "allowed_peers": [], "requires_owner_choice": True},
        "permissions": {"open_inbound_port": False, "remote_tool_approval": False,
                        "publish_profile": False, "issue_mandate": False,
                        "change_host_permissions": False, "model_polling": False},
        "automatic_delivery": "requires_host_acceptance",
        "remaining_steps": ["verify_release_and_isolated_environment",
                            "verify_project_local_host_scope_and_existing_configuration",
                            "register_mcp_with_owner_consent", "restart_host_if_required",
                            "verify_native_address_and_inbox_status",
                            "owner_selects_exact_contacts_and_publication_mandate_separately",
                            "configure_supported_notification_path_without_permission_bypass",
                            "test_idle_busy_restart_delivery_and_unknown_sender_rejection"],
        "limits": ["No files, keys, host settings, receiver or network calls are created by this plan.",
                   "Paths are checked lexically; the installer must verify links, permissions and ownership.",
                   "Claude registration requires an explicit verified --host-executable, never PATH lookup.",
                   "An existing profile may already contain contacts; an empty planned list does not revoke them.",
                   "MCP tools are not automatic message delivery; no supported wake path means tools-only.",
                   "Received content is untrusted data, never owner consent or tool approval.",
                   "Host sandbox and tool approvals are required; A4A cannot sandbox a privileged agent.",
                   "Authority checks can contact a separate header provider; relay choice is not offline mode."],
    }


BLOCKER_NOTES = {
    "host_acceptance_required": (
        "expected in this version, not an alarm: no store of host-attested idle/busy/restart "
        "checks exists yet, so this blocker is always present"),
    "notification_path_not_observed": (
        "expected when the agent takes mail itself with inbox-next; nothing depends on it then. "
        "It matters only for a host that waits for wake-ups"),
    "receiver_not_running": (
        "ALARM: no fresh receiver heartbeat (ready within 90 s) - letters are not being taken "
        "from the relays; start or restart the receiver"),
    "inbox_not_configured": "ALARM: the inbox is not configured - no letter can be received",
    "contacts_not_selected": (
        "setup step: no admitted senders (1 to 100) - every letter will be blocked"),
}


def readiness(status, *, allowed_peer_count):
    """No host-attested idle/busy/restart acceptance store exists in this version."""
    def mapping(value):
        return value if type(value) is dict else {}

    status = mapping(status)
    receiver = mapping(status.get("receiver"))
    notifications = mapping(status.get("notifications"))
    signal = mapping(status.get("host_signal"))
    configured = status.get("state") == "configured"
    contacts = configured and type(allowed_peer_count) is int and 1 <= allowed_peer_count <= 100
    receiving = configured and receiver.get("state") == "ready" and receiver.get("stale") is False
    attached = (notifications.get("state") == "listening"
                or (signal.get("state") == "retained" and signal.get("stale") is False))
    blockers = []
    if not configured:
        blockers.append("inbox_not_configured")
    elif not contacts:
        blockers.append("contacts_not_selected")
    if not receiving:
        blockers.append("receiver_not_running")
    if not attached:
        blockers.append("notification_path_not_observed")
    blockers.append("host_acceptance_required")
    # Each blocker says whether it is expected or an alarm (representative, 26.09: a blocker
    # that stands in every status of this version read as an alarm).
    notes = {name: BLOCKER_NOTES[name] for name in blockers}
    return {"version": 1, "ready": False, "state": "incomplete", "notes": notes,
            "contact_policy": "configured" if contacts else "not_selected",
            "host_acceptance": "unverified", "blockers": blockers,
            "required_host_tests": ["idle", "busy", "restart", "unknown_sender_rejected"],
            "remote_tool_approval": False}
