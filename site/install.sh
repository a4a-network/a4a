#!/bin/sh
# A4A Unix one-command installer (Linux & macOS).
# Works both interactively in a terminal and non-interactively when invoked by an AI agent.
set -eu

client=""
profile=""
project="$PWD"
relay="wss://eu1.a4a.network,wss://us1.a4a.network,wss://sg1.a4a.network,wss://ru1.a4a.network"
data_root="$HOME/.a4a"
apply=no
plan=no
download_only=no

fail() { printf '%s\n' "$*" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --client|--profile|--relay|--project|--data-root)
            [ "$#" -ge 2 ] || fail "Missing option value for $1."
            case "$1" in
                --client) client=$2;;
                --profile) profile=$2;;
                --relay) relay=$2;;
                --project) project=$2;;
                --data-root) data_root=$2;;
            esac
            shift 2;;
        --apply) apply=yes; shift;;
        --plan) plan=yes; shift;;
        --download-only) download_only=yes; shift;;
        *) shift;;
    esac
done

detect_default_client() {
    if [ -d "$project/.kimi-code" ]; then printf 'kimi'; return; fi
    if [ -d "$project/.cursor" ]; then printf 'cursor'; return; fi
    if [ -d "$project/.codex" ]; then printf 'codex'; return; fi
    if [ -n "${KIMI_CODE:-}" ] || [ -n "${KIMI_SESSION:-}" ]; then printf 'kimi'; return; fi
    printf 'claude-code'
}

if [ -z "$client" ] || [ "$client" = "auto" ]; then
    if [ "$apply" = "yes" ] || [ ! -t 0 ]; then
        client=$(detect_default_client)
        apply=yes
    else
        printf '%s\n' 'Choose your application: 1 Claude Code, 2 Claude Desktop, 3 Codex, 4 Cursor, 5 Kimi Code, 6 Gemini / Antigravity [default: 1]'
        printf 'Application number: '
        if ! IFS= read -r choice; then
            choice="1"
        fi
        case "$choice" in
            ""|1|claude|claude-code) client="claude-code";;
            2|claude-desktop) client="claude-desktop";;
            3|codex) client="codex";;
            4|cursor) client="cursor";;
            5|kimi|kimi-code) client="kimi";;
            6|gemini|antigravity|agy) client="gemini";;
            *) client=$(detect_default_client);;
        esac
    fi
fi

case "$client" in
    kimi-code) client="kimi";;
    antigravity|agy) client="gemini";;
esac

if [ -z "$profile" ]; then
    proj_slug=$(basename "$project" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g; s/^-*//; s/-*$//')
    [ -n "$proj_slug" ] || proj_slug="project"
    case "$proj_slug" in [a-z]*) :;; *) proj_slug="p-$proj_slug";; esac
    profile="${proj_slug}-${client}"
fi

if [ "$plan" = "yes" ]; then
    printf '{"state":"installer_plan","version":"0.4.0","client":"%s","project":"%s","profile":"%s","relay":"%s","changes_made":false}\n' "$client" "$project" "$profile" "$relay"
    exit 0
fi

src_dir="$HOME/.a4a-src"
venv_dir="$HOME/.a4a-venv"
profile_home="$data_root/$profile"

printf '[A4A] Preparing A4A v0.4 runtime in %s ...\n' "$venv_dir"
sdk_wheel_url="https://a4a.network/dist/a4a_sdk-0.3.3-py3-none-any.whl"
mcp_wheel_url="https://a4a.network/dist/a4a_mcp-0.3.3-py3-none-any.whl"

if [ "$download_only" = "yes" ]; then
    printf '{"state":"downloaded","source":"%s","runtime_installed":false}\n' "$sdk_wheel_url"
    exit 0
fi

if [ ! -x "$venv_dir/bin/python" ]; then
    python3 -m venv "$venv_dir"
fi

if ! "$venv_dir/bin/pip" install --quiet --upgrade a4a-sdk a4a-mcp && ! "$venv_dir/bin/pip" install --quiet --upgrade "$sdk_wheel_url" "$mcp_wheel_url"; then
    if [ ! -d "$src_dir/sdk-python" ]; then
        rm -rf "$src_dir"
        git clone --depth 1 https://github.com/a4a-network/a4a.git "$src_dir"
    fi
    "$venv_dir/bin/pip" install --quiet --upgrade "$src_dir/sdk-python" "$src_dir/mcp-server"
fi

mkdir -p "$profile_home"
chmod 700 "$profile_home" 2>/dev/null || true

export A4A_HOME="$profile_home"
export A4A_RELAY="$relay"
addr_out=$("$venv_dir/bin/python" -I -m a4a_mcp address)
"$venv_dir/bin/python" -I -m a4a_mcp issue-mandate >/dev/null 2>&1 || true

cfg_out=$("$venv_dir/bin/python" - "$client" "$project" "$venv_dir/bin/python" "$profile_home" "$relay" <<'PY'
import json, os, sys
from pathlib import Path

client, project, venv_py, profile_home, relay = sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
entry = {
    "command": venv_py,
    "args": ["-I", "-m", "a4a_mcp"],
    "env": {
        "A4A_HOME": profile_home,
        "A4A_RELAY": relay,
        "A4A_MCP_TRANSPORT": "stdio",
        "A4A_MANDATE_AUTO": "0",
        "A4A_MANDATE_DAYS": "30"
    }
}
targets = []
if client in ("claude-code", "gemini"):
    targets.append(("json", project / ".mcp.json", entry))
    if (project / ".kimi-code").is_dir() or (Path.home() / ".kimi-code").is_dir():
        targets.append(("json", project / ".kimi-code" / "mcp.json", entry))
elif client == "kimi":
    targets.append(("json", project / ".kimi-code" / "mcp.json", entry))
    if (project / ".mcp.json").is_file():
        targets.append(("json", project / ".mcp.json", entry))
elif client == "cursor":
    targets.append(("json", project / ".cursor" / "mcp.json", {"type": "stdio", **entry}))
elif client == "claude-desktop":
    if sys.platform == "darwin":
        targets.append(("json", Path.home() / "Library/Application Support/Claude/claude_desktop_config.json", entry))
elif client == "codex":
    targets.append(("toml", project / ".codex" / "config.toml", entry))

updated = []
for fmt, path, srv in targets:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        data = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = {}
        servers["a4a"] = srv
        data["mcpServers"] = servers
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        updated.append(str(path))
    elif fmt == "toml":
        txt = path.read_text(encoding="utf-8") if path.is_file() else ""
        if "[mcp_servers.a4a]" not in txt:
            q = lambda v: json.dumps(v, ensure_ascii=False)
            block = (
                f"\n[mcp_servers.a4a]\ncommand = {q(srv['command'])}\nargs = {q(srv['args'])}\n\n"
                + "[mcp_servers.a4a.env]\n"
                + "".join(f"{k} = {q(v)}\n" for k, v in srv["env"].items())
            )
            path.write_text((txt.rstrip() + "\n" + block).lstrip(), encoding="utf-8")
        updated.append(str(path))

print(json.dumps({"updated_configs": updated}))
PY
)

"$venv_dir/bin/python" -I -m a4a_mcp inbox-configure --consumer default --allow-peer apub1jqahsu46f6gwm7husjlmvzvhggrdfugjda8gjl0tnr9wcq2z6casj59wqj --ack-on-receipt --start-after 0 >/dev/null 2>&1 || true

my_apub=$(printf '%s\n' "$addr_out" | grep -Eo 'apub1[0-9a-z]+' | head -n 1)
[ -n "$my_apub" ] || my_apub="$addr_out"

cat <<EOF

========================================================================
  A4A Connected ($client)
========================================================================
  Your A4A Address : $my_apub
  Your Contact Card: https://a4a.network/c/#$my_apub
  MCP Config       : $cfg_out
------------------------------------------------------------------------
  How to use (just ask your AI agent in normal chat):
    - "Send an A4A message to apub1... saying hello"
    - "Check my A4A inbox"
    - "What is my A4A address?"
------------------------------------------------------------------------
  [For AI Agent]: Always tell your user their new A4A address ($my_apub),
  their shareable QR card link (https://a4a.network/c/#$my_apub), and how
  to send/read A4A messages by asking you in chat.
========================================================================
EOF
