[CmdletBinding()]
param(
    [ValidateSet('','auto','claude-code','claude-desktop','codex','cursor','kimi','kimi-code','gemini','antigravity','agy','generic')][string]$Client = '',
    [string]$Profile = '',
    [string]$Project = (Get-Location).Path,
    [string]$Relay = 'wss://eu1.a4a.network,wss://us1.a4a.network,wss://sg1.a4a.network,wss://ru1.a4a.network',
    [string]$DataRoot = (Join-Path $HOME '.a4a'),
    [Uri]$AssetUri = 'https://github.com/a4a-network/a4a.git',
    [switch]$AcceptMicrosoftRuntimeTerms,
    [switch]$Apply,
    [switch]$Plan,
    [switch]$DownloadOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

if (($PSVersionTable.PSEdition -ne 'Desktop' -and $PSVersionTable.PSEdition -ne 'Core') -or $PSVersionTable.PSVersion.Major -lt 5) {
    throw 'Use Windows PowerShell 5.1+ or PowerShell 7+.'
}

$Project = [IO.Path]::GetFullPath($Project)
if (-not [IO.Directory]::Exists($Project)) { throw 'Choose an existing project folder.' }

function Detect-DefaultClient([string]$ProjPath) {
    if (Test-Path -LiteralPath (Join-Path $ProjPath '.kimi-code')) { return 'kimi' }
    if (Test-Path -LiteralPath (Join-Path $ProjPath '.cursor')) { return 'cursor' }
    if (Test-Path -LiteralPath (Join-Path $ProjPath '.codex')) { return 'codex' }
    if ($env:KIMI_CODE -or $env:KIMI_SESSION) { return 'kimi' }
    if ($env:ANTIGRAVITY_CLI -or (Test-Path -LiteralPath (Join-Path $HOME '.gemini\antigravity-cli'))) { return 'claude-code' }
    return 'claude-code'
}

$isNonInteractive = $false
try {
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) { $isNonInteractive = $true }
} catch {
    $isNonInteractive = $true
}

if (-not $Client -or $Client -eq 'auto') {
    if ($Apply -or $isNonInteractive) {
        $Client = Detect-DefaultClient $Project
        $Apply = $true
    } else {
        Write-Host 'Choose your application: 1 Claude Code, 2 Claude Desktop, 3 Codex, 4 Cursor, 5 Kimi Code, 6 Gemini / Antigravity [default: 1]'
        $choice = $null
        try { $choice = Read-Host 'Application number' } catch { $choice = '1' }
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }
        $applications = @{
            '1'='claude-code'; '2'='claude-desktop'; '3'='codex';
            '4'='cursor'; '5'='kimi'; '6'='gemini';
            'claude'='claude-code'; 'claude-code'='claude-code'; 'claude-desktop'='claude-desktop';
            'codex'='codex'; 'cursor'='cursor'; 'kimi'='kimi'; 'kimi-code'='kimi';
            'gemini'='gemini'; 'antigravity'='gemini'; 'agy'='gemini'
        }
        $key = $choice.Trim().ToLowerInvariant()
        if ($applications.ContainsKey($key)) {
            $Client = $applications[$key]
        } else {
            $Client = Detect-DefaultClient $Project
        }
    }
}
if ($Client -eq 'kimi-code') { $Client = 'kimi' }
if ($Client -in @('antigravity','agy')) { $Client = 'gemini' }

if (-not $Profile) {
    $projSlug = ([IO.Path]::GetFileName($Project.TrimEnd('\','/')) -replace '[^a-zA-Z0-9_-]', '-').ToLowerInvariant().Trim('-')
    if (-not $projSlug -or $projSlug -notmatch '^[a-z]') { $projSlug = 'p-' + $projSlug }
    $Profile = ($projSlug + '-' + $Client)
    if ($Profile.Length -gt 48) { $Profile = $Profile.Substring(0, 48).TrimEnd('-') }
}

if ($Plan) {
    @{
        state = 'installer_plan'
        version = '0.4.0'
        client = $Client
        project = $Project
        profile = $Profile
        relay = $Relay
        data_root = $DataRoot
        changes_made = $false
    } | ConvertTo-Json
    return
}

$srcDir = Join-Path $HOME '.a4a-src'
$venvDir = Join-Path $HOME '.a4a-venv'
$profileHome = Join-Path $DataRoot $Profile

Write-Host "[A4A] Preparing A4A v0.4 runtime in $venvDir ..."
$sdkWheelUrl = 'https://a4a.network/dist/a4a_sdk-0.3.3-py3-none-any.whl'
$mcpWheelUrl = 'https://a4a.network/dist/a4a_mcp-0.3.3-py3-none-any.whl'

if ($DownloadOnly) {
    @{ state = 'downloaded'; source = $sdkWheelUrl; runtime_installed = $false } | ConvertTo-Json
    return
}

$venvPy = Join-Path $venvDir 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPy)) {
    & python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Python virtual environment at $venvDir" }
}

& $venvPy -m pip install --quiet --upgrade a4a-sdk a4a-mcp
if ($LASTEXITCODE -ne 0) {
    & $venvPy -m pip install --quiet --upgrade $sdkWheelUrl $mcpWheelUrl
}
if ($LASTEXITCODE -ne 0) {
    if (-not (Test-Path -LiteralPath (Join-Path $srcDir 'sdk-python'))) {
        if (Test-Path -LiteralPath $srcDir) { Remove-Item -LiteralPath $srcDir -Recurse -Force }
        & git clone --depth 1 https://github.com/a4a-network/a4a.git $srcDir
        if ($LASTEXITCODE -ne 0) { throw 'Failed to download A4A packages from https://a4a.network/dist or GitHub' }
    }
    & $venvPy -m pip install --quiet --upgrade (Join-Path $srcDir 'sdk-python') (Join-Path $srcDir 'mcp-server')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install a4a-sdk and a4a-mcp into virtual environment.' }
}

if (-not (Test-Path -LiteralPath $profileHome)) {
    New-Item -ItemType Directory -Path $profileHome -Force | Out-Null
}

$env:A4A_HOME = $profileHome
$env:A4A_RELAY = $Relay
$addrOut = (& $venvPy -I -m a4a_mcp address) -join "`n"
try { & $venvPy -I -m a4a_mcp issue-mandate 2>$null | Out-Null } catch {}

# Configure MCP host file(s)
$pyHelper = @"
import json, os, sys
from pathlib import Path

client = sys.argv[1]
project = Path(sys.argv[2])
venv_py = sys.argv[3]
profile_home = sys.argv[4]
relay = sys.argv[5]

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
    appdata = os.environ.get("APPDATA")
    if appdata:
        targets.append(("json", Path(appdata) / "Claude" / "claude_desktop_config.json", entry))
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
"@

$cfgOut = & $venvPy -c $pyHelper $Client $Project $venvPy $profileHome $Relay
Write-Host ""
Write-Host "=== A4A Connected ($Client) ==="
Write-Host $addrOut
Write-Host "Config:       $cfgOut"
Write-Host "Test command: & `"$venvPy`" -I -m a4a_mcp inbox-configure --consumer default --allow-peer apub1jqahsu46f6gwm7husjlmvzvhggrdfugjda8gjl0tnr9wcq2z6casj59wqj --ack-on-receipt --start-after 0 --replace"
