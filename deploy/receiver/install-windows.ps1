<#
.SYNOPSIS
    Installs the A4A receiver as a Windows scheduled task.

.DESCRIPTION
    A scheduled task is used deliberately instead of a third-party service wrapper.
    Windows cannot run an ordinary program as a service without an adapter, and the
    usual answer is to download an external binary (NSSM or similar). Asking someone
    to download an unrelated executable merely to receive messages is unacceptable:
    instructions that begin with "download this" are exactly what protocols are rightly
    criticized for. Task Scheduler is built into the operating system.

    The task runs AS THE CURRENT USER without elevation. The receiver holds a private
    key and decrypted correspondence, so it has no reason to run with administrator
    privileges.

.EXAMPLE
    .\install-windows.ps1 -Python C:\Projects\a4a\mcp-server\.venv\Scripts\python.exe `
                          -A4aHome C:\Users\me\.a4a\agent `
                          -Relay wss://relay.example.org
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][string]$A4aHome,
    # Comma-separated nodes: the receiver reads from ALL of them. This is the only
    # protection against message loss when one node fails.
    [Parameter(Mandatory)][string]$Relay,
    [string]$TaskName = 'A4A inbox receiver',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Task '$TaskName' removed. Keys and inbox in $A4aHome were not changed."
    return
}

# Validate BEFORE registration: a task that fails on every launch because of an invalid
# path looks installed while silently doing nothing.
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Interpreter not found: $Python"
}
if (-not (Test-Path -LiteralPath $A4aHome -PathType Container)) {
    throw "Identity directory not found: $A4aHome. Create it and add identity.json."
}
if (-not (Test-Path -LiteralPath (Join-Path $A4aHome 'identity.json') -PathType Leaf)) {
    throw "$A4aHome does not contain identity.json; the receiver cannot identify itself to the node."
}

$logDir = Join-Path $env:LOCALAPPDATA 'a4a'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'receiver.log'

# An apostrophe inside PowerShell single quotes closes the string. A path such as
# C:\Users\<O'Brien> is perfectly valid, and without doubling the apostrophe the generated
# command cannot be parsed: the task registers but fails on every launch. Base64 does not
# help here because it encodes already assembled text, while assembly itself is what fails
# (review finding FAN-005).
function Quote([string]$value) { "'" + $value.Replace("'", "''") + "'" }

# Set environment variables inside the command: a scheduled task does NOT inherit the
# environment of the shell that created it.
$inner = "`$env:A4A_HOME=$(Quote $A4aHome); `$env:A4A_RELAY=$(Quote $Relay); " +
         "`$env:PYTHONUNBUFFERED='1'; " +
         "& $(Quote $Python) -I -X utf8 -m a4a_mcp inbox-watch --forever *>> $(Quote $log)"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded"

# Trigger at user logon, not machine startup: the receiver runs as that user and uses that
# user's directory.
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 5 `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $TaskName).State

Write-Host "Task '$TaskName' registered and started. State: $state"
Write-Host "Log: $log"
Write-Host ""
Write-Host "Verify that the receiver is actually running, not merely registered:"
Write-Host "  `$env:A4A_HOME='$A4aHome'; `$env:A4A_RELAY='$Relay'"
Write-Host "  & '$Python' -I -X utf8 -m a4a_mcp inbox-status"
Write-Host "The receiver field in the response must be 'ready', not 'not_started'."
Write-Host "Remove: .\install-windows.ps1 -Remove -Python x -A4aHome '$A4aHome' -Relay x"
