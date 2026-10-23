"""Public FIRST-ACTIVATION safeguards; never execute profile commands."""
import re
from pathlib import Path

import pytest


DOC = (Path(__file__).resolve().parents[2]
       / "docs/onboarding/inbox-activation.md")


@pytest.fixture
def document():
    assert DOC.is_file(), "Missing public first-activation guide"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture
def activation_block(document):
    blocks = re.findall(r"^```powershell\s*\n(.*?)^```", document, re.M | re.S)
    matches = [block for block in blocks if re.search(
        r"^& \$python -I -m a4a_mcp inbox-configure --consumer project-a(?=\s)",
        block, re.M)]
    assert len(matches) == 1, "Expected exactly one generic activation block"
    return matches[0]


@pytest.mark.parametrize("command", ["inbox-configure", "inbox-status"])
def test_activation_checks_exit_code_immediately(activation_block, command):
    lines = [line.strip() for line in activation_block.splitlines() if line.strip()]
    calls = [i for i, line in enumerate(lines) if re.match(
        rf"^& \$python -I -m a4a_mcp {command}(?:\s|$)", line)]
    assert len(calls) == 1, f"Expected exactly one {command} call"
    following = lines[calls[0] + 1:calls[0] + 2]
    assert following and re.fullmatch(
        r"if\s*\(\$LASTEXITCODE\s+-ne\s+0\)\s*\{\s*throw\s+'[^'\n]+'\s*\}",
        following[0]), f"{command} must be followed immediately by a LASTEXITCODE guard"


def test_first_activation_preflight_precedes_address_and_configure(activation_block):
    # Entry-name validation is independent of directory contents or link targets.
    preflight = re.search(
        r"\$existingInbox\s*=\s*@\(\s*"
        r"Get-ChildItem\s+-LiteralPath\s+\$env:A4A_HOME\s+-Force\s+-ErrorAction\s+Stop\s*\|\s*"
        r"Where-Object\s*\{\s*\$_\.Name\s+-in\s*@\('inbox-policy\.json',\s*'inbox'\)\s*\}\s*\)\s*"
        r"if\s*\(\$existingInbox\.Count\s+-ne\s+0\)\s*\{\s*throw\s+'FIRST-ACTIVATION:[^'\n]+'\s*\}",
        activation_block)
    assert preflight, "Any inbox-policy.json OR inbox entry must stop activation, including empty or linked entries"
    address = re.search(r"^\$address = \(& \$python -I -m a4a_mcp address\)", activation_block, re.M)
    configure = re.search(r"^& \$python -I -m a4a_mcp inbox-configure\b", activation_block, re.M)
    assert address and configure, "Both calls must remain in the validated block"
    assert preflight.end() < address.start() < configure.start(), (
        "FIRST-ACTIVATION must stop before address and configure")


def test_activation_has_no_replace_or_cleanup(activation_block):
    assert not re.search(r"^& .*--(?:replace|start-after)\b", activation_block, re.M)
    assert not re.search(
        r"\b(?:Remove-Item|Clear-Content|Set-Content|Move-Item|Rename-Item|rm|rmdir|del)\b",
        activation_block, re.I), "Existing state must not be deleted, changed, or hidden"


def test_existing_queue_requires_manual_metadata_reconciliation(document):
    section = re.search(r"^### Existing queue: stop\n(.*?)(?=\n##|\Z)",
                        document, re.M | re.S)
    assert section, "An existing queue requires a dedicated stop section"
    text = " ".join(section[1].split())
    for fragment in ("read-only", "metadata", "schema", "recipient", "consumer",
                     "receiver", "pending", "processing", "cursors", "relay", "stamp", "event_id",
                     "Do not reset", "delete", "apply `--replace`"):
        assert fragment in text, f"Manual reconciliation is missing: {fragment}"


def test_first_seen_boundary_and_migration_limits_are_explicit(document):
    section = re.search(r"^### The `first_seen` boundary\n(.*?)(?=\n##|\Z)", document, re.M | re.S)
    assert section, "The guide must explain the boundary rather than promise to exclude all old mail"
    text = " ".join(section[1].split())
    for fragment in ("int(time.time())", "--start-after", "existing cursor", "pending",
                     "second", "created_at", '(start_after, "")', "during the same second",
                     "relay migration", "preserve `first_seen`", "cannot preserve"):
        assert fragment in text, f"Boundary limitation is not documented: {fragment}"
    assert "Omitting `--start-after` is intentional: do not process all old correspondence" not in document


def test_activation_validates_existing_identity_and_exact_owner_selected_keys(activation_block):
    assert "$python = '<ABSOLUTE_VENV_PYTHON>'" in activation_block
    assert "$env:A4A_HOME = '<ABSOLUTE_A4A_HOME>'" in activation_block
    assert "$env:A4A_RELAY = '<OWNER_APPROVED_RELAY>'" in activation_block
    assert "$env:A4A_MANDATE_AUTO = '0'" in activation_block
    assert "$env:A4A_PUBLIC_TEXT = 'deny'" in activation_block
    for name in ("expectedPubkey", "allowedPeer"):
        assert re.search(rf"\${name} -cnotmatch '\^\[0-9a-f\]\{{64\}}\$'", activation_block)
    identity_check = activation_block.index('Test-Path -LiteralPath "$env:A4A_HOME/identity.json" -PathType Leaf')
    address = activation_block.index("$address = (& $python -I -m a4a_mcp address)")
    comparison = activation_block.index('[regex]::Escape($expectedPubkey)')
    configure = activation_block.index("& $python -I -m a4a_mcp inbox-configure")
    assert identity_check < address < comparison < configure
    assert '--allow-peer $allowedPeer' in activation_block
    assert "$LASTEXITCODE -ne 0 -or $address -cnotmatch" in activation_block
