"""Release runtime sources must describe limitations instead of leaving placeholders."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_TREES = (
    ROOT / "sdk-python" / "a4a",
    ROOT / "mcp-server" / "a4a_mcp",
    ROOT / "agent-service" / "a4a_agent",
    ROOT / "notary" / "a4a_notary",
    ROOT / "file-gateway" / "a4a_file_gateway",
    ROOT / "relay" / "src",
)
PLACEHOLDER = re.compile(r"\b(?:TODO|FIXME|XXX|HACK)\b|\bNot implemented\b",
                         re.IGNORECASE)


def test_public_runtime_sources_have_no_unclassified_placeholders():
    findings = []
    for tree in RUNTIME_TREES:
        for path in sorted(tree.rglob("*")):
            if path.suffix not in {".py", ".rs"}:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if PLACEHOLDER.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert findings == [], (
        "Replace release-source placeholders with an implementation or an explicit, "
        "reviewable limitation:\n" + "\n".join(findings))
