#!/usr/bin/env python3
"""Insert the project agent's real address into `site/agent.html`.

WHY A SCRIPT INSTEAD OF A CHECKLIST ITEM. Replacing `{{APUB}}` was once a manual
pre-publication step. It is easy to forget, leaving visitors with a placeholder instead
of an address; a broken identity page is worse than no page. The 2026-08-29 audit replaced
that manual step with this command.

Read the address from the project-agent identity (`A4A_AGENT_HOME`, default
`~/.a4a-project-agent`) or accept it explicitly as the first argument, for example when
building on a machine that does not host the agent.

    python scripts/render-agent-page.py                 # read from identity
    python scripts/render-agent-page.py apub1...        # provide explicitly

Write the result to `build/agent.html` without modifying the source template. Keeping the
placeholder in the repository makes every subsequent build reproducible.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "site" / "agent.html"
OUT_DIR = ROOT / "build"
PLACEHOLDER = "{{APUB}}"


def _apub_from_identity() -> str:
    sys.path.insert(0, str(ROOT / "sdk-python"))
    sys.path.insert(0, str(ROOT / "agent-service"))
    from a4a_agent import identity           # noqa: E402 (path configured above)
    return identity.load_or_create_identity().apub


def main(argv: list[str]) -> int:
    apub = argv[1] if len(argv) > 1 else _apub_from_identity()
    if not apub.startswith("apub1"):
        print(f"address must use apub1 format; got {apub!r}", file=sys.stderr)
        return 2

    html = TEMPLATE.read_text(encoding="utf-8")
    if PLACEHOLDER not in html:
        print(f"template does not contain {PLACEHOLDER}; nothing to replace",
              file=sys.stderr)
        return 2
    rendered = html.replace(PLACEHOLDER, apub)

    # Verify the RESULT, not the intention. Match named placeholders such as {{NAME}},
    # not any double brace: the page script legitimately contains "{{" while detecting
    # an unsubstituted address and disabling its copy button.
    import re
    leftover = re.search(r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}", rendered)
    if leftover:
        print(f"placeholder remains in rendered output: {leftover.group(0)!r}", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(exist_ok=True)
    out = OUT_DIR / "agent.html"
    out.write_text(rendered, encoding="utf-8")
    print(f"ready: {out} (address {apub[:16]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
