"""Optional local roster of known contact labels, projects, and roles.

In multi-agent organizations or local multi-profile setups, an operator may maintain
a shared `known-contacts.json` (in `~/.a4a/known-contacts.json`, `$A4A_HOME/known-contacts.json`,
or `$A4A_KNOWN_CONTACTS_FILE`) so every mailbox resolves known internal peers to
human-readable names, projects, and roles automatically without hardcoding private
organization data into open-source code.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from a4a.event import is_canonical_pubkey
from a4a.keys import Keys

from . import identity


def _candidate_roster_paths() -> list[Path]:
    paths: list[Path] = []
    env_file = os.environ.get("A4A_KNOWN_CONTACTS_FILE", "").strip()
    if env_file:
        paths.append(Path(env_file))
    with contextlib.suppress(Exception):
        id_dir = Path(identity.IDENTITY_DIR)
        paths.append(id_dir / "known-contacts.json")
        if id_dir.parent.name == ".a4a":
            paths.append(id_dir.parent / "known-contacts.json")
    return paths


def _normalize_roster_entry(pubkey: str, raw: dict) -> dict | None:
    norm = str(pubkey or "").strip().lower()
    if not is_canonical_pubkey(norm) or not isinstance(raw, dict):
        return None
    mailbox = str(raw.get("mailbox") or raw.get("name") or "").strip()[:80]
    project = str(raw.get("project") or "").strip()[:80]
    role = str(raw.get("role") or raw.get("kind") or "").strip()[:120]
    label = str(raw.get("label") or "").strip()[:160]
    if not label:
        parts = [p for p in (mailbox, project, role) if p]
        label = " — ".join(parts)[:160]
    if not label:
        return None
    origin = str(raw.get("origin") or "own_developer").strip()
    if origin not in ("external_contact", "own_developer", "scoped_partner", "owner_agent"):
        origin = "own_developer"
    level = raw.get("default_level", 2)
    if type(level) is not int or level not in (1, 2, 3):
        level = 2
    return {
        "pubkey": norm,
        "apub": Keys.encode_apub(norm),
        "mailbox": mailbox,
        "project": project,
        "role": role,
        "label": label,
        "origin": origin,
        "default_level": level,
    }


def _parse_roster_file(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not path.is_file() or path.is_symlink():
        return out
    try:
        if path.stat().st_size > 512 * 1024:
            return out
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out

    # Format 1: {"contacts": {"<pubkey>": {...}}}
    contacts_map = data.get("contacts")
    if isinstance(contacts_map, dict):
        for pub, spec in contacts_map.items():
            entry = _normalize_roster_entry(pub, spec)
            if entry is not None:
                out[entry["pubkey"]] = entry

    # Format 2: ops/contact-book.json {"representative": "<pubkey>", "mailboxes": {"<name>": {...}}}
    rep_pub = str(data.get("representative") or "").strip().lower()
    if is_canonical_pubkey(rep_pub) and rep_pub not in out:
        entry = _normalize_roster_entry(
            rep_pub,
            {
                "mailbox": "owner-representative",
                "project": "Owner Office",
                "role": "Owner Representative",
                "label": "Owner Representative (owner-representative)",
                "origin": "owner_agent",
                "default_level": 2,
            },
        )
        if entry is not None:
            out[rep_pub] = entry

    mailboxes_map = data.get("mailboxes")
    if isinstance(mailboxes_map, dict):
        for mb_name, mb_spec in mailboxes_map.items():
            if not isinstance(mb_spec, dict):
                continue
            pub = str(mb_spec.get("pubkey") or "").strip().lower()
            if not is_canonical_pubkey(pub) or pub in out:
                continue
            proj = str(mb_spec.get("project") or "").strip()
            kind = str(mb_spec.get("kind") or "agent").strip()
            entry = _normalize_roster_entry(
                pub,
                {
                    "mailbox": str(mb_name),
                    "project": proj,
                    "role": f"{proj} ({kind})" if proj else kind,
                    "label": f"{mb_name} ({proj} / {kind})" if proj else f"{mb_name} ({kind})",
                    "origin": "own_developer",
                    "default_level": 2,
                },
            )
            if entry is not None:
                out[pub] = entry
            prio_rep = mb_spec.get("priority_representative")
            if isinstance(prio_rep, dict):
                p_pub = str(prio_rep.get("public_key") or "").strip().lower()
                if is_canonical_pubkey(p_pub) and p_pub not in out:
                    p_entry = _normalize_roster_entry(
                        p_pub,
                        {
                            "mailbox": "owner-representative",
                            "project": "Owner Office",
                            "role": "Owner Representative",
                            "label": "Owner Representative (owner-representative)",
                            "origin": "owner_agent",
                            "default_level": 2,
                        },
                    )
                    if p_entry is not None:
                        out[p_pub] = p_entry
    return out


def load_known_contacts() -> dict[str, dict]:
    """Load and merge known contact entries from configured local roster files."""
    merged: dict[str, dict] = {}
    for path in reversed(_candidate_roster_paths()):
        parsed = _parse_roster_file(path)
        if parsed:
            merged.update(parsed)
    return merged


def lookup_known_contact(pubkey: str) -> dict | None:
    """Return known contact metadata for `pubkey`, or None if unknown."""
    norm = str(pubkey or "").strip().lower()
    if not is_canonical_pubkey(norm):
        return None
    return load_known_contacts().get(norm)


def lookup_known_contact_label(pubkey: str) -> str:
    """Return the human-readable label for `pubkey` from the known roster, or empty string."""
    info = lookup_known_contact(pubkey)
    return str(info.get("label", "")).strip() if info else ""
