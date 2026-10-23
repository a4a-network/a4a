#!/usr/bin/env python3
"""Prepare local project links for an explicitly owner-selected GitHub OWNER/REPO.

The default is a read-only JSON plan. --apply updates the listed source files in
this tree; it never contacts GitHub, changes a remote, or publishes anything.
--check validates an already prepared tree against the explicit destination.
Namespace ownership and public availability require separate verification.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
METADATA_FILES = (
    "sdk-python/pyproject.toml", "mcp-server/pyproject.toml",
    "agent-service/pyproject.toml", "file-gateway/pyproject.toml",
    "notary/pyproject.toml",
)
DOCUMENT_FILES = (
    "site/index.html", "site/agent.html", "site/connect-agent.txt",
    "README.md", "docs/translations/README.ru.md", "CONTRIBUTING.md", "SECURITY.md",
    "a4a-master-spec.md", "docs/onboarding/connect-your-agent.md",
    "docs/onboarding/safe-connect.md", "deploy/receiver/a4a-receiver.service",
)
FILES = METADATA_FILES + DOCUMENT_FILES
FORMER = ("a4a-network/a4a", "a4a-network/a4a-legacy", "a4a-network/a4a-protocol")


def repository_slug(value):
    """Accept a GitHub owner/repository pair, never a URL or path expression."""
    parts = value.split("/")
    if (len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", parts[0])
            or "--" in parts[0]
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", parts[1])
            or parts[1] in {".", ".."} or parts[1].lower().endswith(".git")):
        raise ValueError("repository must be an explicit GitHub OWNER/REPO slug")
    return value


def metadata_source(root):
    record = tomllib.loads((root / METADATA_FILES[0]).read_text(encoding="utf-8"))
    source = record.get("project", {}).get("urls", {}).get("Source")
    if not isinstance(source, str):
        raise ValueError("SDK project.urls.Source is missing")
    parsed = urlsplit(source)
    if (parsed.scheme != "https" or parsed.netloc != "github.com"
            or parsed.query or parsed.fragment or source.endswith("/")):
        raise ValueError("SDK Source must be an HTTPS GitHub repository root")
    return repository_slug(parsed.path.removeprefix("/"))


def source_path(root, relative):
    """A namespace edit may write only an unlinked regular file in this tree."""
    current = root
    for part in Path(relative).parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"linked source path: {relative}")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not current.resolve().is_relative_to(root):
        raise ValueError(f"required unlinked regular source file is missing: {relative}")
    return current


def prepare(root, destination):
    root = root.resolve()
    destination = repository_slug(destination)
    current = metadata_source(root)
    routes = sorted(set(FORMER + (current, destination)), key=len, reverse=True)
    # Match a complete repository boundary: a similarly named third-party project
    # must not change, while .git, issue paths, anchors, and query strings survive.
    pattern = re.compile(r"(?<![A-Za-z0-9.-])github\.com/(?:"
                         + "|".join(re.escape(route) for route in routes)
                         + r")(?=\.git(?:[^A-Za-z0-9_.-]|$)|[^A-Za-z0-9_.-]|$)", re.I)
    planned = []
    files = list(FILES)
    translations = None
    if (root / "docs/translations/manifest.json").exists():
        spec = importlib.util.spec_from_file_location(
            "destination_translations", Path(__file__).resolve().parent / "readme_translations.py")
        translations = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(translations)
        contents = translations.read_worktree(root)
        for relative in sorted(translations.validate_catalogue(contents)):
            if relative not in files:
                files.append(relative)
    for relative in files:
        path = source_path(root, relative)
        before = path.read_bytes()
        text = before.decode("utf-8")
        after = pattern.sub("github.com/" + destination, text).encode("utf-8")
        # Compare every declared component Source, including unrecognized wrong URLs.
        if relative in METADATA_FILES:
            record = tomllib.loads(text)
            urls = record.get("project", {}).get("urls", {})
            source = urls.get("Source")
            if source is not None and source != "https://github.com/" + current:
                raise ValueError(f"component Source disagrees with SDK metadata: {relative}")
            if "Issues" in urls and urls["Issues"] != "https://github.com/" + current + "/issues":
                raise ValueError(f"component Issues disagrees with SDK metadata: {relative}")
        planned.append((relative, before, after))
    if translations is not None:
        manifest_path = translations.CATALOGUE
        before = source_path(root, manifest_path).read_bytes()
        record = json.loads(before)
        changed_contents = dict(contents)
        changed_contents.update({relative: after for relative, _before, after in planned})
        record["source_sha256"] = translations.sha256(changed_contents["README.md"])
        record["index_sha256"] = translations.sha256(changed_contents[translations.INDEX])
        for item in record["translations"]:
            item["sha256"] = translations.sha256(changed_contents[item["path"]])
        after = (json.dumps(record, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        changed_contents[manifest_path] = after
        translations.validate_catalogue(changed_contents)
        planned.append((manifest_path, before, after))
    return current, planned


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="owner-selected GitHub OWNER/REPO; no default")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="apply the plan only in this local source tree")
    mode.add_argument("--check", action="store_true", help="require the current tree to match the destination")
    args = parser.parse_args(argv)
    try:
        current, planned = prepare(ROOT, args.repository)
        changed = [(relative, before, after) for relative, before, after in planned if before != after]
        if args.apply:
            # Check the entire plan before writing, so a stale plan or invalid input
            # does not knowingly apply only a subset. Files are never removed.
            for relative, before, _after in planned:
                if source_path(ROOT.resolve(), relative).read_bytes() != before:
                    raise ValueError(f"source changed while preparing destination: {relative}")
            for relative, _before, after in changed:
                (ROOT / relative).write_bytes(after)
        print(json.dumps({
            "repository": args.repository, "previous_repository": current,
            "mode": "apply" if args.apply else "check" if args.check else "plan",
            "release_approved": False, "network_access": False,
            "destination_ownership_verified": False,
            "files": [{"path": relative, "before_sha256": hashlib.sha256(before).hexdigest(),
                       "after_sha256": hashlib.sha256(after).hexdigest()}
                      for relative, before, after in changed],
        }, indent=2))
        return 1 if args.check and changed else 0
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"repository destination preparation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
