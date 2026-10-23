#!/usr/bin/env python3
"""Regenerate hash-checked Linux/Python 3.11 locks for release containers.

The public Python projects retain consumer-friendly dependency ranges. Release images
use the generated locks so rebuilding the same source does not silently select a new
runtime dependency graph. Resolution runs in the same pinned upstream Linux/Python
base as the Dockerfiles, not in the caller's host Python environment. The image build
also applies exact Debian security updates; those do not change Python requirements.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parent.parent
PYTHON_IMAGE = (
    "python:3.11-slim@"
    "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
)
PIP_TOOLS_VERSION = "7.6.1"
LOCKS = (
    ("scripts/container-pip-requirements.in", "scripts/container-pip-requirements.lock"),
    ("scripts/container-build-requirements.in", "scripts/container-build-requirements.lock"),
    ("mcp-server/requirements.container.in", "mcp-server/requirements.container.lock"),
    ("notary/requirements.container.in", "notary/requirements.container.lock"),
)


def regular_bytes(root: Path, relative: str) -> bytes:
    """Reject links and Windows reparse points before reading an explicit input."""
    path = root
    for part in (None, *Path(relative).parts):
        if part is not None:
            path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise ValueError(f"Linked container-lock path: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Container-lock input is not a regular file: {path}")
    return path.read_bytes()


def prepare_stage(root: Path) -> tuple[Path, dict[str, bytes]]:
    """Copy only public lock inputs; retain the isolated run for diagnosis."""
    originals = {
        relative: regular_bytes(root, relative)
        for pair in LOCKS
        for relative in pair
    }
    parent = root / "build" / "container-lock-runs"
    for path in (root / "build", parent):
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise ValueError(f"Unsafe staging directory: {path}")
        else:
            path.mkdir()
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    stage = parent / name
    stage.mkdir()
    for relative, content in originals.items():
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    return stage, originals


def container_command(stage: Path) -> list[str]:
    commands = [
        "set -eu",
        "python -m venv /tmp/lockenv",
        # The base image's installer is used only for this exact hash-checked wheel.
        "/tmp/lockenv/bin/python -m pip install --disable-pip-version-check "
        "--no-cache-dir --only-binary=:all: --no-deps --require-hashes "
        "-r scripts/container-pip-requirements.lock",
        f"/tmp/lockenv/bin/python -m pip install --disable-pip-version-check "
        f"--only-binary=:all: pip-tools=={PIP_TOOLS_VERSION}",
    ]
    for source, output in LOCKS:
        commands.append(
            "/tmp/lockenv/bin/pip-compile --quiet "
            "--allow-unsafe --generate-hashes --no-emit-index-url --no-emit-trusted-host "
            "--strip-extras --upgrade-package pip --upgrade-package setuptools "
            "--upgrade-package pyjwt "
            f"--output-file={output} {source}"
        )
    return [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "2g", "--cpus", "2",
        "--mount", f"type=bind,source={stage},target=/src",
        "--workdir", "/src", PYTHON_IMAGE,
        "sh", "-c", "\n".join(commands),
    ]


def validate_lock(path: Path) -> bytes:
    """Accept only pinned requirements with SHA-256 hashes, not resolver options."""
    content = regular_bytes(path.parent, path.name)
    if len(content) > 2 * 1024 * 1024:
        raise ValueError(f"Oversized generated lock: {path}")
    requirement = None
    hashes = 0
    count = 0
    for line in content.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            line = line[:-1].rstrip()
        if re.fullmatch(r"--hash=sha256:[a-f0-9]{64}", line):
            if requirement is None:
                raise ValueError(f"Hash without a requirement: {path}")
            hashes += 1
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9_.+!-]+", line):
            if requirement is not None and not hashes:
                raise ValueError(f"Requirement without a hash: {path}: {requirement}")
            requirement, hashes = line, 0
            count += 1
        else:
            raise ValueError(f"Unexpected generated lock syntax: {path}: {line}")
    if not count or not hashes:
        raise ValueError(f"Generated lock has no hash-checked requirements: {path}")
    return content


def publish_outputs(root: Path, stage: Path, originals: dict[str, bytes]) -> None:
    # Validate every result and detect concurrent edits before replacing any lock.
    outputs = {output: validate_lock(stage / output) for _, output in LOCKS}
    for relative, content in originals.items():
        if regular_bytes(root, relative) != content:
            raise ValueError(f"Source changed while resolving container locks: {relative}")
    for source, _ in LOCKS:
        if regular_bytes(stage, source) != originals[source]:
            raise ValueError(f"Resolver changed its input: {source}")
    for output, content in outputs.items():
        (root / output).write_bytes(content)


def main() -> int:
    try:
        stage, originals = prepare_stage(ROOT)
        print(f"Public-only resolver stage (retained): {stage}", flush=True)
        result = subprocess.run(container_command(stage), cwd=stage, text=True)
        if result.returncode:
            return result.returncode
        publish_outputs(ROOT, stage, originals)
    except (OSError, ValueError) as error:
        print(f"Container locks were not published: {error}", file=sys.stderr)
        return 1
    print("Regenerated container locks:")
    for _, output in LOCKS:
        print(f"  {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
