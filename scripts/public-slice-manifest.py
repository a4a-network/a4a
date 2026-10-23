"""Fingerprint a public slice by an EXPLICIT, platform-independent rule.

WHY A SCRIPT INSTEAD OF ONE DOCUMENT LINE. The first fingerprint used `sorted(Path)`,
which depends on the operating system: Windows compares paths case-insensitively while
POSIX compares character codes. The same slice could therefore produce `58c6bcce...` on
one and `3606d09b...` on the other. Independent review reproduced both and correctly
required a complete rule: "sort the paths" is not a recipe until the ordering is named.

Complete rule, reproducible by another person on another system:

1. Include every regular slice file using a relative path and `/` separators.
2. Order by `casefold()` of the relative path. Case is ignored INTENTIONALLY to preserve
   existing checkpoints. This changes nothing on case-sensitive systems unless two paths
   differ only by case; the collision check below forbids that ambiguity.
3. For each file, append its UTF-8 path, byte `0x00`, and the RAW 32-byte SHA-256 of its
   contents to the stream. Raw means not hex; hexadecimal text yields another digest.
4. The fingerprint is SHA-256 of the complete stream.

The ordering-ambiguity check is mandatory. If two paths differ only by case, ordering is
undefined and the script refuses to calculate a digest. Returning a number would present
an accident as a fingerprint.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def manifest(root: Path) -> tuple[str, int]:
    """Return `(fingerprint, file count)` using the module rule."""
    relative = sorted((p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()),
                      key=str.casefold)

    collisions = {}
    for path in relative:
        collisions.setdefault(path.casefold(), []).append(path)
    ambiguous = {key: names for key, names in collisions.items() if len(names) > 1}
    if ambiguous:
        raise SystemExit(
            "ordering is undefined: paths differ only by case: "
            f"{sorted(ambiguous.values())}. This slice would have a platform-dependent "
            "fingerprint, so no digest is calculated.")

    stream = hashlib.sha256()
    for path in relative:
        stream.update(path.encode("utf-8"))
        stream.update(b"\0")
        stream.update(hashlib.sha256((root / path).read_bytes()).digest())
    return stream.hexdigest(), len(relative)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default="build/public-slice",
                        help="slice directory (default: build/public-slice)")
    parser.add_argument("--expect", help="compare with a known fingerprint")
    arguments = parser.parse_args()

    root = Path(arguments.root)
    if not root.is_dir():
        raise SystemExit(f"directory does not exist: {root}")

    digest, count = manifest(root)
    print(f"files: {count}")
    print(f"manifest SHA256: {digest}")
    if arguments.expect and arguments.expect != digest:
        raise SystemExit(f"DOES NOT MATCH expected {arguments.expect}")
    if arguments.expect:
        print("matches expected fingerprint")


if __name__ == "__main__":
    main()
