"""No tracked file starts with a UTF-8 byte-order mark, except PowerShell scripts.

A BOM is invisible in review and in most diffs, yet it changes the first line of a
Python docstring and the first byte of every other file. On 2026-09-24 a worker's file
tool added one to every file it wrote; this test is what stops such a commit.

PowerShell scripts are the exception: Windows PowerShell 5.1 reads a BOM-less script
with Cyrillic text in the ANSI code page and fails, so there the BOM is required.
"""
import subprocess
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOM = b"\xef\xbb\xbf"
NEEDS_BOM = (".ps1",)


def test_tracked_files_have_no_byte_order_mark():
    marker = ROOT / "A4A-SOURCE.json"
    if marker.is_file() and not (ROOT / ".git").exists():
        # Source archives are runnable test inputs without Git metadata. Verify
        # their full file set and bytes before trusting the manifest inventory.
        subprocess.run([sys.executable, "-I", "-B",
                        str(ROOT / "scripts/build-public-source-archive.py"),
                        "--verify", str(ROOT)], cwd=ROOT, check=True, capture_output=True)
        names = [item["path"] for item in json.loads(marker.read_bytes())["files"]]
        names.append("A4A-SOURCE.json")
    else:
        names = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                               capture_output=True).stdout.decode("utf-8").split("\0")
    names = [name for name in names if name]
    assert len(names) > 100, "git ls-files returned too little to be the repository"
    marked = []
    for name in names:
        if name.endswith(NEEDS_BOM):
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        with path.open("rb") as handle:
            if handle.read(3) == BOM:
                marked.append(name)
    assert marked == [], f"byte-order mark at the start of: {marked}"
