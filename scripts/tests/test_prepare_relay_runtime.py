"""Fail-closed selection and namespace checks; native image builds are separate evidence."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import struct

import pytest

SPEC = importlib.util.spec_from_file_location("prepare_relay", Path(__file__).parents[1] / "prepare-relay-runtime.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def elf(interpreter=None):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, int(interpreter is not None))
    if interpreter:
        value = interpreter.encode() + b"\0"
        data.extend(struct.pack("<IIQQQQQQ", 3, 0, 120, 0, 0, len(value), len(value), 1))
        data.extend(value)
    return bytes(data)


def test_absolute_and_relative_links_stay_in_image_namespace():
    tree = {"/lib64": {"kind": "symlink", "target": "/usr/lib64"},
            "/usr/lib64/loader": {"kind": "symlink", "target": "../lib/loader"},
            "/usr/lib/loader": {"kind": "file"}}
    assert runtime.resolve(tree, "/lib64/loader") == "/usr/lib/loader"
    tree["/usr/lib/loader"] = {"kind": "symlink", "target": "/lib64/loader"}
    with pytest.raises(runtime.RuntimePreparationError, match="cycle"):
        runtime.resolve(tree, "/lib64/loader")


def test_loader_bytes_without_its_image_alias_are_insufficient():
    payload = {"/usr/src/app/nostr-rs-relay": elf("/lib64/loader"), "/usr/lib64/loader": elf()}
    with pytest.raises(runtime.RuntimePreparationError, match="missing selected ELF"):
        runtime.validate_elf_closure({}, payload)
    tree = {"/lib64": {"kind": "symlink", "target": "usr/lib64"}}
    assert runtime.validate_elf_closure(tree, payload)[0]["resolved"] == "/usr/lib64/loader"


@pytest.mark.parametrize("data", [b"\x7fELF", elf()[:60], elf("/loader")[:125]])
def test_truncated_elf_is_rejected(data):
    with pytest.raises(runtime.RuntimePreparationError):
        runtime.elf_dependencies(data)


def test_dotted_package_names_do_not_match_a_shorter_package():
    assert runtime.info_belongs("libfoo.bar:amd64.list", "libfoo.bar")
    assert not runtime.info_belongs("libfoo.bar:amd64.list", "libfoo")


def test_versioned_alternative_and_virtual_dependencies():
    paragraphs = runtime.control_paragraphs(b"Package: relay\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nDepends: old (>= 3) | virtual (>= 2),\n leaf\n\nPackage: old\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\nPackage: provider\nStatus: install ok installed\nArchitecture: all\nVersion: 9\nProvides: virtual (= 2)\n\nPackage: leaf\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n")
    packages = runtime.installed_packages(paragraphs)
    compare = lambda version, op, wanted: op is None or (version is not None and int(version) >= int(wanted))
    chosen, choices = runtime.package_closure(packages, roots=("relay",), compare=compare)
    assert chosen == {"relay", "provider", "leaf"}
    assert choices[0]["selected"] == "provider"
    packages["provider"]["Provides"] = "virtual"
    with pytest.raises(runtime.RuntimePreparationError, match="unsatisfied"):
        runtime.package_closure(packages, roots=("relay",), compare=compare)


@pytest.fixture
def source(tmp_path, monkeypatch):
    origin, kit = tmp_path / "source", tmp_path / "kit"
    proofdir = origin / "usr/local/share/a4a-debian-install"
    proofdir.mkdir(parents=True)
    kit.mkdir()
    proof = {"build_nonce": "a" * 32, "installation_deadline_utc":
             (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), "lock_policy_sha256": "b" * 64}
    raw = json.dumps(proof).encode()
    (proofdir / "verification.json").write_bytes(raw)
    (kit / "verification.json").write_bytes(raw)
    (proofdir / "result.txt").write_text("exact-inventory-and-health-checked\n")
    monkeypatch.setattr(runtime, "SOURCE", origin)
    monkeypatch.setattr(runtime, "KIT", kit)
    monkeypatch.setattr(runtime, "PREPARED", tmp_path / "prepared")
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("A4A_PREPARE_RELAY_RUNTIME", "1")
    return origin, kit, proofdir, proof


def test_foreign_nonce_or_expired_source_receipt_creates_no_output(source):
    _, kit, proofdir, proof = source
    with pytest.raises(runtime.RuntimePreparationError, match="different build nonce"):
        runtime.prepare("c" * 32)
    proof["installation_deadline_utc"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    raw = json.dumps(proof).encode()
    (kit / "verification.json").write_bytes(raw)
    (proofdir / "verification.json").write_bytes(raw)
    with pytest.raises(runtime.RuntimePreparationError, match="expired"):
        runtime.prepare("a" * 32)
    assert not runtime.PREPARED.exists()


def test_receipt_mismatch_creates_no_output(source):
    (source[2] / "verification.json").write_text("{}")
    with pytest.raises(runtime.RuntimePreparationError, match="differs"):
        runtime.prepare("a" * 32)
    assert not runtime.PREPARED.exists()


def test_inventory_mismatch_creates_no_output(source):
    origin, kit, proofdir, _ = source
    directory = origin / "var/lib/dpkg"
    directory.mkdir(parents=True)
    (directory / "status").write_text("Package: relay\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n")
    (kit / "after.expected.tsv").write_text("relay\t2\tamd64\n")
    (proofdir / "after.tsv").write_text("relay\t1\tamd64\n")
    with pytest.raises(runtime.RuntimePreparationError, match="inventory differs"):
        runtime.prepare("a" * 32)
    assert not runtime.PREPARED.exists()
