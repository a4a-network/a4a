"""Acquisition controls; signature stubs are not cryptographic evidence."""

from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
import lzma
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_debian_build_lock import bundle, NOW, RING, descriptor, trixie_runtime
import debian_release_auth as auth
from debian_lock_contract import LockContractError


def test_acquisition_cli_is_implemented():
    assert (Path(__file__).resolve().parents[1] / "debian_acquire.py").is_file(), "bounded acquisition is missing"


def destination(root):
    return root.parent / (root.name + "-acquired")


@pytest.fixture
def acquisition(bundle, monkeypatch, request):
    module = Path(__file__).resolve().parents[1] / "debian_acquire.py"
    assert module.is_file(), "bounded acquisition is not implemented"
    acquire = importlib.import_module("debian_acquire")
    if getattr(request, "param", "bookworm") == "trixie":
        bundle = trixie_runtime(bundle)
    manifest, root = bundle
    remote = {}
    for name, stage in manifest["stages"].items():
        for repo in stage["repositories"]:
            index = (root / repo["index"]["path"]).read_bytes()
            compressed = lzma.compress(index)
            release_path = root / repo["inrelease"]["path"]
            release = release_path.read_bytes() + (
                f" {hashlib.sha256(compressed).hexdigest()} {len(compressed)} "
                "main/binary-amd64/Packages.xz\n").encode()
            release_path.write_bytes(release)
            repo["inrelease"] = descriptor(repo["inrelease"]["path"], release)
            base = acquire.ORIGINS[repo["suite"]]
            remote[f"{base}/dists/{repo['suite']}/InRelease"] = release
            remote[f"{base}/dists/{repo['suite']}/main/binary-amd64/by-hash/SHA256/"
                   f"{hashlib.sha256(compressed).hexdigest()}"] = compressed
        for package in stage["packages"]:
            remote[f"{acquire.ORIGINS[package['suite']]}/{package['record']['Filename']}"] = b"deb"
    calls = []

    class Response(io.BytesIO):
        status = 200
        headers = {}

        def geturl(self):
            return self.url

    def open_response(url, timeout):
        calls.append(url)
        response = Response(remote[url])
        response.url = url
        return response

    monkeypatch.setattr(acquire, "_open", open_response)
    return acquire, manifest, root, remote, calls


def run(acquisition, **kwargs):
    acquire, manifest, root, _, _ = acquisition
    return acquire.acquire_bundle(manifest, root, destination(root), now=NOW, **kwargs)


def test_complete_acquisition_verifies_real_data_before_receipt(acquisition):
    proof = run(acquisition)
    output = destination(acquisition[2])
    assert proof["signature_verified"] and proof["package_bytes_verified"]
    assert not proof["packages_installed"]
    assert proof["network_bytes"] > 0
    assert json.loads((output / "acquisition.json").read_text()) == proof
    assert proof["lock_sha256"] == hashlib.sha256((output / "lock.json").read_bytes()).hexdigest()
    assert (output / "builder/packages/tool.deb").read_bytes() == b"deb"
    assert proof["stages"]["runtime"]["base_inventory_measured_from_image"] is False


def test_locked_release_bytes_survive_mutable_metadata_rotation(acquisition):
    _, _, root, remote, calls = acquisition
    for url in remote:
        if url.endswith("/InRelease"):
            remote[url] = b"rotated metadata must not be used"
    proof = run(acquisition, release_root=root)
    assert proof["release_source"] == "locked-local"
    assert proof["signature_verified"] and proof["package_bytes_verified"]
    assert not any(url.endswith("/InRelease") for url in calls)
    assert any("/by-hash/SHA256/" in url for url in calls)
    assert any(url.endswith(".deb") for url in calls)


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_bad_locked_release_refuses_before_any_network(acquisition, damage):
    _, manifest, root, _, calls = acquisition
    binding = manifest["stages"]["builder"]["repositories"][0]["inrelease"]
    target = root / binding["path"]
    if damage == "missing":
        target.rename(target.with_name("quarantined-InRelease"))
    else:
        target.write_bytes(b"changed")
    with pytest.raises(LockContractError):
        run(acquisition, release_root=root)
    assert calls == []
    assert not destination(root).exists()


def test_locked_release_still_requires_signature(acquisition, monkeypatch):
    _, _, root, _, calls = acquisition

    def reject_signature(_):
        raise LockContractError("signature rejected")

    monkeypatch.setattr(auth, "authenticate_inrelease", reject_signature)
    with pytest.raises(LockContractError, match="signature rejected"):
        run(acquisition, release_root=root)
    assert calls == []
    assert not (destination(root) / "acquisition.json").exists()


def test_locked_release_still_requires_current_expiry(acquisition):
    acquire, manifest, root, _, calls = acquisition
    with pytest.raises(LockContractError, match="expired"):
        acquire.acquire_bundle(manifest, root, destination(root),
                               now=NOW + timedelta(days=30), release_root=root)
    assert calls == []
    assert not (destination(root) / "acquisition.json").exists()


@pytest.mark.parametrize("acquisition", ["trixie"], indirect=True)
def test_trixie_runtime_acquisition_uses_only_fixed_official_origins(acquisition):
    proof = run(acquisition)
    calls = acquisition[4]
    assert proof["signature_verified"] and proof["package_bytes_verified"]
    assert {repo["suite"] for repo in proof["stages"]["runtime"]["repositories"]} == {
        "trixie", "trixie-updates", "trixie-security"
    }
    assert "https://security.debian.org/debian-security/dists/trixie-security/InRelease" in calls
    assert "https://deb.debian.org/debian/dists/trixie/InRelease" in calls
    assert all(url.startswith(("https://deb.debian.org/debian/", "https://security.debian.org/debian-security/")) for url in calls)


@pytest.mark.parametrize("acquisition", ["trixie"], indirect=True)
def test_tampered_trixie_metadata_prevents_all_package_downloads(acquisition):
    _, _, root, remote, calls = acquisition
    url = next(url for url in remote if "/dists/trixie-security/InRelease" in url)
    remote[url] = b"untrusted metadata"
    with pytest.raises(LockContractError):
        run(acquisition)
    assert not any(url.endswith(".deb") for url in calls)
    assert not (destination(root) / "acquisition.json").exists()


@pytest.mark.parametrize("target", ["release", "index", "package"])
@pytest.mark.parametrize("damage", ["changed", "truncated", "extra"])
def test_tampered_download_cannot_create_success_receipt(acquisition, target, damage):
    _, _, root, remote, _ = acquisition
    key = next(url for url in remote if {"release": url.endswith("InRelease"),
                                        "index": "/by-hash/" in url,
                                        "package": url.endswith(".deb")}[target])
    data = remote[key]
    remote[key] = {"changed": bytes([data[0] ^ 1]) + data[1:],
                   "truncated": data[:-1], "extra": data + b"x"}[damage]
    with pytest.raises(LockContractError):
        run(acquisition)
    assert not (destination(root) / "acquisition.json").exists()


@pytest.mark.parametrize("reason", ["signature", "keyring", "expiry"])
def test_authentication_failure_prevents_package_acquisition(acquisition, monkeypatch, reason):
    if reason == "signature":
        def fail(payload):
            raise LockContractError("invalid signature")
        monkeypatch.setattr(auth, "authenticate_inrelease", fail)
    elif reason == "keyring":
        acquisition[1]["keyring_sha256"] = "d" * 64
    with pytest.raises(LockContractError):
        if reason == "expiry":
            a, manifest, root, _, _ = acquisition
            a.acquire_bundle(manifest, root, destination(root),
                             now=datetime(2026, 10, 8, tzinfo=timezone.utc))
        else:
            run(acquisition)
    assert not any(url.endswith(".deb") for url in acquisition[4])


def test_existing_destination_is_preserved_without_network(acquisition):
    output = destination(acquisition[2])
    output.mkdir()
    (output / "owner.txt").write_bytes(b"keep")
    with pytest.raises(LockContractError, match="destination"):
        run(acquisition)
    assert (output / "owner.txt").read_bytes() == b"keep"
    assert acquisition[4] == []


def test_bad_inventory_is_rejected_before_network(acquisition):
    (acquisition[2] / "builder/base.tsv").write_bytes(b"tampered")
    with pytest.raises(LockContractError):
        run(acquisition)
    assert acquisition[4] == []


@pytest.mark.parametrize("path", ["lock.json", "acquisition.json", "acquisition.pending.json", "README.txt", "_transport/owned"])
def test_manifest_cannot_overwrite_acquisition_control_files(acquisition, path):
    acquisition[1]["stages"]["builder"]["base_inventory"]["path"] = path
    with pytest.raises(LockContractError, match="reserved"):
        run(acquisition)
    assert acquisition[4] == []


def test_deadline_exhaustion_is_loud_and_retains_failed_output(acquisition, monkeypatch):
    a = acquisition[0]
    ticks = iter([0, 10000, 10000])
    monkeypatch.setattr(a.time, "monotonic", lambda: next(ticks, 10000))
    with pytest.raises(LockContractError, match="deadline"):
        run(acquisition)
    output = destination(acquisition[2])
    assert output.is_dir() and not (output / "acquisition.json").exists()


@pytest.mark.parametrize("headers,status,changed_url", [
    ({"Content-Encoding": "gzip"}, 200, False),
    ({"Content-Length": "99999"}, 200, False),
    ({}, 206, False), ({}, 200, True),
])
def test_http_transformations_and_redirects_are_rejected(acquisition, monkeypatch, headers, status, changed_url):
    a = acquisition[0]
    original = a._open
    def open_response(url, timeout):
        result = original(url, timeout)
        result.headers, result.status = headers, status
        if changed_url:
            result.url = "https://example.com/other"
        return result
    monkeypatch.setattr(a, "_open", open_response)
    with pytest.raises(LockContractError):
        run(acquisition)


@pytest.mark.parametrize("raw", [b"plain", lzma.compress(b"x" * 10000),
                                 lzma.compress(b"deb") + b"trailing",
                                 lzma.compress(b"deb") + lzma.compress(b"more")])
def test_xz_invalid_bomb_and_trailing_streams_are_rejected(acquisition, tmp_path, raw):
    source, target = tmp_path / "data.xz", tmp_path / "decoded"
    source.write_bytes(raw)
    binding = descriptor("decoded", b"deb")
    with pytest.raises(LockContractError):
        acquisition[0]._decompress(source, target, binding, float("inf"))
    assert not target.exists() or target.stat().st_size <= binding["size"]


def test_download_read_error_is_reported(acquisition, monkeypatch):
    def fail(url, timeout):
        raise OSError("network failed")
    monkeypatch.setattr(acquisition[0], "_open", fail)
    with pytest.raises(LockContractError, match="download"):
        run(acquisition)


def test_network_budget_is_checked_before_the_next_release(acquisition, monkeypatch):
    a, manifest, _, _, _ = acquisition
    first = manifest["stages"]["builder"]["repositories"][0]
    compressed = lzma.compress((acquisition[2] / first["index"]["path"]).read_bytes())
    monkeypatch.setattr(a, "_MAX_NETWORK", first["inrelease"]["size"] + len(compressed))
    with pytest.raises(LockContractError, match="aggregate"):
        run(acquisition)
    assert len(acquisition[4]) == 2, "the next release must not exceed the wire budget"


def test_invalid_clock_is_rejected_without_output_or_network(acquisition):
    a, manifest, root, _, calls = acquisition
    with pytest.raises(LockContractError, match="timezone"):
        a.acquire_bundle(manifest, root, destination(root), now=datetime(2026, 10, 3))
    assert not destination(root).exists() and not calls


def test_symlink_output_parent_is_rejected(acquisition, tmp_path):
    a, manifest, root, _, calls = acquisition
    parent = tmp_path / "linked-parent"
    try:
        parent.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("native Linux verifies symlink controls")
    with pytest.raises(LockContractError, match="symlink"):
        a.acquire_bundle(manifest, root, parent / "output", now=NOW)
    assert not calls


def test_actual_redirect_handler_refuses_redirect(acquisition):
    from urllib.request import Request
    with pytest.raises(LockContractError, match="redirect"):
        acquisition[0]._NoRedirect().redirect_request(Request("https://deb.debian.org/debian/x"),
                                                       None, 302, "Found", {}, "http://deb.debian.org/debian/x")


def test_receipt_write_failure_cannot_publish_a_partial_receipt(acquisition, monkeypatch):
    original_open = Path.open
    class BrokenReceipt:
        def __init__(self, handle):
            self.handle = handle
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def write(self, text):
            self.handle.write(text[:8])
            raise OSError("simulated disk full")
    def open_file(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        if path.name in {"acquisition.json", "acquisition.pending.json"} and mode == "x":
            return BrokenReceipt(handle)
        return handle
    monkeypatch.setattr(Path, "open", open_file)
    with pytest.raises(LockContractError, match="file operation"):
        run(acquisition)
    assert not (destination(acquisition[2]) / "acquisition.json").exists()


def test_cli_rejects_expiry_bypass_and_custom_origins(acquisition, monkeypatch):
    for option in ("--now", "--ignore-expiry", "--origin"):
        monkeypatch.setattr(sys, "argv", ["debian_acquire.py", "lock", "inventory", "output", option, "value"])
        with pytest.raises(SystemExit) as exc:
            acquisition[0].main()
        assert exc.value.code == 2
