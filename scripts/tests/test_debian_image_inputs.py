"""Offline installation kit controls; native Docker targets are separate proof."""
from datetime import datetime, timezone, timedelta
import hashlib
import importlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_debian_build_lock import bundle, NOW
from debian_lock_contract import LockContractError

ROOT = Path(__file__).resolve().parents[2]
NONCE = "a" * 32


def policy(manifest):
    from debian_refresh import lock_bytes
    return {"schema": "a4a-debian-refresh-policy-v1", "parent_lock_sha256": "f" * 64,
            "lock_sha256": hashlib.sha256(lock_bytes(manifest)).hexdigest(),
            "observed_at_utc": NOW.isoformat(), "usable_until_utc": (NOW + timedelta(days=1)).isoformat()}


def test_installable_kits_require_a_current_bound_refresh_policy(bundle):
    module = importlib.import_module("debian_image_inputs")
    manifest, root = bundle
    with pytest.raises(LockContractError, match="policy"):
        module.emit_kits(manifest, root, root / "no-policy", nonce=NONCE, now=NOW)
    assert not (root / "no-policy").exists()


def test_kit_deadline_is_not_later_than_authenticated_expiry(bundle):
    from test_debian_build_lock import descriptor
    module = importlib.import_module("debian_image_inputs")
    manifest, root = bundle
    for stage in manifest["stages"].values():
        for repo in stage["repositories"]:
            path = root / repo["inrelease"]["path"]
            raw = path.read_bytes().replace(b"Thu, 08 Oct 2026 00:00:00 UTC", b"Fri, 02 Oct 2026 12:00:00 UTC")
            path.write_bytes(raw)
            repo["inrelease"] = descriptor(repo["inrelease"]["path"], raw)
    output = root / "short-lived"
    module.emit_kits(manifest, root, output, nonce=NONCE, now=NOW, policy=policy(manifest))
    expected = int((NOW + timedelta(hours=12)).timestamp())
    assert int((output / "runtime/expires.unix").read_text()) == expected


def test_dockerfile_has_offline_installation_and_empty_context_defaults():
    source = (ROOT / "relay/Dockerfile").read_text()
    assert "FROM scratch AS debian-bundle" in source
    assert "FROM scratch AS debian-tools" in source
    assert "apt-get update" not in source and "apt-get install" not in source
    assert source.count("target=/tmp/a4a-debian-kit") == 2
    assert "AS builder-inputs" in source and "AS runtime-inputs" in source
    assert "DEBIAN_BUILD_NONCE" in source


@pytest.fixture
def kits(bundle):
    manifest, root = bundle
    module = importlib.import_module("debian_image_inputs")
    output = root / "kits"
    proof = module.emit_kits(manifest, root, output, nonce=NONCE, now=NOW, policy=policy(manifest))
    return module, manifest, root, output, proof


def test_emit_exact_package_bytes_and_expected_inventory(kits):
    _, _, _, output, proof = kits
    assert proof["packages_installed"] is False
    assert (output / "builder/packages/000.deb").read_bytes() == b"deb"
    assert (output / "runtime/after.expected.tsv").read_text() == "base\t1\tamd64\ntool\t2\tamd64\n"
    assert (output / "runtime/before.expected.tsv").read_text() == "base\t1\tamd64\n"
    receipt = json.loads((output / "runtime/verification.json").read_text())
    assert receipt["signature_verified"] and receipt["build_nonce"] == NONCE
    assert receipt["stages"]["runtime"]["base_inventory_measured_from_image"] is False


def test_installation_checks_precede_mutation_and_check_health(kits):
    script = (kits[3] / "runtime/install.sh").read_text()
    assert script.index("before.expected.tsv") < script.index("dpkg --install")
    assert script.index("files.sha256") < script.index("dpkg --install")
    assert script.index("dpkg --install") < script.index("after.expected.tsv")
    assert "dpkg --audit" in script and "apt-get check" in script
    assert "--force" not in script and "apt-get install" not in script
    assert "A4A_DEBIAN_INSTALL" in script
    assert "${Package}" in script and "${Architecture}" in script


@pytest.mark.parametrize("nonce", ["", "x", "z" * 32, "a" * 31, "a" * 33, "A" * 32])
def test_bad_nonce_is_rejected_before_output_or_verification(bundle, nonce):
    module = importlib.import_module("debian_image_inputs")
    manifest, root = bundle
    output = root / "invalid-nonce"
    with pytest.raises(LockContractError, match="nonce"):
        module.emit_kits(manifest, root, output, nonce=nonce, now=NOW, policy=policy(manifest))
    assert not output.exists()


def test_expired_bundle_cannot_emit_installable_kits(bundle):
    module = importlib.import_module("debian_image_inputs")
    manifest, root = bundle
    output = root / "expired"
    with pytest.raises(LockContractError, match="expired"):
        module.emit_kits(manifest, root, output, nonce=NONCE, now=datetime(2026, 10, 8, tzinfo=timezone.utc), policy=policy(manifest))
    assert not output.exists()


def test_tampered_bundle_cannot_emit_installable_kits(bundle):
    module = importlib.import_module("debian_image_inputs")
    manifest, root = bundle
    (root / "runtime/packages/tool.deb").write_bytes(b"bad")
    with pytest.raises(LockContractError):
        module.emit_kits(manifest, root, root / "bad-kits", nonce=NONCE, now=NOW, policy=policy(manifest))
    assert not (root / "bad-kits").exists()


def test_existing_kit_destination_is_preserved(kits):
    module, manifest, root, output, _ = kits
    with pytest.raises(LockContractError, match="destination"):
        module.emit_kits(manifest, root, output, nonce=NONCE, now=NOW, policy=policy(manifest))
    assert (output / "runtime/packages/000.deb").read_bytes() == b"deb"


def test_supported_builder_forces_fresh_verification_and_named_local_inputs():
    source = (ROOT / "scripts/build-relay-image.py").read_text()
    assert "--no-cache-filter" in source
    assert "debian-verify,builder-inputs,runtime-inputs" in source
    assert "uuid.uuid4().hex" in source
    assert "--build-context" in source
    assert "shell=True" not in source


@pytest.fixture
def build_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_relay", ROOT / "scripts/build-relay-image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_filtered_bundle_does_not_forward_unbound_files(bundle, build_module):
    manifest, root = bundle
    (root / "unrelated-private-file.txt").write_text("not a build input")
    destination = root / "filtered"
    build_module.filter_bundle(manifest, root, destination)
    assert not (destination / "unrelated-private-file.txt").exists()
    assert (destination / "runtime/packages/tool.deb").read_bytes() == b"deb"


def test_filtered_bundle_rejects_changed_bytes(bundle, build_module):
    manifest, root = bundle
    (root / "runtime/packages/tool.deb").write_bytes(b"bad")
    with pytest.raises(LockContractError, match="SHA256"):
        build_module.filter_bundle(manifest, root, root / "filtered")


def test_prepared_contexts_exclude_production_config_and_arbitrary_scripts(tmp_path, build_module):
    manifest, relay, tools = build_module.prepare_contexts(ROOT, tmp_path / "contexts")
    assert set(p.name for p in tools.iterdir()) == set(build_module.TOOLS)
    assert not (relay / "config.prod.toml").exists()
    assert not (relay / "target").exists()
    assert manifest["stages"]["runtime"]["base_inventory"]["size"] > 0
    assert (relay / "Cargo.lock").read_bytes() == (ROOT / "relay/Cargo.lock").read_bytes()
    with pytest.raises(LockContractError, match="destination"):
        build_module.prepare_contexts(ROOT, tmp_path / "contexts")


def test_build_command_repeats_actual_installation_for_each_nonce(tmp_path, build_module):
    commands = [build_module.build_command(tmp_path / "relay", tmp_path / "tools", nonce=nonce,
                tag="local:test", target="runtime-inputs", bundle=tmp_path / "bundle")
                for nonce in ("a" * 32, "b" * 32)]
    for nonce, command in zip(("a" * 32, "b" * 32), commands):
        assert command[command.index("--no-cache-filter") + 1].split(",") == [
            "debian-verify", "builder-inputs", "runtime-inputs", "debian-acquire"]
        assert f"DEBIAN_BUILD_NONCE={nonce}" in command
        assert f"debian-bundle={tmp_path / 'bundle'}" in command
        assert command[command.index("--platform") + 1] == "linux/amd64"
    assert commands[0] != commands[1]
