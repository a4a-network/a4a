"""Unit tests for the release artifact inventory's fail-closed boundaries."""

from email.message import EmailMessage
import importlib.util
import io
import tarfile
import json
from pathlib import Path
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate-release-inventory.py"
SPEC = importlib.util.spec_from_file_location("release_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_wheel(path: Path, *, name: str = "a4a-sdk", version: str = "1.2.3") -> Path:
    metadata = EmailMessage()
    metadata["Metadata-Version"] = "2.4"
    metadata["Name"] = name
    metadata["Version"] = version
    metadata["License-Expression"] = "MIT"
    metadata["Requires-Python"] = ">=3.11"
    metadata["Requires-Dist"] = "example>=1"
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{dist_info}/METADATA", metadata.as_bytes())
        archive.writestr(f"{dist_info}/licenses/LICENSE", "MIT License\n")
    return path


def test_wheel_inventory_is_bound_to_bytes_and_metadata(tmp_path):
    wheel = make_wheel(tmp_path / "a4a_sdk-1.2.3-py3-none-any.whl")
    item = MODULE.wheel_inventory(wheel)
    assert item["name"] == "a4a-sdk"
    assert item["version"] == "1.2.3"
    assert item["license"] == "MIT"
    assert item["requires_dist"] == ["example>=1"]
    assert item["sha256"] == MODULE.sha256_bytes(wheel.read_bytes())


def test_wheel_inventory_rejects_missing_license_file(tmp_path):
    wheel = tmp_path / "broken.whl"
    metadata = b"Metadata-Version: 2.4\nName: a4a-sdk\nVersion: 1\nLicense-Expression: MIT\n\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("a4a_sdk-1.dist-info/METADATA", metadata)
    with pytest.raises(MODULE.InventoryError, match="no license file"):
        MODULE.wheel_inventory(wheel)


def test_exact_wheel_set_is_required(tmp_path):
    wheel = make_wheel(tmp_path / "a4a_sdk-1-py3-none-any.whl", version="1")
    with pytest.raises(MODULE.InventoryError, match="wheel set mismatch"):
        MODULE.validate_wheels([wheel])


def test_spdx_requires_version_packages_and_names():
    with pytest.raises(MODULE.InventoryError, match="SPDX 2.2"):
        MODULE.validate_spdx({}, image="relay")
    with pytest.raises(MODULE.InventoryError, match="no packages"):
        MODULE.validate_spdx({"spdxVersion": "SPDX-2.2", "packages": []}, image="relay")
    with pytest.raises(MODULE.InventoryError, match="unnamed"):
        MODULE.validate_spdx({"spdxVersion": "SPDX-2.2", "packages": [{}]}, image="relay")


def test_spdx_reports_unknown_licenses_without_claiming_completeness():
    summary = MODULE.validate_spdx(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {"name": "known", "licenseConcluded": "MIT"},
                {"name": "unknown", "licenseConcluded": "NOASSERTION"},
            ],
        },
        image="relay",
    )
    assert summary == {"package_count": 2, "unknown_license_count": 1}


def test_spdx_requires_named_application_packages():
    document = {
        "spdxVersion": "SPDX-2.2",
        "packages": [{"name": "a4a-sdk", "licenseConcluded": "MIT"}],
    }
    with pytest.raises(MODULE.InventoryError, match="a4a-mcp"):
        MODULE.validate_spdx(
            document,
            image="mcp",
            required_packages={"a4a-sdk", "a4a-mcp"},
        )


def write_review(tmp_path, *, evidence=b"license text", evidence_path="/licenses/COPYING"):
    review = {
        "schema": "a4a-license-review-v1",
        "packages": [{
            "images": ["mcp"],
            "name": "unknown",
            "version": "1.2.3",
            "license_expression": "MIT",
            "evidence_path": evidence_path,
            "evidence_sha256": MODULE.sha256_bytes(evidence),
            "source_url": "https://example.invalid/upstream/LICENSE",
            "distribution_notes": ["Preserve the license text."],
        }],
    }
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review), encoding="utf-8")
    return path


def unknown_document(*, version="1.2.3"):
    return {
        "spdxVersion": "SPDX-2.2",
        "packages": [{
            "name": "unknown",
            "versionInfo": version,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        }],
    }


def test_license_review_binds_exact_package_version_and_evidence(tmp_path, monkeypatch):
    evidence = b"license text"
    _, reviews = MODULE.load_license_review(write_review(tmp_path, evidence=evidence))
    monkeypatch.setattr(MODULE, "copy_image_file", lambda *args, **kwargs: evidence)

    verified = MODULE.verify_license_review(
        "mcp", "example:image", unknown_document(), reviews,
    )

    assert verified[0]["license_expression"] == "MIT"
    assert verified[0]["evidence_sha256"] == MODULE.sha256_bytes(evidence)


def test_license_review_rejects_new_or_version_drifted_noassertion(tmp_path):
    _, reviews = MODULE.load_license_review(write_review(tmp_path))
    with pytest.raises(MODULE.InventoryError, match="unreviewed NOASSERTION"):
        MODULE.verify_license_review(
            "mcp", "example:image", unknown_document(version="1.2.4"), reviews,
        )


def test_license_review_rejects_changed_artifact_evidence(tmp_path, monkeypatch):
    _, reviews = MODULE.load_license_review(write_review(tmp_path))
    monkeypatch.setattr(MODULE, "copy_image_file", lambda *args, **kwargs: b"changed license")
    with pytest.raises(MODULE.InventoryError, match="license evidence changed"):
        MODULE.verify_license_review(
            "mcp", "example:image", unknown_document(), reviews,
        )


def test_license_review_rejects_unsafe_evidence_path(tmp_path):
    path = write_review(tmp_path, evidence_path="/licenses/../secret")
    with pytest.raises(MODULE.InventoryError, match="unsafe evidence path"):
        MODULE.load_license_review(path)


def test_git_state_rejects_dirty_candidate(monkeypatch):
    responses = iter([b"abc123\n", b" M relay/Dockerfile\n"])
    monkeypatch.setattr(MODULE, "run", lambda command: next(responses))
    with pytest.raises(MODULE.InventoryError, match="working tree is dirty"):
        MODULE.git_state(allow_dirty=False)


def test_git_state_names_dirty_paths_for_diagnostic_run(monkeypatch):
    responses = iter([b"abc123\n", b" M relay/Dockerfile\n?? new-file\n"])
    monkeypatch.setattr(MODULE, "run", lambda command: next(responses))
    assert MODULE.git_state(allow_dirty=True) == {
        "commit": "abc123",
        "dirty": True,
        "changed_paths": [" M relay/Dockerfile", "?? new-file"],
    }


def test_output_is_restricted_to_repository_build_directory(tmp_path):
    with pytest.raises(MODULE.InventoryError, match="must be a child"):
        MODULE.write_inventory(
            tmp_path / "outside",
            images={},
            wheels=[],
            relay_builder_image="unused",
        )


def test_canonical_json_is_stable_and_terminated():
    assert MODULE.canonical_json({"b": 1, "a": 2}) == b'{\n  "a": 2,\n  "b": 1\n}\n'


def test_existing_output_is_preserved_before_any_external_command(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    output = tmp_path / "build/inventory"
    output.mkdir(parents=True)
    sentinel = output / "original.json"
    sentinel.write_bytes(b"old evidence must survive")
    monkeypatch.setattr(MODULE, "run", lambda *a, **kw: pytest.fail("no external command expected"))
    with pytest.raises(MODULE.InventoryError, match="already exists"):
        MODULE.write_inventory(output, images={}, wheels=[], relay_builder_image="unused")
    assert sentinel.read_bytes() == b"old evidence must survive"


@pytest.mark.parametrize("kind", ["file", "symlink", "traversal", "extra"])
def test_stopped_notice_carrier_checks_archive_without_starting_image(monkeypatch, kind):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("../copyright" if kind == "traversal" else "copyright")
        if kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "/private/key"
            archive.addfile(member)
        else:
            member.size = 6
            archive.addfile(member, io.BytesIO(b"notice"))
        if kind == "extra":
            archive.addfile(tarfile.TarInfo("extra"))
    calls = []
    def run(command):
        calls.append(command)
        return output.getvalue() if "cp" in command else b"carrier"
    monkeypatch.setattr(MODULE, "run", run)
    action = lambda: MODULE.copy_image_file("sha256:" + "a" * 64, "/usr/share/doc/tzdata/copyright", docker_context="desktop-linux")
    if kind == "file":
        assert action() == b"notice"
    else:
        with pytest.raises(MODULE.InventoryError, match="bounded regular file"):
            action()
    assert len(calls) == 2
    assert "create" in calls[0] and "none" in calls[0] and "--read-only" in calls[0]
    assert not any("start" in call or "run" in call or "rm" in call for call in calls)


def test_cargo_metadata_requires_a_verified_public_export(monkeypatch):
    monkeypatch.setattr(MODULE, "run", lambda *a, **kw: pytest.fail("no private mount expected"))
    with pytest.raises(MODULE.InventoryError, match="verified public source"):
        MODULE.relay_cargo_metadata("unused", docker_context="desktop-linux")


def test_cargo_metadata_mounts_only_the_export_with_offline_readonly_guards(tmp_path, monkeypatch):
    source = tmp_path / "export"
    source.mkdir()
    calls = []
    data = {"packages": [{"id": "root", "name": "nostr-rs-relay", "license": "MIT"}],
            "resolve": {"nodes": [{"id": "root"}]}}
    monkeypatch.setattr(MODULE, "verified_public_source", lambda path, **kwargs: {"git_commit": "a" * 40},
                        raising=False)

    def run(command):
        calls.append(command)
        return json.dumps(data).encode()

    monkeypatch.setattr(MODULE, "run", run)
    assert MODULE.relay_cargo_metadata("sha256:builder", public_source=source,
                                      docker_context="desktop-linux") == data
    command, = calls
    assert command[:3] == ["docker", "--context", "desktop-linux"]
    assert command[command.index("--mount") + 1] == f"type=bind,source={source.resolve()},target=/src,readonly"
    assert str(ROOT) not in command[command.index("--mount") + 1]
    assert "--offline" in command and "--locked" in command and "--read-only" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command
    assert "--tmpfs" in command and "CARGO_TARGET_DIR=/tmp/target" in command


def test_license_probe_uses_the_explicit_context_and_readonly_guards(tmp_path, monkeypatch):
    evidence = b"license text"
    _, reviews = MODULE.load_license_review(write_review(tmp_path, evidence=evidence))
    calls = []

    def run(command):
        calls.append(command)
        if "cp" not in command:
            return b"carrier\n"
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("COPYING")
            member.size = len(evidence)
            archive.addfile(member, io.BytesIO(evidence))
        return output.getvalue()

    monkeypatch.setattr(MODULE, "run", run)
    MODULE.verify_license_review("mcp", "sha256:" + "a" * 64, unknown_document(), reviews,
                                 docker_context="desktop-linux")
    command, copy = calls
    assert command[:3] == ["docker", "--context", "desktop-linux"]
    assert "--read-only" in command and "create" in command
    assert "run" not in command and "start" not in copy
    assert copy[:3] == ["docker", "--context", "desktop-linux"] and "cp" in copy and "-L" in copy
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command


def test_sbom_explicitly_inspects_all_retained_image_layers(monkeypatch):
    calls = []

    def run(command):
        calls.append(command)
        return b"raw SPDX"

    monkeypatch.setattr(MODULE, "run", run)
    assert MODULE.image_sbom("sha256:image", docker_context="desktop-linux") == b"raw SPDX"
    command, = calls
    assert command[:3] == ["docker", "--context", "desktop-linux"]
    assert command[command.index("--layers") + 1] == "all"


@pytest.mark.parametrize("context", ["", "bad context", "--host", "remote/unsafe"])
def test_docker_context_rejects_empty_or_option_like_names(context):
    with pytest.raises(MODULE.InventoryError, match="Docker context"):
        MODULE.docker_command(["image", "inspect", "unused"], context=context)


def test_public_source_must_match_the_inventory_git_commit(tmp_path, monkeypatch):
    verifier = type("Verifier", (), {"PublicSourceError": ValueError,
                                    "verify_directory": staticmethod(lambda path: {"git_commit": "a" * 40})})
    monkeypatch.setattr(MODULE, "load_public_source_verifier", lambda: verifier, raising=False)
    with pytest.raises(MODULE.InventoryError, match="different Git commit"):
        MODULE.verified_public_source(tmp_path, expected_commit="b" * 40)


def test_unverified_source_is_rejected_before_any_docker_command(tmp_path, monkeypatch):
    def invalid(path):
        raise ValueError("export contains extra private files")

    verifier = type("Verifier", (), {"PublicSourceError": ValueError,
                                    "verify_directory": staticmethod(invalid)})
    monkeypatch.setattr(MODULE, "load_public_source_verifier", lambda: verifier, raising=False)
    monkeypatch.setattr(MODULE, "run", lambda *a, **kw: pytest.fail("no Docker command expected"))
    with pytest.raises(MODULE.InventoryError, match="extra private files"):
        MODULE.relay_cargo_metadata("unused", public_source=tmp_path, docker_context="desktop-linux")


def test_duplicate_wheel_name_cannot_hide_an_extra_artifact(tmp_path):
    wheels = [make_wheel(tmp_path / (name + ".whl"), name=name)
              for name in sorted(MODULE.EXPECTED_WHEELS)]
    wheels.append(make_wheel(tmp_path / "duplicate.whl"))
    with pytest.raises(MODULE.InventoryError, match="wheel set mismatch"):
        MODULE.validate_wheels(wheels)


def test_inventory_rejects_missing_image_ecosystems_before_git(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "run", lambda *a, **kw: pytest.fail("no Git or Docker command expected"))
    with pytest.raises(MODULE.InventoryError, match="exactly mcp, notary and relay"):
        MODULE.write_inventory(tmp_path / "build/new", images={"mcp": "unused"}, wheels=[],
                               relay_builder_image="unused", docker_context="desktop-linux")
