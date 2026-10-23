"""Container dependency updates must not expose the private checkout to a resolver."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "compile_container_locks", ROOT / "scripts" / "compile-container-locks.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for source, output in MODULE.LOCKS:
        (root / source).parent.mkdir(parents=True, exist_ok=True)
        (root / source).write_text("example>=1\n", encoding="utf-8")
        (root / output).write_text("old lock\n", encoding="utf-8")
    private = root / ".private" / "must-not-be-mounted.txt"
    private.parent.mkdir()
    private.write_text("private fixture\n", encoding="utf-8")
    return root


def generated_lock():
    return "example==2 \\" + "\n    --hash=sha256:" + "a" * 64 + "\n"


def test_stage_contains_only_explicit_public_inputs_and_locks(tmp_path):
    root = fixture_root(tmp_path)
    stage, originals = MODULE.prepare_stage(root)
    assert stage.is_relative_to(root / "build" / "container-lock-runs")
    assert stage != root
    expected = {item for pair in MODULE.LOCKS for item in pair}
    assert {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()} == expected
    assert set(originals) == expected
    assert not (stage / ".private").exists()


def test_container_mounts_the_stage_not_the_checkout(tmp_path):
    root = fixture_root(tmp_path)
    stage, _ = MODULE.prepare_stage(root)
    command = MODULE.container_command(stage)
    assert f"type=bind,source={stage},target=/src" in command
    assert f"type=bind,source={root},target=/src" not in command
    assert "--cap-drop" in command and "ALL" in command
    assert "no-new-privileges" in command
    shell = command[-1]
    bootstrap = shell.index("-r scripts/container-pip-requirements.lock")
    assert bootstrap < shell.index("pip-tools==") < shell.index("pip-compile")
    assert "--require-hashes" in shell
    assert "--upgrade-package pyjwt" in shell
    assert " --upgrade " not in shell


def test_failed_compiler_preserves_all_original_locks(tmp_path, monkeypatch):
    root = fixture_root(tmp_path)
    monkeypatch.setattr(MODULE, "ROOT", root)
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a[0], 7))
    assert MODULE.main() == 7
    assert all((root / output).read_text(encoding="utf-8") == "old lock\n" for _, output in MODULE.LOCKS)
    assert len(list((root / "build" / "container-lock-runs").iterdir())) == 1


def test_all_outputs_validate_before_any_lock_is_replaced(tmp_path):
    root = fixture_root(tmp_path)
    stage, originals = MODULE.prepare_stage(root)
    for _, output in MODULE.LOCKS:
        (stage / output).write_text(generated_lock(), encoding="utf-8")
    (stage / MODULE.LOCKS[-1][1]).write_text("example==2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        MODULE.publish_outputs(root, stage, originals)
    assert all((root / output).read_text(encoding="utf-8") == "old lock\n" for _, output in MODULE.LOCKS)


def test_concurrent_source_changes_are_not_overwritten(tmp_path):
    root = fixture_root(tmp_path)
    stage, originals = MODULE.prepare_stage(root)
    for _, output in MODULE.LOCKS:
        (stage / output).write_text(generated_lock(), encoding="utf-8")
    changed = root / MODULE.LOCKS[-1][1]
    changed.write_text("another author's edit\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        MODULE.publish_outputs(root, stage, originals)
    assert changed.read_text(encoding="utf-8") == "another author's edit\n"
    assert (root / MODULE.LOCKS[0][1]).read_text(encoding="utf-8") == "old lock\n"


def test_resolver_cannot_change_its_inputs(tmp_path):
    root = fixture_root(tmp_path)
    stage, originals = MODULE.prepare_stage(root)
    for _, output in MODULE.LOCKS:
        (stage / output).write_text(generated_lock(), encoding="utf-8")
    (stage / MODULE.LOCKS[-1][0]).write_text("changed input\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Resolver changed"):
        MODULE.publish_outputs(root, stage, originals)
    assert all((root / output).read_text(encoding="utf-8") == "old lock\n" for _, output in MODULE.LOCKS)


def test_reparse_inputs_are_rejected_before_their_contents_are_read(tmp_path, monkeypatch):
    root = fixture_root(tmp_path)
    original = Path.lstat
    target = root / MODULE.LOCKS[0][0]

    def linked_lstat(path):
        info = original(path)
        if path == target:
            class ReparseInfo:
                st_mode = info.st_mode
                st_file_attributes = MODULE.stat.FILE_ATTRIBUTE_REPARSE_POINT
            return ReparseInfo()
        return info

    # A synthetic reparse point works without privileged Windows symlink creation.
    monkeypatch.setattr(MODULE.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, raising=False)
    monkeypatch.setattr(Path, "lstat", linked_lstat)
    with pytest.raises(ValueError, match="Linked"):
        MODULE.prepare_stage(root)
    assert not (root / "build").exists()


def test_only_generated_locks_are_published_and_stage_is_retained(tmp_path):
    root = fixture_root(tmp_path)
    stage, originals = MODULE.prepare_stage(root)
    for _, output in MODULE.LOCKS:
        (stage / output).write_text(generated_lock(), encoding="utf-8")
    (stage / "extra.txt").write_text("do not copy me\n", encoding="utf-8")
    MODULE.publish_outputs(root, stage, originals)
    assert all((root / output).read_text(encoding="utf-8") == generated_lock() for _, output in MODULE.LOCKS)
    assert not (root / "extra.txt").exists()
    assert stage.is_dir()


@pytest.mark.parametrize("content", [
    "example==2\n",
    "--index-url https://example.invalid\n",
    "example @ https://example.invalid/a.whl\n",
    "example>=2 --hash=sha256:" + "a" * 64 + "\n",
    "example==2 \\" + "\n    --hash=md5:" + "a" * 32 + "\n",
])
def test_invalid_lock_output_is_rejected(tmp_path, content):
    path = tmp_path / "invalid.lock"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        MODULE.validate_lock(path)


@pytest.mark.parametrize("path", ["mcp-server/Dockerfile", "notary/Dockerfile"])
def test_python_base_digest_and_bounded_os_fixes_match(path):
    dockerfile = (ROOT / path).read_text(encoding="utf-8")
    base = re.search(r"^ARG PYTHON_IMAGE=(.+)$", dockerfile, re.MULTILINE)
    assert base and base.group(1) == MODULE.PYTHON_IMAGE
    assert re.fullmatch(r"python:3\.11-slim@sha256:[0-9a-f]{64}", base.group(1))
    assert MODULE.PYTHON_IMAGE.endswith(
        "e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
    )
    patch_stage = dockerfile.split("FROM ${PYTHON_IMAGE} AS base", 1)[1].split("FROM base AS builder", 1)[0]
    assert "apt-get update --error-on=any" in patch_stage
    assert "--only-upgrade --no-remove --no-install-recommends" in patch_stage
    expected = {
        "libpcre2-8-0": "10.46-1~deb13u3",
        "liblzma5": "5.8.1-1+deb13u2",
        "libssl3t64": "3.5.7-1~deb13u3",
        "openssl": "3.5.7-1~deb13u3",
        "openssl-provider-legacy": "3.5.7-1~deb13u3",
    }
    pins = re.findall(r"^\s+([a-z0-9-]+)=([a-z0-9.+~:-]+)\s*\\?$", patch_stage, re.MULTILINE)
    assert dict(pins) == expected and len(pins) == len(expected)
    for package, version in expected.items():
        assert (f"test \"$(dpkg-query -W -f='${{Version}}' {package})\" = '{version}'"
                in patch_stage)
    assert "FROM base AS runtime-build" in dockerfile
    assert not any(option in patch_stage for option in (
        "--allow-unauthenticated", "--allow-insecure", "trusted=yes",
        "Check-Valid-Until=false", "AllowInsecureRepositories", "apt-get upgrade",
    ))


def test_python_images_use_identical_os_patch_steps():
    patches = []
    for path in ("mcp-server/Dockerfile", "notary/Dockerfile"):
        dockerfile = (ROOT / path).read_text(encoding="utf-8")
        patches.append(dockerfile.split("FROM ${PYTHON_IMAGE} AS base", 1)[1]
                       .split("FROM base AS builder", 1)[0])
    assert patches[0] == patches[1]


@pytest.mark.parametrize("path", ["mcp-server/Dockerfile", "notary/Dockerfile"])
def test_both_image_stages_bootstrap_hash_checked_pip(path):
    dockerfile = (ROOT / path).read_text(encoding="utf-8")
    matches = re.findall(r"(?ms)^FROM base AS ([^\n]+)\n(.*?)(?=^FROM |\Z)", dockerfile)
    assert len(matches) == 3
    stages = dict(matches)
    assert set(stages) == {"builder", "runtime-build", "runtime-select"}
    assert "python -m pip" not in stages["runtime-select"]
    for name in ("builder", "runtime-build"):
        stage = stages[name]
        assert stage.index("COPY scripts/container-pip-requirements.lock") < stage.index("RUN python -m pip")
        first_run = stage[stage.index("RUN python -m pip"):].split("\nCOPY ")[0]
        assert "--only-binary=:all:" in first_run
        assert "--no-deps" in first_run
        assert "--require-hashes" in first_run
        assert "-r /tmp/container-pip-requirements.lock" in first_run


def test_bootstrap_lock_is_in_the_docker_context():
    assert "!scripts/container-pip-requirements.lock" in (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "!scripts/prepare-python-runtime.py" in (ROOT / ".dockerignore").read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [
    "scripts/container-build-requirements.lock",
])
def test_corrected_installer_and_backend_remain_in_the_build_lock(path):
    content = (ROOT / path).read_text(encoding="utf-8")
    assert "\npip==26.2.1 \\" in content
    assert "\nsetuptools==84.0.0 \\" in content
    MODULE.validate_lock(ROOT / path)


@pytest.mark.parametrize("project", ["mcp-server", "notary"])
def test_runtime_locks_do_not_include_build_only_installers(project):
    content = (ROOT / project / "requirements.container.lock").read_text(encoding="utf-8")
    assert not any(line.startswith(("pip==", "setuptools==", "wheel=="))
                   for line in content.splitlines())
    MODULE.validate_lock(ROOT / project / "requirements.container.lock")
    inputs = (ROOT / project / "requirements.container.in").read_text(encoding="utf-8")
    assert not any(line.startswith(("pip==", "setuptools==", "wheel=="))
                   for line in inputs.splitlines())


@pytest.mark.parametrize("path", ["mcp-server/Dockerfile", "notary/Dockerfile"])
def test_final_image_does_not_inherit_installer_payload_layers(path):
    dockerfile = (ROOT / path).read_text(encoding="utf-8")
    assert "FROM base AS runtime-build" in dockerfile
    runtime, selection_and_final = dockerfile.split("FROM base AS runtime-select", 1)
    selection, final = selection_and_final.rsplit("FROM scratch", 1)
    assert "prepare-python-runtime.py" in runtime
    assert "A4A_PREPARE_CONTAINER_RUNTIME=1 python -I -B" in runtime
    assert "COPY --from=runtime-build / /runtime/" in selection
    assert "prepare-python-filesystem.py" in selection
    assert "RUN --network=none A4A_PREPARE_PYTHON_FILESYSTEM=1 python -I -B" in selection
    assert "COPY --from=runtime-select /prepared/rootfs/ /" in final
    assert "COPY --from=runtime-build" not in final
    assert "python -m pip" not in final
    assert "USER " in final
    assert "LANG=C.UTF-8" in final
    assert "PATH=/usr/local/bin:" in final
