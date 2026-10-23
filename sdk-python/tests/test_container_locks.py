"""Release containers must install a complete, hash-checked dependency closure."""

from pathlib import Path
import re
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
import pytest


ROOT = Path(__file__).resolve().parents[2]
BASE_DIGEST = "sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
COMPONENTS = {
    "mcp-server": ("sdk-python", "mcp-server"),
    "notary": ("sdk-python", "notary"),
}


def project_dependencies(directory: str) -> list[Requirement]:
    data = tomllib.loads((ROOT / directory / "pyproject.toml").read_text("utf-8"))
    return [Requirement(value) for value in data["project"]["dependencies"]]


def input_requirements(component: str) -> list[Requirement]:
    lines = (ROOT / component / "requirements.container.in").read_text("utf-8").splitlines()
    return [Requirement(line) for line in lines if line and not line.startswith("#")]


def locked_requirements(path: Path) -> dict[str, tuple[Version, int]]:
    text = path.read_text("utf-8")
    starts = list(re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==([^\s\\]+) \\\n", text))
    assert starts, f"no pinned requirements in {path}"
    locked = {}
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start():end]
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", block)
        assert hashes, f"{match.group(1)} has no SHA-256 in {path}"
        name = canonicalize_name(match.group(1))
        assert name not in locked, f"duplicate locked package {name} in {path}"
        locked[name] = (Version(match.group(2)), len(hashes))
    return locked


@pytest.mark.parametrize("component,projects", COMPONENTS.items())
def test_runtime_inputs_cover_exactly_public_project_dependencies(component, projects):
    declared = [dependency for project in projects for dependency in project_dependencies(project)]
    external = [
        dependency for dependency in declared
        if canonicalize_name(dependency.name) not in {"a4a-sdk"}
    ]
    inputs = input_requirements(component)
    assert {canonicalize_name(item.name) for item in inputs} == {
        canonicalize_name(item.name) for item in external
    }

    locked = locked_requirements(ROOT / component / "requirements.container.lock")
    for requirement in external:
        version = locked[canonicalize_name(requirement.name)][0]
        assert version in requirement.specifier, f"{requirement} rejects locked {version}"


def test_build_lock_is_hashed_and_satisfies_each_backend():
    locked = locked_requirements(ROOT / "scripts/container-build-requirements.lock")
    assert {"hatchling", "setuptools", "wheel"} <= set(locked)
    assert locked["setuptools"][0] >= Version("84")
    assert locked["hatchling"][0] >= Version("1")


@pytest.mark.parametrize("component", COMPONENTS)
def test_dockerfile_uses_pinned_base_and_hash_checked_multistage_install(component):
    dockerfile = (ROOT / component / "Dockerfile").read_text("utf-8")
    assert f"python:3.11-slim@{BASE_DIGEST}" in dockerfile
    assert re.findall(r"(?m)^FROM .+$", dockerfile) == [
        "FROM ${PYTHON_IMAGE} AS base", "FROM base AS builder",
        "FROM base AS runtime-build", "FROM base AS runtime-select", "FROM scratch",
    ]
    assert "COPY --from=runtime-build / /runtime/" in dockerfile
    assert "COPY --from=runtime-select /prepared/rootfs/ /" in dockerfile
    assert "A4A_PREPARE_PYTHON_FILESYSTEM=1 python -I -B /selection/prepare-python-filesystem.py" in dockerfile
    assert '--mount=type=tmpfs,target=/var/cache/ldconfig ["/usr/sbin/ldconfig"]' in dockerfile
    assert "container-build-requirements.lock" in dockerfile
    assert "requirements.container.lock" in dockerfile
    assert "container-pip-requirements.lock" in dockerfile
    assert dockerfile.count("--require-hashes") == 4
    assert "--no-build-isolation" in dockerfile
    assert "--no-index --no-deps" in dockerfile
    assert "pip install --no-cache-dir /app/" not in dockerfile
    assert "A4A_PREPARE_CONTAINER_RUNTIME=1 python -I -B /tmp/prepare-python-runtime.py" in dockerfile
    assert "USER 10001" in dockerfile


def test_lock_compiler_uses_same_pinned_linux_environment():
    compiler = (ROOT / "scripts" / "compile-container-locks.py").read_text("utf-8")
    assert BASE_DIGEST in compiler
    assert 'PIP_TOOLS_VERSION = "7.6.1"' in compiler
    assert '"--platform", "linux/amd64"' in compiler
    assert "--generate-hashes" in compiler


def test_docker_context_admits_only_the_shared_build_lock_from_scripts():
    rules = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "scripts/" not in rules
    assert "scripts/*" in rules
    assert "!scripts/container-build-requirements.lock" in rules
    assert "!scripts/prepare-python-filesystem.py" in rules
    assert "!scripts/prepare-relay-runtime.py" in rules
