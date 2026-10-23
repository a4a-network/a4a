"""Offline packaging checks; artifact checks need build and the local backends."""

import configparser
from email.parser import BytesParser
from email.policy import default
from fnmatch import fnmatchcase
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGES = (
    ("sdk-python", "a4a"),
    ("mcp-server", "a4a_mcp"),
    ("agent-service", "a4a_agent"),
    ("notary", "a4a_notary"),
)


def project_config(directory):
    return tomllib.loads((ROOT / directory / "pyproject.toml").read_text("utf-8"))


def mit_license():
    # The root's trailing relay note is not part of the Python packages' license.
    return (ROOT / "LICENSE").read_text("utf-8").split("\n---\n", 1)[0].strip()


#: STRICT license comparison with the local source is deliberate and must not be relaxed.
#:
#: On 2026-09-16 this comparison caught CRLF in LICENSE. By itself, however, it does
#: NOT prove cross-machine reproducibility: the wheel and expected bytes come from the
#: same checkout and may change together. That is how 55 `.py` modules differing
#: between a `core.autocrlf=true` checkout and an LF checkout remained green.
#:
#: This remains a narrow local-build integrity guarantee. A separate test below builds
#: wheels from two checkouts and compares every member payload. It relies on `LICENSE`
#: and `*.py text eol=lf` in .gitattributes. It does not claim complete ZIP equality,
#: including headers and timestamps.
#:
#: The governing rule: a failing check has two explanations, "the check is wrong" and
#: "the check is right." The latter requires product work and therefore feels more
#: expensive. Before changing a check, name the PRODUCT FACT the change would hide.


@pytest.mark.parametrize("directory,package", PACKAGES)
def test_package_has_repository_mit_license(directory, package):
    config = project_config(directory)
    license_path = ROOT / directory / "LICENSE"
    assert license_path.is_file(), f"{directory} needs its own distributable LICENSE"
    assert license_path.read_text("utf-8").strip() == mit_license()
    assert config["project"]["license"] == "MIT"
    assert config["project"]["license-files"] == ["LICENSE"]
    if config["build-system"]["build-backend"] == "setuptools.build_meta":
        # SPDX metadata requires 77; the notary's corrected build requires 84.
        minimum = "84" if directory == "notary" else "77"
        assert config["build-system"]["requires"] == [f"setuptools>={minimum}"]


@pytest.mark.parametrize("directory,package", PACKAGES)
def test_package_discovery_is_explicit_and_scoped(directory, package):
    config = project_config(directory)
    if config["build-system"]["build-backend"] == "hatchling.build":
        assert config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [package]
    else:
        patterns = config.get("tool", {}).get("setuptools", {}).get("packages", {}).get(
            "find", {}).get("include", [])
        for name in (package, f"{package}.submodule"):
            assert any(fnmatchcase(name, pattern) for pattern in patterns), name
        for name in ("tests", "licenses", f"{package}_unrelated"):
            assert not any(fnmatchcase(name, pattern) for pattern in patterns), name


def test_mcp_description_has_no_universal_one_command_promise():
    description = project_config("mcp-server")["project"]["description"].lower()
    assert "\u043e\u0434\u043d\u043e\u0439 \u043a\u043e\u043c\u0430\u043d\u0434\u043e\u0439" not in description
    assert "one command" not in description
    assert "one-command" not in description


def test_notary_declares_sdk_as_runtime_dependency():
    # history, service, and __main__ import a4a outside Docker too.
    assert "a4a-sdk" in project_config("notary")["project"]["dependencies"]


def test_mcp_rejects_sdk_without_its_required_modules():
    from packaging.requirements import Requirement
    dependencies = [Requirement(value) for value in project_config("mcp-server")["project"]["dependencies"]]
    sdk = next(value for value in dependencies if value.name == "a4a-sdk")
    assert not sdk.specifier.contains("0.1.0")
    assert sdk.specifier.contains(project_config("sdk-python")["project"]["version"])


def test_ci_tests_and_audits_every_python_distribution():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    assert "-p 127.0.0.1:8080:8080" in workflow
    assert "python scripts/check-relay-runtime-contract.py" in workflow
    test_markers = {
        "sdk-python": "run: bash scripts/test-sdk.sh",
        "mcp-server": "working-directory: mcp-server",
        "agent-service": "working-directory: agent-service",
        "notary": "working-directory: notary",
    }
    assert {directory for directory, _ in PACKAGES} == set(test_markers)
    for marker in test_markers.values():
        assert marker in workflow

    for dockerfile in ("mcp-server/Dockerfile", "notary/Dockerfile"):
        assert f"dockerfile: {dockerfile}" in workflow
    assert "docker image inspect" in workflow
    assert "docker run --rm --network none" in workflow
    assert "Require material third-party notices in the runtime image" in workflow
    for name in (
        "pycryptodomex-LICENSE.rst",
        "python-bitcoinlib-LICENSE.txt",
    ):
        assert name in workflow
    assert "scripts/check-python-runtime-graph.py" in workflow
    assert "-m pip check" not in workflow
    assert 'user: notary' not in workflow
    assert 'test -s "$path" || exit 1' in workflow

    # Keep the audit list explicit so the shell cannot accidentally discover private or
    # non-distribution directories, but make this test fail whenever PACKAGES changes.
    audit_order = " ".join(directory for directory, _ in PACKAGES)
    assert f"for pkg in {audit_order}; do" in workflow
    for lock in (
        "scripts/container-build-requirements.lock",
        "mcp-server/requirements.container.lock",
        "notary/requirements.container.lock",
    ):
        assert f"pip-audit --progress-spinner off --no-deps -r {lock}" in workflow


def test_notary_container_carries_complete_opentimestamps_license_set():
    license_dir = ROOT / "notary" / "licenses"
    expected = {
        "python-opentimestamps-LICENSE.txt",
        "LGPL-3.0.txt",
        "GPL-3.0.txt",
        "pycryptodomex-3.23.0-native-NOTICES.txt",
        "pycryptodomex-LICENSE-libtom.txt",
        "CC0-1.0.txt",
    }
    assert {path.name for path in license_dir.iterdir() if path.is_file()} == expected
    for name in expected:
        assert (license_dir / name).stat().st_size > (50 if name == "pycryptodomex-LICENSE-libtom.txt" else 1000), name

    upstream = (license_dir / "python-opentimestamps-LICENSE.txt").read_text("utf-8")
    assert "python-opentimestamps is free software" in upstream
    assert "GNU Lesser General Public License" in upstream
    assert "GNU GENERAL PUBLIC LICENSE" in (
        license_dir / "GPL-3.0.txt").read_text("utf-8")
    native_notices = (license_dir / "pycryptodomex-3.23.0-native-NOTICES.txt").read_text("utf-8")
    assert "SipHash reference C implementation" in native_notices
    assert "Copyright (c) 2022, Helder Eijs" in native_notices
    assert "CC0 1.0 Universal" in (license_dir / "CC0-1.0.txt").read_text("utf-8")
    assert "LibTomCrypt is public domain" in (license_dir / "pycryptodomex-LICENSE-libtom.txt").read_text("utf-8")

    dockerfile = (ROOT / "notary" / "Dockerfile").read_text("utf-8")
    assert "COPY notary/licenses/ /app/licenses/" in dockerfile
    assert "/wheels/a4a_sdk-*.whl /wheels/a4a_notary-*.whl" in dockerfile
    assert "--no-index --no-deps" in dockerfile
    for name in (
        "pycryptodomex-LICENSE.rst",
        "python-bitcoinlib-LICENSE.txt",
    ):
        assert f"/app/licenses/{name}" in dockerfile
    # The application already defaults to /data/notary.key. Keeping a KEY-named ENV in
    # the image is unnecessary and makes BuildKit flag a possible baked-in secret.
    assert "A4A_NOTARY_KEY_FILE=" not in dockerfile
    notary_main = (ROOT / "notary" / "a4a_notary" / "__main__.py").read_text("utf-8")
    assert 'env.get("A4A_NOTARY_KEY_FILE", "/data/notary.key")' in notary_main
    dockerignore_rules = {
        line.strip() for line in (ROOT / ".dockerignore").read_text("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    # The notary image is built from the repository root, so excluding this directory
    # makes every COPY from notary/ fail before pip or the license checks can run.
    assert "notary/" not in dockerignore_rules
    notices = (ROOT / "THIRD_PARTY_LICENSES.md").read_text("utf-8")
    for name in expected:
        assert name in notices or (name in {"LGPL-3.0.txt", "GPL-3.0.txt"}
                                   and name.split(".", 1)[0] in notices)
    normalized_notices = " ".join(notices.split())
    assert "scripts/generate-release-inventory.py" in notices
    assert "refuses a dirty Git worktree" in normalized_notices
    assert "registry above must cover every such entry" in notices
    assert "not a legal opinion or automatic authorization to publish" in notices


def test_relay_preserves_upstream_license_and_reproducible_fork_provenance():
    cargo = tomllib.loads((ROOT / "relay" / "Cargo.toml").read_text("utf-8"))
    assert cargo["package"]["license"] == "MIT"
    upstream_license = (ROOT / "relay" / "LICENSE").read_text("utf-8")
    assert "MIT License" in upstream_license
    assert "Copyright (c) 2026 A4A Network (A4A Protocol)" in upstream_license

    readme = (ROOT / "relay" / "README.md").read_text("utf-8")
    assert "A4A" in readme
    third_party = (ROOT / "THIRD_PARTY_LICENSES.md").read_text("utf-8")
    assert "relay/LICENSE" in third_party
    dockerfile = (ROOT / "relay" / "Dockerfile").read_text("utf-8")
    assert dockerfile.count("cargo auditable build --release --locked") == 2
    assert 'CMD ["./nostr-rs-relay", "--db", "/usr/src/app/db"]' in dockerfile
    assert "CMD ./nostr-rs-relay" not in dockerfile


def build_artifact(source, output, kind, env):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "build", "--no-isolation", f"--{kind}",
         "--outdir", str(output), str(source)],
        cwd=source.parent, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    artifacts = list(output.glob("*.whl" if kind == "wheel" else "*.tar.gz"))
    assert len(artifacts) == 1, artifacts
    return artifacts[0]


def _isolated_git_env():
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def _git(args, *, cwd=ROOT):
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
        env=_isolated_git_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def _fixture_repository(destination):
    """Create the smallest source repository needed for the wheel comparison."""
    destination.mkdir()
    shutil.copy2(ROOT / ".gitattributes", destination / ".gitattributes")
    for directory, package in PACKAGES:
        source = ROOT / directory
        target = destination / directory
        target.mkdir()
        for filename in ("pyproject.toml", "LICENSE"):
            shutil.copy2(source / filename, target / filename)
        shutil.copytree(
            source / package,
            target / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

    _git(["init", "--quiet", "--template="], cwd=destination)
    _git(["config", "user.email", "packaging-test@example.invalid"], cwd=destination)
    _git(["config", "user.name", "Packaging test"], cwd=destination)
    _git(["config", "core.autocrlf", "false"], cwd=destination)
    _git(["add", "--", ".gitattributes", *(directory for directory, _ in PACKAGES)],
         cwd=destination)
    _git(["commit", "--quiet", "-m", "packaging fixture"], cwd=destination)
    top = Path(_git(["rev-parse", "--show-toplevel"], cwd=destination)).resolve()
    assert top == destination.resolve(), "packaging fixture must not inherit a parent .git"
    return _git(["rev-parse", "HEAD"], cwd=destination)


def _clone_at(repository, destination, commit, *, autocrlf):
    _git(["clone", "--shared", "--no-checkout", "--quiet", "--template=",
          str(repository), str(destination)], cwd=repository.parent)
    _git(["config", "core.autocrlf", "true" if autocrlf else "false"], cwd=destination)
    _git(["config", "core.eol", "native" if autocrlf else "lf"], cwd=destination)
    _git(["checkout", "--detach", "--quiet", commit], cwd=destination)
    assert not (destination / "ops").exists(), "packaging fixture must not checkout ops"


def test_git_fixture_ignores_ambient_state(tmp_path, monkeypatch):
    ambient = {
        "GIT_DIR": tmp_path / "ambient-git-dir",
        "GIT_WORK_TREE": tmp_path / "ambient-work-tree",
        "GIT_INDEX_FILE": tmp_path / "ambient-index",
    }
    hook_sentinel = tmp_path / "ambient-hook-ran"
    template = tmp_path / "ambient-template"
    hooks = template / "hooks"
    hooks.mkdir(parents=True)
    hook_script = (
        "#!/bin/sh\n"
        f"printf hook > {shlex.quote(hook_sentinel.as_posix())}\n"
        "exit 91\n"
    )
    for name in ("pre-commit", "post-checkout"):
        hook = hooks / name
        hook.write_text(hook_script, encoding="utf-8", newline="\n")
        hook.chmod(0o755)
    hostile_config = tmp_path / "ambient.gitconfig"
    hostile_config.write_text(
        f'[core]\n\thooksPath = "{hooks.as_posix()}"\n'
        f'[init]\n\ttemplateDir = "{template.as_posix()}"\n',
        encoding="utf-8", newline="\n",
    )
    hostile_config_before = hostile_config.read_bytes()
    for name, path in ambient.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile_config))
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(template))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hooks))

    repository = tmp_path / "source"
    commit = _fixture_repository(repository)
    _clone_at(repository, tmp_path / "checkout", commit, autocrlf=True)

    assert all(not path.exists() for path in ambient.values())
    assert not hook_sentinel.exists()
    assert hostile_config.read_bytes() == hostile_config_before


def _wheel_members(path):
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_packaged_source_eol_contract_is_explicit():
    rules = {line.split("#", 1)[0].strip()
             for line in (ROOT / ".gitattributes").read_text("utf-8").splitlines()}
    assert "*.py text eol=lf" in rules
    assert "LICENSE text eol=lf" in rules


def test_wheel_member_payloads_do_not_depend_on_checkout_eol(tmp_path):
    pytest.importorskip("build", reason="artifact comparison needs local build tooling")
    from packaging.requirements import Requirement

    try:
        version("build")
    except PackageNotFoundError:
        pytest.skip("artifact comparison needs the local build frontend: pip install build")
    for directory, _ in PACKAGES:
        for spec in project_config(directory)["build-system"]["requires"]:
            requirement = Requirement(spec)
            if requirement.marker and not requirement.marker.evaluate():
                continue
            try:
                installed = version(requirement.name)
            except PackageNotFoundError:
                pytest.skip(f"artifact comparison needs local {spec}")
            if installed not in requirement.specifier:
                pytest.skip(f"artifact comparison needs {spec}, found {installed}")

    repository = tmp_path / "source"
    commit = _fixture_repository(repository)
    checkouts = {"autocrlf": tmp_path / "autocrlf", "lf": tmp_path / "lf"}
    _clone_at(repository, checkouts["autocrlf"], commit, autocrlf=True)
    _clone_at(repository, checkouts["lf"], commit, autocrlf=False)
    env = {**_isolated_git_env(), "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}

    for directory, package in PACKAGES:
        relative_sources = sorted(
            path.relative_to(checkouts["autocrlf"] / directory).as_posix()
            for path in (checkouts["autocrlf"] / directory / package).rglob("*.py"))
        assert relative_sources
        for relative in relative_sources:
            left = (checkouts["autocrlf"] / directory / relative).read_bytes()
            right = (checkouts["lf"] / directory / relative).read_bytes()
            assert left == right, f"checkout EOL changed {directory}/{relative}"
            assert b"\r\n" not in left, f"non-canonical CRLF in {directory}/{relative}"

        wheels = {}
        for mode, checkout in checkouts.items():
            wheels[mode] = build_artifact(
                checkout / directory, tmp_path / f"wheel-{mode}-{directory}",
                "wheel", env)
        left, right = (_wheel_members(wheels[mode]) for mode in ("autocrlf", "lf"))
        assert left.keys() == right.keys(), directory
        changed = sorted(name for name in left if left[name] != right[name])
        assert not changed, f"checkout EOL changed wheel payloads for {directory}: {changed}"


def check_metadata(raw, config):
    from packaging.requirements import Requirement

    metadata = BytesParser(policy=default).parsebytes(raw)
    project = config["project"]
    assert metadata["Name"] == project["name"]
    assert metadata["Version"] == project["version"]
    assert metadata["Requires-Python"] == project["requires-python"]
    assert metadata["Summary"] == project["description"]
    assert metadata.get_all("License-File") == ["LICENSE"]
    assert metadata["License-Expression"] == "MIT" or (
        "MIT License" in (metadata["License"] or "")
        and "Copyright (c) 2026 A4A Network (A4A Protocol)" in metadata["License"]
    )
    expected = {Requirement(item) for item in project.get("dependencies", [])}
    for extra, requirements in project.get("optional-dependencies", {}).items():
        for item in requirements:
            requirement = Requirement(item)
            separator = " and " if requirement.marker else "; "
            expected.add(Requirement(f'{requirement}{separator}extra == "{extra}"'))
    assert {Requirement(item) for item in metadata.get_all("Requires-Dist", [])} == expected
    assert set(metadata.get_all("Provides-Extra", [])) == set(project.get("optional-dependencies", {}))


def check_wheel(path, sources, config):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert {name for name in names if name.endswith(".py")} == set(sources)
        for name, content in sources.items():
            assert archive.read(name) == content, name
            # Previously missing boundary: the package must contain CANONICAL line
            # endings, not whatever the build machine provides. The comparison above
            # misses this because a CRLF checkout changes both wheel and local source.
            assert b"\r\n" not in archive.read(name), f"CRLF in packaged file {name}"

        licenses = [name for name in names if name.endswith("/LICENSE")]
        assert len(licenses) == 1, licenses
        assert ".dist-info/" in licenses[0]
        assert archive.read(licenses[0]).decode("utf-8").strip() == mit_license()
        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        assert len(metadata_paths) == 1
        check_metadata(archive.read(metadata_paths[0]), config)
        if config["project"].get("scripts"):
            entry_path = metadata_paths[0].removesuffix("METADATA") + "entry_points.txt"
            entries = configparser.ConfigParser()
            entries.read_string(archive.read(entry_path).decode("utf-8"))
            assert dict(entries["console_scripts"]) == config["project"]["scripts"]


@pytest.mark.parametrize("directory,package", PACKAGES)
def test_wheel_and_sdist_are_complete_and_self_contained(directory, package, tmp_path):
    pytest.importorskip("build", reason="artifact inspection needs local build tooling")
    from packaging.requirements import Requirement

    # The guard checked only the backend from build-system.requires but builds through
    # `python -m build`, a second dependency path it did not verify. Without the
    # frontend, the test failed with a subprocess message that described only a symptom.
    #
    # Do not probe the frontend BY MODULE NAME: the repository root contains `build/`,
    # and `find_spec("build")` sees it as a namespace package, silently hiding a missing
    # distribution. This was found when the guard failed to fire on 2026-09-08. Query
    # the INSTALLED distribution, just as the line below does for the backend.
    try:
        version("build")
    except PackageNotFoundError:
        pytest.skip("artifact inspection needs the local build frontend: pip install build")

    config = project_config(directory)
    for spec in config["build-system"]["requires"]:
        requirement = Requirement(spec)
        if requirement.marker and not requirement.marker.evaluate():
            continue
        try:
            installed = version(requirement.name)
        except PackageNotFoundError:
            pytest.skip(f"artifact inspection needs local {spec}")
        if installed not in requirement.specifier:
            pytest.skip(f"artifact inspection needs {spec}, found {installed}")

    source = tmp_path / "source"
    source.mkdir()
    original = ROOT / directory
    # Copy only packaging inputs and source, never a venv, profile, or stale build.
    for name in ("pyproject.toml", "LICENSE", "README.md"):
        if (original / name).is_file():
            shutil.copy2(original / name, source / name)
    shutil.copytree(original / package, source / package,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if (original / "licenses").is_dir():
        shutil.copytree(original / "licenses", source / "licenses")
    sources = {path.relative_to(source).as_posix(): path.read_bytes()
               for path in (source / package).rglob("*.py")}
    assert sources
    env = {**os.environ, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}

    wheel = build_artifact(source, tmp_path / "wheel", "wheel", env)
    check_wheel(wheel, sources, config)
    sdist = build_artifact(source, tmp_path / "sdist", "sdist", env)
    unpacked = tmp_path / "unpacked"
    with tarfile.open(sdist) as archive:
        members = archive.getmembers()
        roots = {member.name.split("/")[0] for member in members}
        assert len(roots) == 1, roots
        prefix = roots.pop()
        for name, content in sources.items():
            assert archive.extractfile(f"{prefix}/{name}").read() == content, name
        assert archive.extractfile(f"{prefix}/LICENSE").read().decode("utf-8").strip() == mit_license()
        check_metadata(archive.extractfile(f"{prefix}/PKG-INFO").read(), config)
        archive.extractall(unpacked, filter="data")

    rebuilt = build_artifact(unpacked / prefix, tmp_path / "rebuilt-wheel", "wheel", env)
    check_wheel(rebuilt, sources, config)
