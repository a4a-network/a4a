"""Keep relay image/tool inputs fixed without claiming an apt snapshot."""

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("stage, image", [
    (
        "builder",
        "docker.io/library/rust:1.98.1-bookworm@sha256:"
        "93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e",
    ),
    (
        "runtime",
        "docker.io/library/debian:trixie-slim@sha256:"
        "7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c",
    ),
])
def test_relay_base_images_are_the_verified_immutable_inputs(stage, image):
    dockerfile = (ROOT / "relay" / "Dockerfile").read_text(encoding="utf-8")
    bases = dict((name, base) for base, name in re.findall(
        r"^FROM ([^\s]+) AS ([\w-]+)$", dockerfile, re.MULTILINE))
    assert set(bases) == {"debian-bundle", "debian-tools", "debian-acquire", "debian-verify",
                          "builder-inputs", "builder", "runtime-inputs", "runtime-tools",
                          "runtime-filesystem", "runtime-prepare", "runtime"}
    assert bases[f"{stage}-inputs"] == image
    if stage == "builder":
        assert bases[stage] == f"{stage}-inputs"
        assert bases["debian-verify"] == bases["debian-acquire"] == image
    else:
        assert bases["runtime-tools"] == "runtime-inputs"
        assert bases["runtime-filesystem"] == "runtime-tools"
        assert bases["runtime-prepare"] == "debian-verify"
        assert bases["runtime"] == "scratch"
        assert "COPY --from=runtime-filesystem / /runtime/" in dockerfile
        assert "COPY --from=runtime-prepare /prepared/rootfs/ /" in dockerfile
        assert 'RUN --network=none --mount=type=tmpfs,target=/var/cache/ldconfig ["/usr/sbin/ldconfig"]' in dockerfile


def test_relay_auditable_tool_version_and_dependency_lock_are_explicit():
    dockerfile = (ROOT / "relay" / "Dockerfile").read_text(encoding="utf-8")
    installs = re.findall(r"^RUN USER=root cargo install (.+)$", dockerfile, re.MULTILINE)
    assert installs == ["--version 0.7.6 --locked cargo-auditable"]


def test_relay_release_builds_use_the_copied_cargo_lock():
    dockerfile = (ROOT / "relay" / "Dockerfile").read_text(encoding="utf-8")
    copy_lock = dockerfile.index("COPY ./Cargo.lock ./Cargo.lock")
    builds = list(re.finditer(r"^RUN cargo auditable build (.+)$", dockerfile, re.MULTILINE))
    assert len(builds) == 2
    assert all(build.start() > copy_lock for build in builds)
    assert all(build.group(1) == "--release --locked" for build in builds)
