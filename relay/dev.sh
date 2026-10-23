#!/usr/bin/env bash
# Rust dev-loop for the vendored relay fork, run entirely inside Docker
# (Rust is intentionally not installed on the host).
#
# Usage:
#   bash relay/dev.sh build            # cargo build
#   bash relay/dev.sh build --release  # cargo build --release
#   bash relay/dev.sh test             # cargo test
#   bash relay/dev.sh <any cargo subcommand + args>
#
# One-time setup (build the builder image):
#   docker build -f relay/Dockerfile.dev -t a4a-relay-builder relay/
#
# Caching: the cargo registry (~/.cargo/registry equivalent inside the
# container, /usr/local/cargo/registry) and the crate's target/ directory are
# each backed by a Docker named volume, so they persist across `docker run`
# invocations. First run downloads + compiles everything from scratch
# (several minutes); subsequent runs with no source changes are near-instant,
# and runs with small source changes only recompile what changed.
set -euo pipefail

IMAGE=a4a-relay-builder
CARGO_REGISTRY_VOLUME=a4a-relay-cargo-registry
TARGET_VOLUME=a4a-relay-target

# --- Resolve the relay/ directory as an absolute, Docker-Desktop-friendly path ---
# This script lives in relay/, so its own directory IS the build context/crate root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# On Windows + Git Bash, `pwd` returns an MSYS-style path (e.g. /c/path/to/a4a/relay).
# That format is NOT understood by the Docker CLI's -v flag on Windows, and Git Bash's
# automatic path conversion also likes to mangle any argument that *looks* like a path
# (including the container-side "/app"), which breaks the mount entirely.
# Fix, in order:
#   1. If `cygpath` is available (Git Bash ships it), convert to a native Windows path
#      (C:/path/to/a4a/relay) which docker.exe understands directly.
#   2. Set MSYS_NO_PATHCONV=1 so Git Bash does NOT try to rewrite the container-side
#      paths (/app, /usr/local/cargo/registry, /app/target) into bogus Windows paths.
if command -v cygpath >/dev/null 2>&1; then
    HOST_RELAY_DIR="$(cygpath -w "$SCRIPT_DIR")"
else
    HOST_RELAY_DIR="$SCRIPT_DIR"
fi

export MSYS_NO_PATHCONV=1

if [ "$#" -eq 0 ]; then
    echo "Usage: bash relay/dev.sh <cargo subcommand> [args...]" >&2
    echo "e.g.:  bash relay/dev.sh build" >&2
    echo "       bash relay/dev.sh test" >&2
    exit 1
fi

# The target volume is shared by every checkout (the main tree, worker worktrees,
# temporary copies), and all of them are mounted at the same /app. Cargo decides whether
# this crate is fresh from file modification times, so a checkout with older sources than
# another checkout's last build silently runs THAT checkout's binaries. On 2026-09-23 a
# clean worker checkout ran tests compiled from a deliberately broken mutation-testing
# checkout; two accepted tests failed on code that was not in its tree. The reverse is
# worse: a broken tree can pass on someone else's good binary.
#
# Mounting each checkout at its own path does NOT help: that was tried and reproduced the
# same failure, because the path is not part of cargo's fingerprint for this crate.
#
# So the volume records which checkout built last. When a different checkout builds, this
# crate's artifacts are cleaned first; registry dependencies stay cached. The whole run
# holds a lock on the volume, so two checkouts cannot interleave clean, build, and test.
CHECKOUT_KEY="$(printf '%s' "$HOST_RELAY_DIR" | cksum | cut -d' ' -f1)"
GUARD='mkdir -p target && exec 9>target/.dev.lock && flock 9 && '
# The command substitution must run in the container after acquiring its lock.
# shellcheck disable=SC2016
GUARD+='if [ "$(cat target/.last-checkout 2>/dev/null)" != "'"$CHECKOUT_KEY"'" ]; then '
GUARD+='echo "dev.sh: another checkout built last; cleaning nostr-rs-relay artifacts" >&2; '
GUARD+='cargo clean --offline -p nostr-rs-relay >&2 || exit 1; fi; '
GUARD+='echo '"$CHECKOUT_KEY"' > target/.last-checkout && '

exec docker run --rm \
    -v "${HOST_RELAY_DIR}:/app" \
    -w /app \
    -v "${CARGO_REGISTRY_VOLUME}:/usr/local/cargo/registry" \
    -v "${TARGET_VOLUME}:/app/target" \
    "${IMAGE}" \
    bash -c "${GUARD}cargo $*"
