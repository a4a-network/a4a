# A4A MCP server as an HTTP service: for environments where the agent has no internet
# access and packages cannot be installed in its pod. Build from the repository ROOT:
#   docker build -f mcp-server/Dockerfile -t a4a-mcp:0.1.1 .
#
# By default, the image starts the HTTP transport on port 8765. The stdio transport remains
# the primary option for local connections (`python -m a4a_mcp`) and needs no image.
#
# WARNING: THE HTTP TRANSPORT AUTHENTICATES NOBODY. Anyone who can reach the port controls
# the agent and its keys. Never expose the port publicly: use an internal network and put
# your own gateway in front of it.
# Historical 2026-09-05 size: 274 MB unpacked, 63 MB as a file (previously 571 and 127):
# `COPY` pulled in whole directories, including 90-120 MB virtual environments, and deleting
# them in the same layer did not help because the layers remain. The fix is the root
# `.dockerignore`, not the Dockerfile.
ARG PYTHON_IMAGE=python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

FROM ${PYTHON_IMAGE} AS base

# The pinned official base predates these signed Debian security updates.
# Keep the already-installed binaries exact; do not perform a floating upgrade.
# A missing version or failed repository verification must stop the build.
RUN apt-get update --error-on=any \
    && apt-get install --yes --only-upgrade --no-remove --no-install-recommends \
        libpcre2-8-0=10.46-1~deb13u3 \
        liblzma5=5.8.1-1+deb13u2 \
        libssl3t64=3.5.7-1~deb13u3 \
        openssl=3.5.7-1~deb13u3 \
        openssl-provider-legacy=3.5.7-1~deb13u3 \
    && test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.46-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' liblzma5)" = '5.8.1-1+deb13u2' \
    && test "$(dpkg-query -W -f='${Version}' libssl3t64)" = '3.5.7-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' openssl)" = '3.5.7-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' openssl-provider-legacy)" = '3.5.7-1~deb13u3' \
    && rm -rf /var/lib/apt/lists/*

FROM base AS builder

WORKDIR /build
COPY scripts/container-pip-requirements.lock /tmp/container-pip-requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes \
        -r /tmp/container-pip-requirements.lock
COPY scripts/container-build-requirements.lock /tmp/container-build-requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
        -r /tmp/container-build-requirements.lock
COPY sdk-python/ /build/sdk-python/
COPY mcp-server/ /build/mcp-server/
RUN python -m pip wheel --no-cache-dir --no-deps --no-build-isolation \
        --wheel-dir /wheels /build/sdk-python /build/mcp-server

FROM base AS runtime-build

WORKDIR /app
COPY scripts/container-pip-requirements.lock /tmp/container-pip-requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes \
        -r /tmp/container-pip-requirements.lock
COPY mcp-server/requirements.container.lock /tmp/requirements.container.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
        -r /tmp/requirements.container.lock
COPY --from=builder /wheels/ /wheels/
RUN python -m pip install --no-cache-dir --no-index --no-deps \
        /wheels/a4a_sdk-*.whl /wheels/a4a_mcp-*.whl \
    && rm -rf /wheels /tmp/requirements.container.lock

# Strict privacy mode is a BUILD PROPERTY (finding 117).
#
# Not only amounts and addresses are public: so is the subject of the work, which belongs
# to our user's client. The integrator rightly rejected soft protection—an optional flag and
# a warning in the tool description. Their measurements showed that 25 out of 30 skills were
# not invoked until added to a mandatory list, and here the model also has an incentive to
# violate the rule (a request without a description attracts fewer responses).
#
# Therefore the policy file is placed next to the installed package by root, before switching
# to UID 10001. The server process cannot write to it, so neither can the model: it operates
# only through tools, which write solely to /keys and to paths explicitly provided to them.
# `A4A_PUBLIC_TEXT` CANNOT relax this restriction (it can only tighten it); otherwise a single
# manifest line could nullify the guarantee for which this image was built.
#
# Anyone who needs soft mode can build an image without this layer or run
# `python -m a4a_mcp` without the image; its existing default remains `allow`.
RUN python -c "import a4a_mcp, json, pathlib; \
p = pathlib.Path(a4a_mcp.__file__).with_name('policy.json'); \
p.write_text(json.dumps({'public_text': 'deny', 'locked': True}), encoding='utf-8'); \
print('build policy:', p)" \
    && chmod 444 "$(python -c "import a4a_mcp, pathlib; print(pathlib.Path(a4a_mcp.__file__).with_name('policy.json'))")"

# Agent keys live on a volume, not in the image: the image is shared, identities are not.
#
# `A4A_MCP_STATELESS` and `A4A_MCP_JSON` are explicit even though they are enabled by
# default: the gateway relies on "one POST, one JSON response", and a future default change
# would otherwise break it silently.
#
# `A4A_RELAY` is intentionally NOT set: the default is the network's public relay, which is
# unreachable from a closed cluster. Set the internal relay address in the manifest, or the
# first tool call will fail with a connection timeout.
#
# `A4A_HEADERS_URL` supplies Bitcoin block headers for timestamp verification
# (`a4a_check_authority`). Without internet access or a private Esplora instance, verification
# correctly reports "unverifiable": the source is unavailable; the tool is not broken (see
# its description).
# Unprivileged user: the agent's private key lives on a volume, so there is no reason to run
# the process as root. The numeric UID can be repeated in a cluster securityContext
# (runAsUser/fsGroup); without a matching UID, the volume would be accessible only to root
# and the server could not write the key.
RUN adduser --system --uid 10001 --group --home /keys a4a \
    && mkdir -p /keys && chown -R 10001:10001 /keys && chmod 700 /keys

COPY scripts/prepare-python-runtime.py /tmp/prepare-python-runtime.py
RUN A4A_PREPARE_CONTAINER_RUNTIME=1 python -I -B /tmp/prepare-python-runtime.py \
    && rm /tmp/prepare-python-runtime.py /tmp/container-pip-requirements.lock

# Select complete source-present packages after installer/privilege preparation.
# Keep every CPython/application/distribution file and the declared native/data
# dependencies; retain notices and exact selected package metadata.
FROM base AS runtime-select
COPY --from=runtime-build / /runtime/
COPY scripts/prepare-python-filesystem.py scripts/prepare-relay-runtime.py /selection/
RUN --network=none A4A_PREPARE_PYTHON_FILESYSTEM=1 python -I -B /selection/prepare-python-filesystem.py

# Only the selected filesystem enters image layers. Rebuild the loader cache
# without retaining its auxiliary cache or the original installer/tool payloads.
FROM scratch
COPY --from=runtime-select /prepared/rootfs/ /
RUN --network=none --mount=type=tmpfs,target=/var/cache/ldconfig ["/usr/sbin/ldconfig"]
WORKDIR /app
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    A4A_HOME=/keys \
    A4A_MCP_TRANSPORT=http \
    A4A_MCP_HOST=0.0.0.0 \
    A4A_MCP_PORT=8765 \
    A4A_MCP_PATH=/mcp \
    A4A_MCP_STATELESS=1 \
    A4A_MCP_JSON=1 \
    A4A_MANDATE_AUTO=0 \
    PYTHONUNBUFFERED=1
USER 10001
VOLUME ["/keys"]
EXPOSE 8765

# The owner issues the mandate with a separate command (A4A_MANDATE_AUTO=0 means the agent
# does not grant itself authority): docker exec <container> python -m a4a_mcp issue-mandate
ENTRYPOINT ["python", "-m", "a4a_mcp"]
