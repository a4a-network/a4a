# The A4A time notary is a relay sidecar. Build it from the repository root:
#   docker build -f notary/Dockerfile -t a4a-notary:0.1.4 .
# (the context is the root because the notary needs the local a4a-sdk from sdk-python/).
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
COPY notary/ /build/notary/
RUN python -m pip wheel --no-cache-dir --no-deps --no-build-isolation \
        --wheel-dir /wheels /build/sdk-python /build/notary

FROM base AS runtime-build

# Run as an unprivileged user and keep state in the /data volume. The notary key is created
# there with mode 0600 on first start; its pubkey is written to the log for use in relay config.
RUN useradd --create-home --uid 10001 notary && mkdir -p /data && chown notary:notary /data

WORKDIR /app
COPY scripts/container-pip-requirements.lock /tmp/container-pip-requirements.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes \
        -r /tmp/container-pip-requirements.lock
COPY notary/requirements.container.lock /tmp/requirements.container.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
        -r /tmp/requirements.container.lock
COPY --from=builder /wheels/ /wheels/
RUN python -m pip install --no-cache-dir --no-index --no-deps \
        /wheels/a4a_sdk-*.whl /wheels/a4a_notary-*.whl \
    && rm -rf /wheels /tmp/requirements.container.lock
COPY notary/licenses/ /app/licenses/
RUN cp /usr/local/lib/python3.11/site-packages/pycryptodomex-3.23.0.dist-info/LICENSE.rst \
        /app/licenses/pycryptodomex-LICENSE.rst \
    && cp /usr/local/lib/python3.11/site-packages/python_bitcoinlib-0.12.2.dist-info/LICENSE \
        /app/licenses/python-bitcoinlib-LICENSE.txt

COPY scripts/prepare-python-runtime.py /tmp/prepare-python-runtime.py
RUN A4A_PREPARE_CONTAINER_RUNTIME=1 python -I -B /tmp/prepare-python-runtime.py \
    && rm /tmp/prepare-python-runtime.py /tmp/container-pip-requirements.lock

# Keep all CPython/application/distribution files and complete source-present
# Debian packages required by their native dependencies, accounts and data.
FROM base AS runtime-select
COPY --from=runtime-build / /runtime/
COPY scripts/prepare-python-filesystem.py scripts/prepare-relay-runtime.py /selection/
RUN --network=none A4A_PREPARE_PYTHON_FILESYSTEM=1 python -I -B /selection/prepare-python-filesystem.py

# Do not distribute original installers/tools or a stale loader cache.
FROM scratch
COPY --from=runtime-select /prepared/rootfs/ /
RUN --network=none --mount=type=tmpfs,target=/var/cache/ldconfig ["/usr/sbin/ldconfig"]
WORKDIR /app
USER 10001
VOLUME ["/data"]
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    A4A_RELAY_URL=ws://relay:8080 \
    A4A_NOTARY_DB=/data/notary.db \
    A4A_NOTARY_INTERVAL=3600

# OTS calendars are reached externally over HTTPS; the relay uses the internal Compose network.
ENTRYPOINT ["python", "-m", "a4a_notary"]
