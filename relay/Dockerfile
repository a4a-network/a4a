# Build with scripts/build-relay-image.py: named contexts are filtered local inputs.
# Empty defaults fail closed; no unverified remote context fallback is available.
FROM scratch AS debian-bundle
FROM scratch AS debian-tools

FROM docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS debian-acquire
COPY --from=debian-tools / /a4a-tools/
COPY ./debian/ /a4a-policy/
ARG DEBIAN_BUILD_NONCE
RUN test -n "$DEBIAN_BUILD_NONCE" \
 && python3 -B /a4a-tools/debian_refresh.py check-policy /a4a-policy/lock.json /a4a-policy/policy.json \
 && python3 -B /a4a-tools/debian_acquire.py /a4a-policy/lock.json /a4a-policy /acquired --locked-releases /a4a-policy

FROM docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS debian-verify
COPY ./debian/ /a4a-policy/
ARG DEBIAN_BUILD_NONCE
RUN --network=none \
 --mount=type=bind,from=debian-bundle,target=/input \
 --mount=type=bind,from=debian-tools,target=/tools \
 python3 -B /tools/debian_image_inputs.py /a4a-policy/lock.json /input /verified "$DEBIAN_BUILD_NONCE"

FROM docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder-inputs
ARG DEBIAN_BUILD_NONCE
RUN --network=none \
 --mount=type=bind,from=debian-verify,source=/verified/builder,target=/tmp/a4a-debian-kit \
 test -n "$DEBIAN_BUILD_NONCE" \
 && A4A_DEBIAN_INSTALL=1 sh /tmp/a4a-debian-kit/install.sh

FROM builder-inputs AS builder
ARG CARGO_LOG
RUN USER=root cargo install --version 0.7.6 --locked cargo-auditable
RUN USER=root cargo new --bin nostr-rs-relay
WORKDIR /nostr-rs-relay
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
# build dependencies only (caching)
RUN cargo auditable build --release --locked
# get rid of starter project code
RUN rm src/*.rs

# copy project source code
COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs

# build auditable release using locked deps
RUN rm ./target/release/deps/nostr*relay*
RUN cargo auditable build --release --locked

FROM docker.io/library/debian:trixie-slim@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c AS runtime-inputs
ARG DEBIAN_BUILD_NONCE
RUN --network=none \
 --mount=type=bind,from=debian-verify,source=/verified/runtime,target=/tmp/a4a-debian-kit \
 test -n "$DEBIAN_BUILD_NONCE" \
 && A4A_DEBIAN_INSTALL=1 sh /tmp/a4a-debian-kit/install.sh

FROM runtime-inputs AS runtime-tools

ARG APP=/usr/src/app
ARG APP_DATA=/usr/src/app/db

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP} \
    && mkdir -p ${APP_DATA} \
    && chown -R $APP_USER:$APP_USER ${APP}

# Local diagnostic target only: SQLite and file utilities never enter runtime.
USER $APP_USER
WORKDIR ${APP}

FROM runtime-tools AS runtime-filesystem
USER root

COPY --from=builder /nostr-rs-relay/target/release/nostr-rs-relay ${APP}/nostr-rs-relay

RUN chown -R $APP_USER:$APP_USER ${APP}

# The relay needs no set-user-ID or set-group-ID helpers in its runtime image.
# Preserve executable/ownership bits, and fail the build if privilege bits remain.
RUN find / -xdev -perm /6000 -exec chmod a-s {} + \
    && test -z "$(find / -xdev -perm /6000 -print)"

FROM debian-verify AS runtime-prepare
COPY --from=runtime-filesystem / /runtime/
ARG DEBIAN_BUILD_NONCE
RUN --network=none \
 --mount=type=bind,from=debian-tools,target=/tools \
 A4A_PREPARE_RELAY_RUNTIME=1 python3 -I -B /tools/prepare-relay-runtime.py "$DEBIAN_BUILD_NONCE"

FROM scratch AS runtime
COPY --from=runtime-prepare /prepared/rootfs/ /
# The auxiliary cache contains build-filesystem inode data. Keep it ephemeral;
# only the runtime loader cache is committed to the image.
RUN --network=none --mount=type=tmpfs,target=/var/cache/ldconfig ["/usr/sbin/ldconfig"]

EXPOSE 8080
ENV TZ=Etc/UTC APP_USER=appuser APP_DATA=/usr/src/app/db
USER appuser
WORKDIR /usr/src/app

ENV RUST_LOG=info,nostr_rs_relay=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["./nostr-rs-relay", "--healthcheck", "--healthcheck-address", "127.0.0.1:8080"]

CMD ["./nostr-rs-relay", "--db", "/usr/src/app/db"]
