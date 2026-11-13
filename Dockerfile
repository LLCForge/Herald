# syntax=docker/dockerfile:1.7
# Herald container image: static musl binary on distroless, non-root.
# The builder runs on the build host's architecture and cross-compiles with
# cargo-zigbuild, so multi-arch builds do not need slow QEMU compilation.

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
ARG ZIGLANG_VERSION=0.13.0
ARG CARGO_ZIGBUILD_VERSION=0.19.8
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages \
      "ziglang==${ZIGLANG_VERSION}" "cargo-zigbuild==${CARGO_ZIGBUILD_VERSION}"
RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac > /rust-target \
 && rustup target add "$(cat /rust-target)"
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo zigbuild --release --locked --target "$(cat /rust-target)" \
 && install -D -m 0755 "target/$(cat /rust-target)/release/herald" /out/herald \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Herald" \
      org.opencontainers.image.description="Certificate Transparency log monitor with typosquat, CAA and expiry alerts" \
      org.opencontainers.image.source="https://github.com/LLCForge/Herald" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/herald /usr/local/bin/herald
COPY --from=build --chown=65532:65532 /out/data /data
# Data dir picked up by llcforge_beacon::default_data_dir (queue, silences, state).
ENV STATE_DIRECTORY=/data
VOLUME ["/data"]
EXPOSE 9898
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/herald"]
CMD ["run", "--config", "/etc/herald/herald.toml"]
