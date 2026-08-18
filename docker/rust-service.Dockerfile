# syntax=docker/dockerfile:1.7

# Build Rust on the native host CPU and cross-compile when the image target is
# different. Running Cargo itself under QEMU makes local and CI builds stall.
FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS build
ARG BUILDARCH
ARG TARGETARCH
ARG RUST_TARGET=aarch64-unknown-linux-gnu
RUN case "${BUILDARCH}:${TARGETARCH}:${RUST_TARGET}" in \
      amd64:amd64:x86_64-unknown-linux-gnu|arm64:arm64:aarch64-unknown-linux-gnu) ;; \
      amd64:arm64:aarch64-unknown-linux-gnu) \
        apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
          && rm -rf /var/lib/apt/lists/* ;; \
      arm64:amd64:x86_64-unknown-linux-gnu) \
        apt-get update && apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
          && rm -rf /var/lib/apt/lists/* ;; \
      *) echo "unsupported build/target architecture pair" >&2; exit 1 ;; \
    esac \
    && rustup target add "${RUST_TARGET}"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
WORKDIR /workspace
RUN mkdir candy-cloud
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./candy-cloud/
COPY .cargo/ ./candy-cloud/.cargo/
COPY crates/ ./candy-cloud/crates/
WORKDIR /workspace/candy-cloud
# Keep every Rust service on one immutable build layer. The selected binary is
# copied into each small runtime image below, so Compose does not rebuild the
# dependency graph once per service.
RUN cargo build --release --target "${RUST_TARGET}" --workspace --bins

FROM --platform=$TARGETPLATFORM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*
ARG RUST_TARGET=aarch64-unknown-linux-gnu
ARG BINARY
COPY --from=build /workspace/candy-cloud/target/${RUST_TARGET}/release/${BINARY} /usr/local/bin/service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]

FROM --platform=$TARGETPLATFORM debian:bookworm-slim AS core-module-installer
ARG TARGETARCH
ARG CORE_MODULE_BUNDLE_SHA256
ARG CORE_MODULE_VERSION
ARG CORE_MODULE_SHA256
ARG CORE_MODULE_TARGET
ARG CORE_MODULE_URL
ARG USIGN_COMMIT=c4c72b1b07945ee192361dc751291a7c98d6adcd
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git jq \
    && rm -rf /var/lib/apt/lists/*
RUN git init -q /tmp/usign \
    && git -C /tmp/usign remote add origin https://github.com/openwrt/usign.git \
    && git -C /tmp/usign fetch --depth 1 origin "${USIGN_COMMIT}" \
    && git -C /tmp/usign checkout -q FETCH_HEAD \
    && cmake -S /tmp/usign -B /tmp/usign/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/usign/build --parallel 2 \
    && install -m 0755 /tmp/usign/build/usign /usr/local/bin/usign
COPY docker/install-core-cloud-module.sh /usr/local/bin/install-core-cloud-module
COPY keys/core-release.pub /usr/share/candy/keys/core-release.pub
RUN case "${CORE_MODULE_VERSION}" in \
      ''|*[!0-9A-Za-z._-]*) echo 'invalid Core module version' >&2; exit 1 ;; \
    esac \
    && case "${TARGETARCH}:${CORE_MODULE_TARGET}" in \
      amd64:x86_64-unknown-linux-gnu|arm64:aarch64-unknown-linux-gnu) ;; \
      *) echo 'Core module target does not match image architecture' >&2; exit 1 ;; \
    esac \
    && core_release_tag="core-v${CORE_MODULE_VERSION}" \
    && core_module_asset="candy-core-${CORE_MODULE_VERSION}-cloud-abi-${CORE_MODULE_TARGET}.tar.gz" \
    && core_module_url="${CORE_MODULE_URL:-https://github.com/reTsubasa/candy-release/releases/download/${core_release_tag}/${core_module_asset}}" \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --retry 5 --retry-all-errors --connect-timeout 15 --max-time 300 \
      --output /tmp/core-module.tar.gz "${core_module_url}" \
    && CORE_MODULE_BUNDLE=/tmp/core-module.tar.gz \
      CORE_MODULE_BUNDLE_SHA256="${CORE_MODULE_BUNDLE_SHA256}" \
      CORE_MODULE_VERSION="${CORE_MODULE_VERSION}" \
      CORE_MODULE_SHA256="${CORE_MODULE_SHA256}" \
      CORE_MODULE_TARGET="${CORE_MODULE_TARGET}" \
      CORE_MODULE_PUBLIC_KEY=/usr/share/candy/keys/core-release.pub \
      /usr/local/bin/install-core-cloud-module \
    && rm -f /tmp/core-module.tar.gz

FROM runtime AS runtime-core
ARG CORE_MODULE_VERSION
ARG CORE_MODULE_SHA256
COPY --from=core-module-installer --chown=0:0 /opt/candy/cores /opt/candy/cores
ENV CLOUD_CORE_MODULE_ROOT=/opt/candy/cores \
    CLOUD_CORE_MODULE_PATH=/opt/candy/cores/${CORE_MODULE_VERSION}/libcandy_core_cloud.so \
    CLOUD_CORE_MODULE_SHA256=${CORE_MODULE_SHA256} \
    CLOUD_CORE_MODULE_OWNER_UID=0

FROM runtime AS default
