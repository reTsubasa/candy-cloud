FROM rust:1.88-bookworm AS build
ARG PACKAGE
ARG BINARY
WORKDIR /workspace
COPY . ./candy-cloud/
WORKDIR /workspace/candy-cloud
RUN cargo build --release -p ${PACKAGE} --bin ${BINARY}

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*
ARG BINARY
COPY --from=build /workspace/candy-cloud/target/release/${BINARY} /usr/local/bin/service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]

FROM debian:bookworm-slim AS core-module-installer
ARG CORE_MODULE_BUNDLE_SHA256
ARG CORE_MODULE_VERSION
ARG CORE_MODULE_SHA256
ARG CORE_MODULE_TARGET=x86_64-unknown-linux-gnu
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
    && test "${CORE_MODULE_TARGET}" = x86_64-unknown-linux-gnu \
    && core_module_url="https://github.com/reTsubasa/candy-release/releases/download/core-cloud-module-v${CORE_MODULE_VERSION}/candy-core-cloud-module-${CORE_MODULE_VERSION}-${CORE_MODULE_TARGET}.tar.gz" \
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
