FROM rust:1.88-bookworm AS build
ARG PACKAGE
ARG BINARY
WORKDIR /workspace
COPY . ./candy-cloud/
COPY --from=candy-core . ./candy-core/
WORKDIR /workspace/candy-cloud
RUN cargo build --release -p ${PACKAGE} --bin ${BINARY}
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*
ARG BINARY
COPY --from=build /workspace/candy-cloud/target/release/${BINARY} /usr/local/bin/service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]
