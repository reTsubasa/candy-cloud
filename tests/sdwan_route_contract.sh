#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings

interop_status=not-run
if [ -n "${CANDY_CORE_INTEROP_MODULE:-}" ]; then
    cargo test -p cloud-core-module --test core_interop --locked -- --ignored
    cargo test -p cloud-auth --test core_module_interop --locked -- --ignored
    cargo test -p cloud-worker --test core_module_interop --locked -- --ignored
    cargo test -p cloud-worker --test route_publication --locked -- --ignored
    interop_status=released-module-passed
fi

rustfmt --edition 2021 --check \
    crates/cloud-db/src/authorization.rs \
    crates/cloud-auth/src/db_mapping.rs \
    crates/cloud-auth/src/issuance.rs \
    crates/cloud-auth/src/service.rs \
    crates/cloud-worker/src/route_publication.rs \
    crates/cloud-worker/tests/route_publication.rs \
    crates/cloud-worker/tests/core_module_interop.rs

if rg -n 'tracing::[^;]*(signing_key|signature|signed_envelope|remote_routes|local_prefixes|packet_payload)' \
    crates/cloud-worker/src/route_publication.rs \
    crates/cloud-auth/src/issuance.rs \
    crates/cloud-auth/src/service.rs; then
    printf '%s\n' "sdwan_route_contract: sensitive diagnostic field" >&2
    exit 1
fi

git diff --check

core_version=$(awk -F= '$1 == "CORE_MODULE_VERSION" { print $2 }' .env.example)
test -n "$core_version"
printf '%s\n' \
    "{\"suite\":\"candy_cloud_sdwan_route_contract\",\"wire\":\"0.3\",\"core\":\"$core_version\",\"unit_status\":\"passed\",\"released_module_interop\":\"$interop_status\"}"
