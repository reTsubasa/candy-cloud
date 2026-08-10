#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CORE_ROOT=${CANDY_CORE_DIR:-"$ROOT/../candy-core"}
cd "$ROOT"

test -f "$CORE_ROOT/interop/vectors/candy-sdwan-route-contract-v1.json"

cargo test -p cloud-worker --test route_publication --test sdwan_core_interop --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings

rustfmt --edition 2021 --check \
    crates/cloud-db/src/authorization.rs \
    crates/cloud-auth/src/db_mapping.rs \
    crates/cloud-auth/src/issuance.rs \
    crates/cloud-auth/src/service.rs \
    crates/cloud-worker/src/route_publication.rs \
    crates/cloud-worker/tests/route_publication.rs \
    crates/cloud-worker/tests/sdwan_core_interop.rs

if rg -n 'tracing::[^;]*(signing_key|signature|signed_envelope|remote_routes|local_prefixes|packet_payload)' \
    crates/cloud-worker/src/route_publication.rs \
    crates/cloud-auth/src/issuance.rs \
    crates/cloud-auth/src/service.rs; then
    printf '%s\n' "sdwan_route_contract: sensitive diagnostic field" >&2
    exit 1
fi

git diff --check

printf '%s\n' '{"suite":"candy_cloud_sdwan_route_contract","wire":"0.3","core":"0.3.4","status":"passed"}'
