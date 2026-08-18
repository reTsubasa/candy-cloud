#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile="$root/docker/web.Dockerfile"
workflow="$root/.github/workflows/release-x86-images.yml"
rust_dockerfile="$root/docker/rust-service.Dockerfile"

for invariant in \
	'FROM --platform=$BUILDPLATFORM node:22.18-alpine AS build' \
	'FROM --platform=$TARGETPLATFORM busybox:1.37.0-musl'; do
	grep -F "$invariant" "$dockerfile" >/dev/null || {
		echo "web_cross_platform_build: missing invariant: $invariant" >&2
		exit 1
	}
done

grep -F 'docker build --platform linux/amd64' "$workflow" >/dev/null || {
	echo "web_cross_platform_build: x86-64 output platform is not enforced" >&2
	exit 1
}

for invariant in \
	'FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS build' \
	'cargo build --release --target "${RUST_TARGET}" --workspace --bins' \
	'FROM --platform=$TARGETPLATFORM debian:bookworm-slim AS runtime' \
	'--build-arg RUST_TARGET=x86_64-unknown-linux-gnu'; do
	if grep -F -- "$invariant" "$rust_dockerfile" "$workflow" >/dev/null; then
		continue
	fi
	echo "web_cross_platform_build: missing Rust cross-build invariant: $invariant" >&2
	exit 1
done

echo "web_cross_platform_build: ok"
