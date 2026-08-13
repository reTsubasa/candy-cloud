#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dockerfile="$root/docker/web.Dockerfile"
workflow="$root/.github/workflows/release-arm64-images.yml"

for invariant in \
	'FROM --platform=$BUILDPLATFORM node:22.18-alpine AS build' \
	'FROM --platform=$TARGETPLATFORM busybox:1.37.0-musl'; do
	grep -F "$invariant" "$dockerfile" >/dev/null || {
		echo "web_cross_platform_build: missing invariant: $invariant" >&2
		exit 1
	}
done

grep -F 'docker build --platform linux/arm64' "$workflow" >/dev/null || {
	echo "web_cross_platform_build: ARM64 output platform is not enforced" >&2
	exit 1
}

echo "web_cross_platform_build: ok"
