#!/usr/bin/env python3
"""Dependency-free structural checks for the Candy Cloud V1 API contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "docs" / "openapi-v1.yaml"
GUIDE = ROOT / "docs" / "api-contract.md"
CONTROL = ROOT / "crates" / "cloud-control" / "src" / "lib.rs"
CLOUD_API = ROOT / "crates" / "cloud-api" / "src" / "lib.rs"
CLOUD_AUTH_ROUTES = ROOT / "crates" / "cloud-auth" / "src" / "routes.rs"
CLOUD_AUTH_RUNTIME = ROOT / "crates" / "cloud-auth" / "src" / "runtime.rs"
CLOUD_IDENTITY = ROOT / "crates" / "cloud-identity" / "src" / "lib.rs"
CADDYFILE = ROOT / "docker" / "reverse-proxy" / "Caddyfile"


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def fail(message: str) -> None:
    print(f"api_contract: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, needle: str, location: str) -> None:
    if needle not in text:
        fail(f"{location} is missing {needle!r}")


def reject(text: str, needle: str, location: str) -> None:
    if needle in text:
        fail(f"{location} contains forbidden {needle!r}")


def path_blocks(document: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^  (/[^:]+):\s*$", document))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else document.find("\ncomponents:", match.end())
        if end < 0:
            fail("OpenAPI components section is missing")
        blocks[match.group(1)] = document[match.start() : end]
    return blocks


def collection_values(control: str) -> set[str]:
    body = re.search(
        r"pub fn api_collection\(self\).*?\{(?P<body>.*?)\n    \}\n\n    pub fn database_value",
        control,
        re.S,
    )
    if body is None:
        fail("cannot extract ResourceKind::api_collection")
    return set(re.findall(r'=> "([a-z-]+)"', body.group("body")))


def openapi_collection_values(document: str) -> set[str]:
    match = re.search(
        r"(?ms)^    Collection:\n.*?^        enum: \[(?P<values>[^\]]+)\]",
        document,
    )
    if match is None:
        fail("cannot extract OpenAPI Collection enum")
    return {value.strip() for value in match.group("values").split(",")}


def main() -> None:
    openapi = read(OPENAPI)
    guide = read(GUIDE)
    control = read(CONTROL)
    cloud_api = read(CLOUD_API)
    auth_routes = read(CLOUD_AUTH_ROUTES)
    auth_runtime = read(CLOUD_AUTH_RUNTIME)
    identity = read(CLOUD_IDENTITY)
    caddy = read(CADDYFILE)

    require(openapi, "openapi: 3.1.0", "OpenAPI")
    require(openapi, "version: 1.0.0", "OpenAPI")
    require(guide, "Candy Cloud V1 API and Runtime Integration Contract", "Runtime guide")

    expected_paths = {
        "/v1/auth/register": {"post:"},
        "/v1/auth/login": {"post:"},
        "/v1/auth/refresh": {"post:"},
        "/v1/auth/logout": {"post:"},
        "/health/live": {"get:"},
        "/health/ready": {"get:"},
        "/health/degraded": {"get:"},
        "/v1/tenants/{tenant_id}/{collection}": {"get:", "post:"},
        "/v1/tenants/{tenant_id}/{collection}/{id}": {"get:", "put:", "delete:"},
        "/v1/enrollment/challenges": {"post:"},
        "/v1/enrollment/complete": {"post:"},
        "/v1/access-grants": {"post:"},
        "/v1/runtime/capabilities": {"get:"},
        "/v1/runtime/configuration": {"get:"},
        "/v1/runtime/configuration/status": {"put:"},
    }
    blocks = path_blocks(openapi)
    for path, methods in expected_paths.items():
        block = blocks.get(path)
        if block is None:
            fail(f"OpenAPI path {path} is missing")
        for method in methods:
            require(block, f"    {method}", f"OpenAPI path {path}")

    management_list = blocks["/v1/tenants/{tenant_id}/{collection}"]
    management_item = blocks["/v1/tenants/{tenant_id}/{collection}/{id}"]
    require(management_list, "managementBearer", "management collection security")
    require(management_item, "managementBearer", "management item security")
    require(management_list, "IdempotencyKey", "management create contract")
    require(management_item, "IfMatch", "management mutation contract")
    require(management_item, '"412"', "management revision contract")
    require(management_item, '"428"', "management precondition contract")

    for path in ["/v1/auth/login", "/v1/auth/refresh"]:
        block = blocks[path]
        require(block, "IdentitySessionResponse", f"identity path {path}")
    require(blocks["/v1/auth/register"], "IdentityMessageResponse", "identity registration")
    require(blocks["/v1/auth/register"], '"202"', "identity registration")
    require(blocks["/v1/auth/verify-email"], "IdentitySessionResponse", "identity verification")
    require(blocks["/v1/auth/logout"], "managementBearer", "identity logout security")
    for route in ["/v1/auth/register", "/v1/auth/login", "/v1/auth/refresh", "/v1/auth/logout", "/v1/auth/verify-email", "/v1/auth/request-email-verification", "/v1/auth/request-password-reset", "/v1/auth/reset-password", "/v1/auth/sessions"]:
        require(identity, route, "cloud-identity router")
    for boundary in ["Argon2", "rotate_refresh_token", "hash_token", "session_is_active"]:
        require(identity, boundary, "cloud-identity security boundary")

    enrollment = blocks["/v1/enrollment/challenges"] + blocks["/v1/enrollment/complete"]
    reject(enrollment, "deviceMtls", "public enrollment contract")
    reject(enrollment, "managementBearer", "public enrollment contract")
    for forbidden_identity in ["tenant_id:", "device_id:", "device_key_id:"]:
        reject(enrollment, forbidden_identity, "public enrollment request")

    for path in [
        "/v1/access-grants",
        "/v1/runtime/capabilities",
        "/v1/runtime/configuration",
        "/v1/runtime/configuration/status",
    ]:
        require(blocks[path], "deviceMtls", f"device path {path}")
    runtime_fetch = blocks["/v1/runtime/configuration"]
    capabilities = blocks["/v1/runtime/capabilities"]
    for boundary in [
        "RuntimeCapabilities",
        "site_projection_v1",
        "application/vnd.candy.site-projection-envelope.v1+octet-stream",
    ]:
        require(capabilities, boundary, "Runtime capabilities contract")
    for boundary in [
        "If-None-Match",
        "ConfigurationETag",
        "X-Candy-Projection-Publication-Id",
        "X-Candy-Projection-Id",
        "X-Candy-Segment-Generation",
        "X-Candy-Projection-Generation",
        "X-Candy-Projection-Content-Hash",
        '"304"',
        '"204"',
        "application/vnd.candy.site-projection-envelope.v1+octet-stream",
    ]:
        require(runtime_fetch, boundary, "Runtime fetch contract")
    runtime_status = blocks["/v1/runtime/configuration/status"]
    for boundary in ["RuntimeIfMatch", "projection_publication_id", "projection_content_hash", "state", "error_code"]:
        require(runtime_status, boundary, "Runtime status contract")
    for status in ['"204"', '"409"']:
        require(runtime_status, status, "Runtime status response contract")

    source_collections = collection_values(control)
    documented_collections = openapi_collection_values(openapi)
    if source_collections != documented_collections:
        missing = sorted(source_collections - documented_collections)
        extra = sorted(documented_collections - source_collections)
        fail(f"resource collections differ from source; missing={missing}, extra={extra}")

    for route in [
        "/v1/tenants/{tenant_id}/{collection}",
        "/v1/tenants/{tenant_id}/{collection}/{id}",
    ]:
        require(cloud_api, route, "cloud-api router")
    for route in [
        "/v1/enrollment/challenges",
        "/v1/enrollment/complete",
        "/v1/access-grants",
    ]:
        require(auth_routes, route, "cloud-auth router")

    runtime_routes_implemented = all(
        route in auth_routes or route in auth_runtime
        for route in [
            "/v1/runtime/capabilities",
            "/v1/runtime/configuration",
            "/v1/runtime/configuration/status",
        ]
    )
    runtime_status_count = len(
        re.findall(r"(?m)^      x-candy-status: runtime-sync$", openapi)
    )
    if runtime_routes_implemented and runtime_status_count != 3:
        fail("implemented Runtime routes must retain all OpenAPI synchronization markers")
    if not runtime_routes_implemented and runtime_status_count != 3:
        fail("Runtime routes being synchronized must retain all OpenAPI markers")

    require(caddy, "header_up -X-Candy-Verified-Device-Certificate-Der", "Caddy identity boundary")
    require(caddy, "handle_path /identity/*", "Caddy human identity boundary")
    require(caddy, "{tls_client_certificate_der_base64}", "Caddy verified certificate forwarding")
    for statement in [
        "Cloud never instructs Runtime to remove the last-known-good configuration",
        "Runtime identity is never accepted from JSON",
        "Weak ETags are rejected",
        "If-None-Match",
        "bounded exponential backoff and jitter",
        "Cloud does not create a separate Core binary",
    ]:
        require(guide, statement, "Runtime guide")
    for retired_name in ["core-cloud-module-v", "core-cloud-module-"]:
        reject(openapi + guide, retired_name, "unified Core contract")

    print(
        "api_contract: ok "
        f"paths={len(expected_paths)} collections={len(source_collections)} "
        f"runtime_routes={'implemented' if runtime_routes_implemented else 'synchronizing'}"
    )


if __name__ == "__main__":
    main()
