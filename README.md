# Candy Cloud

独立的 Candy Cloud 控制面，产品版本 `0.1.0`。控制面负责 AAA、租户、设备、订阅、权益和 Grant 签发，不承载客户数据面流量。

- Candy Core Cloud module: `0.3.10` from revision
  `37757a70a8b94d787b50fc612c276f80176ac355`
- wire line: `0.3`
- auth profile: `cloud_grant_v1`
- runtime: Rust + Axum + Tokio + SQLx/MySQL
- deployment: Docker Compose with an independent MySQL instance

产品入口统一使用 Candy Cloud Server / Client / Runtime；Core 中的历史 crate 名称不作为产品名。

## Local checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
tests/sdwan_route_contract.sh
docker compose config
```

## SD-WAN signed control

`cloud-worker` compiles one immutable Segment topology into one signed
`SegmentRouteSnapshotV1` and every device-specific `SiteRouteProjectionV1`.
The complete publication is committed in one MySQL transaction. TUN Grants use
the `private.tun.connect` permission and bind the exact projection id,
generation, and content hash; ordinary `private.connect` Grants retain their
existing bytes and carry no route policy.

Route-signing and Grant-signing keys are separate. Private key bytes are loaded
only by their owning service and are never stored in route tables, audit rows,
logs, or API responses.

## Repository layout

`crates/` and `tests/` contain the Cloud SD-WAN control-plane publication,
validation, and Core interoperability implementation. The OpenWrt delivery
slice is kept under [`openwrt-sdwan/`](openwrt-sdwan/); it contains the package,
procd, LuCI, and focused productization checks without copying the Core
protocol implementation.

The project is pinned to the signed Candy Core Cloud module `0.3.10` from Core
revision `37757a70a8b94d787b50fc612c276f80176ac355` and wire line `0.3`. Cloud
never checks out or compiles the private Core repository. The
service images load the signed, versioned `libcandy_core_cloud.so` module from
the formal `candy-release` asset path. IPv6 remains outside this delivery;
Mesh precedes dynamic routing in the expansion sequence.
