# IP Geo 策略

SERVICE_POLICY 规则可通过 `destination_geo` 按目标 IPv4 的国家/地区代码匹配：

```json
{
  "provider": "openwrt-cidr-v1",
  "countries": ["CN", "US"],
  "version": "2026-09-24",
  "digest": "<64 hex characters>"
}
```

Cloud Worker 使用与 OpenWrt 兼容的 `<country>-ip.cidr` 文件，将规则在发布前展开为规范 IPv4 前缀，再纳入现有签名 Route Projection。Geo selector 不会改变隧道、Core 会话或 netd 的链路代次；策略更新仍由 netd 的 policy-only 事务热加载。

Provider 文件位于 `CANDY_GEOIP_PROVIDER_DIR`，默认 `/etc/candy/rulesets`。生产 Compose 使用独立的 `candy-cloud-geoip-data` 卷和 `geoip-updater` 一次性更新器。更新器先在临时目录下载、校验并原子替换文件；任一国家没有可验证的新文件时，如果存在旧的已验证文件则保留旧版本，否则更新失败，Cloud Worker 不会发布该 Geo 规则。

发布保护：

- 国家代码必须是唯一的两位大写 ISO 代码。
- Provider 版本或 digest（若规则指定）不匹配时拒绝发布。
- 非规范 CIDR、空文件、IPv6 条目和超过 65,536 条展开前缀的规则都会被拒绝。
- Geo 规则不能被静默转换为 `0.0.0.0/0`；远端出口必须拥有显式 CIDR 或可展开的 Geo selector。
- Geo provider digest 会绑定到策略引用，provider 内容变化会产生新的签名策略代次。

OpenWrt 侧现有 `cn-ip.cidr` 等文件可直接复用；Cloud 默认使用 `ipdeny` aggregated IPv4 数据源，也可以通过 `CANDY_GEOIP_SOURCE_URL` 指定受控镜像。
