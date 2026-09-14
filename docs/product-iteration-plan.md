# Candy SD-WAN 产品化迭代计划

本文档是 Core、Runtime、Cloud 和 Release 的共同交付计划。目标不是增加
降级行为，而是完成可证明的产品级连续性、隔离性、可观测性和可回滚发布。

## 交付原则

- 任何数据面切换都必须先准备、确认、提交，再排空旧代次。
- 事务必须携带稳定的 `handoff_id`、`generation` 和 `transaction_id`，并且幂等。
- Proxy 与 SD-WAN 是独立数据面；SD-WAN 故障不得停止或改写普通 Proxy。
- 无法迁移的既有 TCP/NAT 流必须有序排空并明确报告，不能伪装成无损迁移。
- 失败必须精确到阶段、组件、对象和原因；回滚失败不能覆盖原始错误。
- 所有可部署产物只能来自签名、可追溯且版本一致的 Release metadata。
- 真实 Linux/OpenWrt、公网 NAT 和跨节点流量是发布证据，单元测试和回环测试不能替代。

## 迭代总览

| 迭代 | 目标 | 依赖 | 发布级别 |
| --- | --- | --- | --- |
| I0 | 冻结跨仓库协议、版本和验收基线 | 无 | 阻断后续开发 |
| I1 | 双节点 commit barrier、双代 netd、旧流 drain | I0 | P0 |
| I2 | TCP/NAT 既有连接连续性策略与实现 | I1 | P0 |
| I3 | 按 prefix 精确降级和 Proxy 回注 | I0、I1 | P1 |
| I4 | Cloud 发布版本单一来源和签名 Release 归属 | I0 | P1 |
| I5 | 阶段化升级错误码和 Cloud -> Runtime E2E | I4 | P1 |
| F | 全平台、故障、性能、升级和发布验收 | I1-I5 | 最终门禁 |

## I0：协议与基线冻结

交付：

- 冻结 `prepare -> ready -> commit -> drain -> complete` 状态机。
- 冻结 `handoff_id`、配置 generation、事务幂等、fencing 和事件序列规则。
- 冻结 prefix/route-owner/readiness、Proxy fallback 和升级任务 schema。
- 建立 Linux/Linux、OpenWrt/Linux、公网 NAT 的测试拓扑和流量脚本。
- 建立 Core、Runtime、Cloud、Release 的唯一版本来源。

退出条件：所有参与仓库引用同一份 schema/兼容矩阵；旧版本收到新事务时安全拒绝。

## I1：双节点 barrier 和双代 netd

交付：

- 两端候选都 `PREPARED` 且 readiness 成功后才能 `COMMIT`。
- 重复/乱序/错误事务号、丢回复和分区恢复都必须幂等且可恢复。
- netd 同时维护旧 generation 和候选 generation，切换后进入有界 `DRAINING`。
- journal 持久化 barrier 状态；重启后只能恢复、提交或安全回滚。
- 旧 Runtime/Core 通过 fencing 不能重新取得 ownership。

验收：双节点分区、重复 commit、`kill -9`、netlink 重启、drain 超时、journal 恢复，
并证明新流在新路径 ready 后使用新 generation，旧流在 drain 完成前仍可用。

## I2：TCP/NAT 连续性

交付：

- netd 保存 flow owner、NAT binding、generation 和 drain deadline。
- 同一公网出口或 Relay 场景使用稳定 connection ID/QUIC migration。
- 公网地址变化且不能迁移时，旧出口保持到 drain deadline；不得提前删除 conntrack。
- 不可迁移流报告 `migration_failed` 或 `drained`，新流立即使用新路径。
- 增加迁移、排空、重置、超时和失败的 flow-level telemetry。

验收：长 TCP、双向 UDP、NAT rebinding、Relay 切换、新旧流混合和不同公网出口测试；
发布说明明确“可迁移”与“有序排空”边界。

## I3：按 prefix 降级与 Proxy 回注

交付：

- Core 输出 prefix-level owner/readiness 和失败原因。
- Runtime/netd 能原子撤销单个失败 prefix，保留其他健康 prefix。
- 建立 failed prefix 到普通 Proxy 的真实回注路径和防环规则。
- prefix 恢复只恢复自身；Cloud、LuCI 和 Runtime 显示局部降级。
- 遥测记录 fallback owner、原因、恢复时间和丢包。

验收：多 prefix、多 owner、三节点、多 Segment、prefix 移动/冲突以及真实 TCP/UDP/DNS
混合流量测试；不得出现失败 prefix 黑洞或跨租户回注。

## I4：发布链路一致性

交付：

- 删除 workflow 中手工漂移的 Runtime/Core 版本，统一读取 Release metadata。
- Cloud 镜像发布显式指定 `reTsubasa/candy-release`。
- metadata 固定记录 Cloud commit、Runtime/Core tag、digest、架构和镜像 digest。
- CI 拒绝旧版本 tag、错误仓库、未签名 Core/Runtime 或 prerelease 进入 stable。
- 同步更新 README、平台矩阵、测试 fixture 和升级兼容矩阵。

验收：x86/ARM64 镜像均能从中心 Release 下载并校验，故意注入旧 tag 或错误仓库时 CI 必须失败。

## I5：升级错误码与 E2E

交付：

- 错误码按领取、下载、校验、签名、平台、安装、启动、健康检查、回滚、回执和恢复阶段划分。
- 每个任务保留原始阶段、cause code、组件、版本、generation、job ID、可重试性和回滚结果。
- Cloud UI 展示准确阶段和结果，不再把不同故障合并成单一错误码。
- 覆盖 Runtime/Core 单独升级、组合升级、断电、`kill -9`、回执丢失和重复任务。

验收：下载失败、checksum/signature/architecture 错误、安装失败、健康检查失败、回滚失败和中断恢复
均能在 Cloud、Runtime 日志和节点实际版本中得到一致结论。

## F：最终发布门禁

必须全部通过：

- OpenWrt↔OpenWrt、OpenWrt↔Linux、Linux↔Linux 双向真实流量。
- 双节点分区、重复 barrier、Core/Runtime/netd `kill -9`、netlink 故障和 drain 超时。
- 单 prefix 故障、Proxy 回注、prefix 恢复和跨租户隔离。
- TCP/NAT 既有连接迁移或有序排空的实际证据。
- Cloud/Runtime/Core 升级、回滚、断电恢复和版本一致性。
- 24 小时丢包/抖动压力、72 小时设备 soak、内存/CPU/磁盘预算。
- 签名 Release、中心仓库资产、节点升级和重启恢复。

任一 P0 未完成，禁止宣称无感切换；I4 未完成，禁止发布新的 Cloud 镜像；I5 未完成，禁止开放正式节点升级按钮。
