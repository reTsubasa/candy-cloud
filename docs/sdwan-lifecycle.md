# SD-WAN 数据面与控制面生命周期

## 数据面阶段

Runtime 接收 Cloud 的签名配置后，数据面按以下顺序推进。阶段写入 Core 状态文件 `dataplane_phase`，由 Cloud Sync 原样上报；阶段变化产生 `RUNTIME_DATAPLANE_PHASE_CHANGED` 审计事件。

1. `control_received`：收到配置响应。
2. `control_verified`：校验设备身份、签名、代次和授权绑定。
3. `config_compiled`：解析分段、Peer、路径和路由 owner。
4. `netd_prepared`：netd 完成 TUN、路由、转发和 NAT 的事务预配置。
5. `core_policy_staged`：Core 暂存策略，旧数据面仍可继续工作。
6. `peer_connecting`：开始建立 Peer 的 QUIC 连接。
7. `peer_authenticated`：Peer 完成身份和路径授权认证。
8. `stream_opening`：建立每个 Peer 独立的 `IP_PACKET_STREAM_V1`。
9. `stream_ready`：Stream 完成双向打开、信用额度和接收侧准备。
10. `route_owners_ready`：所有必需路由 owner 都有可用 Stream。
11. `steering_committed`：netd 提交本代路由，流量开始导向 TUN。
12. `data_plane_active`：TUN、Stream、路由和出口条件全部满足。
13. `degraded`：数据面撤销接管，流量按本地降级策略转发。
14. `recovering`：保留旧配置/降级出口并异步重建失败的 Peer 或 Stream。
15. `failed`、`stopping`、`stopped`：不可恢复故障或有序停止。

每条 Stream 都有独立的 generation、状态、队列、窗口、收发计数、重置次数和错误码；单条 Stream 故障不能覆盖其他 Stream 的遥测。

## 流量路径

`LAN ingress → DNS 决策 → SD-WAN 策略匹配 → candy0 TUN → 路由 owner → 对应 Peer Stream → QUIC → 对端 TUN → 主机转发/NAT → WAN`。

回程按相反方向返回。Cloud 控制请求使用独立的 mTLS/HTTPS 控制通道，并排除业务 TUN 路由，避免出口策略形成控制面递归。

## 独立生命周期

以下状态不能互相覆盖：

| 维度 | 状态来源 | 说明 |
| --- | --- | --- |
| 注册 | 设备证书/Enrollment | `UNREGISTERED`、`REGISTERING`、`REGISTERED`、`REVOKED`；注册成功不代表数据面可用 |
| 控制通道 | mTLS 心跳/租约 | `OFFLINE`、`CONNECTING`、`ONLINE`、`STALE`；只决定 Cloud 是否能下发配置 |
| Runtime 模式 | 本地服务 | `PROXY_ONLY`、`SDWAN_ONLY`、`HYBRID`、`STOPPED`；与 Peer 状态无关 |
| 配置应用 | 配置回执 | `NONE`、`PREPARED`、`ACTIVE`、`REJECTED`；拒绝只影响该配置代次 |
| Peer/线路 | 路径与 Stream 遥测 | `UNCONFIGURED`、`NEGOTIATING`、`AUTHENTICATED`、`STREAM_READY`、`DEGRADED`、`FAILED` |
| 流量 | Core/TUN 计数 | `IDLE`、`ACTIVE`、`DEGRADED`、`FAIL_OPEN` |

节点是否注册由设备身份决定，节点是否在线由控制通道租约决定，站点颜色只汇总节点注册/在线/Runtime 故障；线路颜色只汇总两端在线节点和双向路径遥测。Peer、线路或策略故障不得撤销设备注册状态。

## 观测字段

Cloud 保留每次最新遥测中的 `dataplane_phase`、`lifecycle`、配置代次、Peer/路由 owner 计数、每条路径和每条 Stream 的状态与计数，以及 `last_error_code`/`last_error_detail`。控制台在“数据面遥测”中显示节点当前阶段，在日志中显示阶段变更、配置准备/激活/拒绝、降级和恢复事件。
