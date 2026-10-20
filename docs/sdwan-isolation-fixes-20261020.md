# SD-WAN 发布隔离与拓扑修复（2026-10-20）

本轮目标是将策略发布、隧道基础设施、节点实际运行状态和 Cloud 自身部署分开处理。策略变更应更换匹配流量的投递规则；没有运输身份变化时，不应重新建立隧道。所有验证使用本地数据库及隔离 Docker，未重启或压测线上节点。

## 问题与实现

| 问题 | 修复 | 边界 |
| --- | --- | --- |
| 自动续期依赖数据库默认值，被归类为 `TUNNEL` | 续期显式写入 `POLICY_ONLY`；存在未成功覆盖的运输配置变更时保留 `TUNNEL` | 快照读取当前资源图，必须防止旧策略任务把后来运输变更误当作策略发布 |
| 一个慢站点阻塞同一 Segment 的后续策略 | 有界保留每个 Peer 精确确认的活动投影；仅跨连续 `POLICY_ONLY` 版本 | 多代开关默认关闭，运输变更仍保留屏障；不能将本轮描述为所有情况下的完整站点隔离 |
| 新目标被拒绝，但旧版本仍运行时显示为等待 | 分离目标回执 `current` 与活动版本 `running_current` | 拒绝原因保留；旧活动投影不能覆盖最新目标失败状态 |
| 某个 Peer 被其他 Peer 的健康状态误判 | 只使用该 Peer 当前 Stream 的就绪证据 | 缺证据显示未知；部分 Stream 故障显示降级，剩余可用 Stream 仍计入路径 |
| 历史计数/最后错误让已恢复路径一直显示故障 | 就绪按当前 Stream `state`；单独显示最后错误、累计解码错误和重置 | `last_error_code` 会在可恢复拥塞丢包后保留，不能等同于当前连接关闭 |
| Worker 串行发布使无关 Segment 相互等待 | 默认 4 条独立发布 lane，独立续期扫描，租约超时后可回收 | `CLOUD_WORKER_CONCURRENCY=1..32`；同 Segment 仍由数据库顺序及租约 fencing 约束 |
| 无 schema 变更的 Cloud 部署也停止入口及所有应用 | 目标 migrator 只读检查 schema；一致时 ready → Caddy 切流 → 有界排空 → 替换旧应用 | schema 改变走维护事务；脏历史、校验变化、未知版本检查失败时不切换服务 |

## 部署与回滚约束

- 部署锁避免两个升级事务同时运行。
- 候选 API、Identity、Auth 全部健康后才修改入口映射；Caddy 进程和 MySQL 保持运行。
- 排空采用 `CANDY_CLOUD_DRAIN_SECONDS`（默认 30 秒，上限 300 秒）；超出预算的长请求可能结束，需要调用者重试。
- rolling 回滚只恢复应用与 UI，不恢复数据库快照，不丢弃切换期间接受的写入。
- 维护路径停止所有写入者后再次备份，只有最终快照通过校验才迁移。
- UI 先复制内容寻址资源，最后原子替换 `index.html`；回滚也保留在线页面使用的资源。
- 恢复失败保留候选进程与恢复证据，不清理仍可能承载请求的候选。

## 已完成的验证

- 前端 16 个测试文件、148 项用例通过；ESLint、TypeScript 和生产构建通过。
- Cloud workspace 在独立 MySQL 库上 395 项测试通过，8 项外部模块互操作测试按原条件跳过；workspace 严格 Clippy 通过。随后独立复核发现的边界修复另做定向回归。
- 最终边界修复后，Cloud DB/Auth/Worker 在新建 MySQL 库上 272 项回归通过；workspace 全 target 严格 Clippy、格式和 API 合约再次通过。复用旧测试库会触发旧证书测试固定序列号冲突，因此最终回归使用全新隔离库。
- API/OpenAPI 合约检查通过（36 条路径、11 类资源集合）。
- `tests/deploy_arm64_handoff.py` 使用真实 Docker Compose 与 Caddy，调用部署脚本原有 helper：初次 2,396 次、候选清理修复后 2,566 次 HTTP 请求均零失败，验证旧响应切到新响应、入口容器身份保持、候选进程被回收。
- MySQL schema 探针覆盖空库只读、精确匹配、dirty、checksum 不匹配、正常旧版本前缀、未知新版本及历史缺口。
- 真实 MySQL 发布 → 本地 Core ABI 签名 → Runtime 解码和验证 → Core CLI 验签桥接通过，包含当前代 3 与旧代 1/2，以及篡改拒绝。此处使用本地隔离测试模块，不替代正式签名发布模块或活 QUIC/TUN 验收。
- Core app 125 项、candy-tun 156 项；Runtime cloud-sync 112 项、sdwan-agent 114 项通过。部分 Peer 失联时，真实 Unix IPC 测试确认 PolicyUpdate 保持 Core PID、不启动新 TUN 事务，`ready=1/required=2` 仍提交新策略并报告局部降级。

真实 Caddy 测试验证控制面短请求的切换连续性，不代表 SD-WAN 数据面的吞吐或完整线上长连接验收。测试报告中的性能结论只能来自对应流量测试。

## Core 与 Runtime 的本地故障隔离

Core 兼容目录由当前真实签名的权限限定，旧代不能扩张身份、epoch、路径、源网段或出口权限。不兼容旧 Peer 单独排除，并输出模块、错误码和原因。

`RoutingDomainSupervisor::replace_pump` 原先要求每个新路由 owner 均已建立连接，因此单个 Peer 失联会阻止整个本地策略安装。修复允许已签名策略引用暂不可用的 owner，同时保留 domain、local attachment 与 epoch 校验。分发仍只使用已认证的活动连接；缺失 owner 只影响对应路由，健康 owner 继续转发。Core 对当前失败包丢弃，Runtime 的后续 host fallback 沿用已有失败前缀策略，本轮未改变 netd 的 fail-open 语义。

## 上线边界

`CANDY_ENABLE_MULTI_GENERATION_POLICY_ISOLATION` 默认关闭。开启前必须先部署支持精确 `route_policy` 请求的新 Cloud，再同步部署有界多代与当前权限上限验证的 Runtime/Core，并完成三端联动门禁。旧 Cloud 会拒绝未知请求字段，不能先升级发送新字段的 Runtime。

兼容组最多 32 代，目录总身份最多 4096，Runtime 配置文档仍有 3 MiB 总上限；Core 当前 Peer 目录仍保留 256 上限。这些是解析和内存保护，不是容量承诺。Cloud 以最旧活动版本到新目标的跨度预留兼容预算，避免后续 ACTIVE 回执把 32 组拆成 33 组、使当前配置读取失败；迟到回执也不能越过这一范围。慢站点停留超过 32 轮策略更新仍可能阻塞整个 Segment。运输配置仍需 prepare/commit；完全独立的每站点投影及容量耗尽时仅让落后站点重同步，属于进一步消除全 Segment 屏障的工作，不能宣称已经完成。

## Worker 并发与 Geo 缓存隔离补充

发布调度使用默认 4 条独立 lane（可配置 1–32），每次运行、每条 lane 的 lease owner 都唯一；续期扫描只有一个实例。同 Segment 的先后顺序仍由数据库 claim 事务和租约 fencing 保证。存储或发布失败只让对应 lane 退避，超时与停机取消尚未完成的异步操作，遗留 lease 到期后可重新领取。

并发审查还发现 Geo 刷新将 provider 根目录重命名到自身 `.previous` 子目录；该路径既不合法，也不应尝试移动 Docker 挂载根目录。现在保持根目录稳定，在 `current` 子目录激活新数据；激活失败恢复旧目录，取消或失败清理本次 staging。旧根目录中的有效缓存仍可直接读取。

Geo 刷新、元数据校验与同一策略全部同步读取共同持有跨进程 `flock`。竞争者立即得到可重试的 `ROUTE_INPUT_GEO_PROVIDER_BUSY`，延迟 1 秒重新排队，释放发布 lane；不等待其他 Geo 下载占满所有 lane，非 Geo 策略不获取此锁。网络与文件读取故障可重试，CIDR、摘要、版本等内容校验失败仍作为明确配置错误处理。

验证结果：`cargo test -p cloud-worker` 共 33 项通过（19 项库测试、14 项调度测试）；6 项需要 Core 模块的互操作测试仍按既有条件跳过。`cargo clippy -p cloud-worker --all-targets -- -D warnings` 通过。新增验证覆盖不同 Segment 的慢任务隔离、同 Segment 顺序、超时 lease 回收、停机取消、Geo 锁竞争快速重试、挂载根目录稳定、切换失败恢复和有效缓存复用。

部署事务测试 `python3 tests/deploy_arm64_transaction.py` 的 9 个案例全部通过：rolling 成功、候选不健康、候选创建失败、清理首个候选失败仍继续清理后续候选、切流后 canonical 更新失败、维护迁移失败、最终备份时收到 SIGTERM、回滚失败后阻止下一次部署、schema 检查异常时拒绝修改。测试执行完整 shell 事务和真实文件/SHA-256/jq 校验，仅模拟外部主机及网络边界；不替代真实 Docker/Caddy 门禁。

维护最终备份采用独立 `mysql-quiesced.sql` 和校验清单的原子切换，保留初始恢复资产，避免中断破坏既有备份。Caddy 原配置同时纳入两处恢复校验。回滚失败写入 `.deployment-recovery-required`，后续部署会拒绝继续；管理员须先根据记录中的事务目录核对活动入口映射、应用与数据，再清除此标记。


Worker 恢复扫描不再作为 `main` 启动时的必成步骤。独立恢复任务以最长 5 秒期限扫描，正常间隔至少 60 秒，失败按 2–64 秒退避；单条恢复记录或暂时存储故障不会阻止正常发布 lane 领取其他工作。定向调度测试增至 16 项全部通过，覆盖恢复连续失败后重试成功、恢复挂起时健康任务继续及立即停机；相关库、入口与调度测试的 Clippy 检查通过。
