# SD-WAN 发布隔离与拓扑修复（2026-10-20）

本轮目标是将策略发布、隧道基础设施、节点实际运行状态和 Cloud 自身部署分开处理。策略变更应更换匹配流量的投递规则；没有运输身份变化时，不应重新建立隧道。所有验证使用本地数据库及隔离 Docker，未重启或压测线上节点。

## 问题与实现

| 问题 | 修复 | 边界 |
| --- | --- | --- |
| 自动续期依赖数据库默认值，被归类为 `TUNNEL` | 续期显式写入 `POLICY_ONLY`；存在未成功覆盖的运输配置变更时保留 `TUNNEL` | 快照读取当前资源图，必须防止旧策略任务把后来运输变更误当作策略发布 |
| 一个慢站点阻塞同一 Segment 的后续策略 | 最近 32 代保留每个 Peer 精确活动投影；落后窗口的 Peer 明确进入 `resync_required` 并取得最新目标，健康站点继续发布 | 多代开关默认关闭，仅跨连续 `POLICY_ONLY`；运输变更仍保留 prepare/commit 屏障 |
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

`CANDY_ENABLE_MULTI_GENERATION_POLICY_ISOLATION` 默认关闭。发布顺序为 Cloud → Core → Runtime：先提供精确 `route_policy` 请求与重同步响应，再提供完整 inbound signed catalog 和 managed policy socket，最后更新生成这些输入的 Runtime。旧 Cloud 会拒绝未知请求字段，旧 Core 会拒绝新的 `inbound_server_config`，因此不能颠倒依赖。多代隔离开关须在各实例配置一致、三端联动门禁通过后再开启。

兼容组最多 32 代，仅接收 `[N-32,N-1]` 内每个 Peer 的一个旧活动身份或 N-1 排空身份。当前目录和旧目录分别最多 4096 个身份，组合预算 8192，避免同一个 Peer 同时出现在当前与旧目录时被重复计入同一个 4096 配额；单目录、单对象及 Runtime 文档 3 MiB 字节上限不变，Core 当前 Peer 目录仍保留 256 上限。这些是解析和内存保护，不是实际容量承诺。

落后窗口的 Peer 不再阻止全 Segment 后续策略发布。Cloud 保留它精确的活动投影指针用于如实显示；管理接口同时返回 `policy_resync_required=true`、`policy_resync_reason=compatibility_window_exceeded`、活动代及最新目标代。第一次越界产生 `SDWAN_PEER_POLICY_RESYNC_REQUIRED` 审计事件，包含模块、原因、旧身份及恢复动作；同一旧身份不会每次发布重复记账。事件使用包含租户和活动身份的域分离 SHA-256 稳定 ID，批量写入并以主键去重，不扫描租户历史审计日志。

只有该 Peer 的过旧精确引用不能取得新 Grant，并得到 HTTP 409 `{"code":"route_policy_resync_required"}`。错误引用、其他站点或未确认的历史引用继续拒绝。Runtime 始终可取得并验证最新目标，最新目标的新 Grant 不受此状态限制；成功应用并报告 ACTIVE 后，派生 resync 状态自动清除。旧准入目录退出不代表已有连接退出：已有包始终受当前 pump 的最新签名权限约束，缺旧引用只能拒绝对应新 OPEN，不能重建 TUN 或断开健康 Peer。

本次局部 resync 修订的 Cloud API/Auth 编译、DB/Auth/API 全 target 严格 Clippy、8192 组合预算单元测试、格式、API 合约及 Grant 409 JSON 契约检查已通过，授权仓库与边界验证两项回归通过。全新隔离 MySQL 库上的 4 项发布、1 项续期回归通过，覆盖连续 35 代策略发布、健康 Peer 每代持续 ACTIVE、落后 Peer 只收到一次 resync 审计、过旧精确 Grant 被 409 拒绝而错误哈希仍拒绝、最新目标 Grant 可用、最新 ACTIVE 清除 resync，以及第 36 代继续发布。禁用站点、设备、权益的负例同时确认撤销优先，不能以 resync 替代拒绝，也不能通过省略 `route_policy` 绕过禁用站点。完整每站点签名快照拆分与运输版本解耦仍是后续架构工作；本轮不取消运输配置 prepare/commit。

## Worker 并发与 Geo 缓存隔离补充

发布调度使用默认 4 条独立 lane（可配置 1–32），每次运行、每条 lane 的 lease owner 都唯一；续期扫描只有一个实例。同 Segment 的先后顺序仍由数据库 claim 事务和租约 fencing 保证。存储或发布失败只让对应 lane 退避，超时与停机取消尚未完成的异步操作，遗留 lease 到期后可重新领取。

并发审查还发现 Geo 刷新将 provider 根目录重命名到自身 `.previous` 子目录；该路径既不合法，也不应尝试移动 Docker 挂载根目录。现在保持根目录稳定，在 `current` 子目录激活新数据；激活失败恢复旧目录，取消或失败清理本次 staging。旧根目录中的有效缓存仍可直接读取。

Geo 刷新、元数据校验与同一策略全部同步读取共同持有跨进程 `flock`。竞争者立即得到可重试的 `ROUTE_INPUT_GEO_PROVIDER_BUSY`，延迟 1 秒重新排队，释放发布 lane；不等待其他 Geo 下载占满所有 lane，非 Geo 策略不获取此锁。网络与文件读取故障可重试，CIDR、摘要、版本等内容校验失败仍作为明确配置错误处理。

验证结果：`cargo test -p cloud-worker` 共 33 项通过（19 项库测试、14 项调度测试）；6 项需要 Core 模块的互操作测试仍按既有条件跳过。`cargo clippy -p cloud-worker --all-targets -- -D warnings` 通过。新增验证覆盖不同 Segment 的慢任务隔离、同 Segment 顺序、超时 lease 回收、停机取消、Geo 锁竞争快速重试、挂载根目录稳定、切换失败恢复和有效缓存复用。

部署事务测试 `python3 tests/deploy_arm64_transaction.py` 的 9 个案例全部通过：rolling 成功、候选不健康、候选创建失败、清理首个候选失败仍继续清理后续候选、切流后 canonical 更新失败、维护迁移失败、最终备份时收到 SIGTERM、回滚失败后阻止下一次部署、schema 检查异常时拒绝修改。测试执行完整 shell 事务和真实文件/SHA-256/jq 校验，仅模拟外部主机及网络边界；不替代真实 Docker/Caddy 门禁。

维护最终备份采用独立 `mysql-quiesced.sql` 和校验清单的原子切换，保留初始恢复资产，避免中断破坏既有备份。Caddy 原配置同时纳入两处恢复校验。回滚失败写入 `.deployment-recovery-required`，后续部署会拒绝继续；管理员须先根据记录中的事务目录核对活动入口映射、应用与数据，再清除此标记。


Worker 恢复扫描不再作为 `main` 启动时的必成步骤。独立恢复任务以最长 5 秒期限扫描，失败按 2–64 秒退避，首次成功后本次进程不再重复扫描，避免反复复活永久无效配置；单条恢复记录或暂时存储故障不会阻止正常发布 lane 领取其他工作。定向调度测试增至 17 项全部通过，覆盖恢复连续失败后重试成功、恢复挂起时健康任务继续及立即停机，以及首次成功后新永久错误不会被再次复活；相关库、入口与调度测试的 Clippy 检查通过。

## Runtime 重同步与界面状态补充

Grant HTTP 409 只有顶层 `code=route_policy_resync_required` 才触发重同步。Runtime 有界读取该响应，保留旧活动 Grant 和待确认请求；不会将它标记成永久身份撤销，也不会用旧 Grant 提交新候选。同步器清除条件 GET 的 ETag 和旧拒绝缓存，立即无条件拉取最新配置一次；同轮仍失败则交回现有调度退避，不递归无限重试，不停止当前 Core。403 及其他明确拒绝仍按原授权规则失效处理。

新增 3 项重同步状态/凭证/解析回归及本地真实 HTTP 409/403 分类回归通过；Grant 模块 16 项回归通过，cloud-sync 全 target 严格 Clippy 通过。

拓扑节点单独显示“路由策略需重同步”，详情列出已确认运行代际、目标代际与原因。该提示不改变节点、Peer、隧道健康状态；缺遥测时仍保留重同步提示，且不会编造隧道就绪。拓扑 34 项回归通过，包含局部重同步不会改变健康 Peer 状态；TypeScript、ESLint 与生产构建通过。

## 共享 listener 的最新授权目录

Managed listener 原先在启动闭包中固定捕获 inbound signed catalog，导致 PolicyUpdate 已更新转发规则后，新连接仍可能拿到旧目录。本轮改为单个完整快照携带 catalog、policy generation、authorization hash、local attachment epoch，Core 验证并收到 pump ACK 后一起发布。已认证但尚未发送 OPEN 的连接，在真正处理 OPEN 时重新读取最新目录，避免跨撤销竞态。已协商 successor 普通重连也必须通过当前目录，不能用历史协商证据绕过撤销。

Runtime client activation 生成完整签名 inbound 输入，快照闭包复制并改写当前/保留签名文件与 transport 引用，不能从本地路由推断远端权限。热更新保持已运行 listener 的身份和信任；需要轮换信任时走运输替换。

真实 QUIC + owner IPC 门禁 1 项通过，覆盖当前及保留引用的新 OPEN、AUTH 与 OPEN 之间发布撤销的精确拒绝、后续当前引用恢复接入，以及原健康 lane 的身份/epoch 不变并继续传输 28 字节载荷。严格 Clippy 通过。该门禁不创建特权内核 TUN，也不代表吞吐验收。

## Managed 策略与物理 owner 分离

复核发现，managed Runtime 原先将签名摘要变化统一按新 worker/authority 处理，因此即使 Cloud 标记 `POLICY_ONLY`，仍会进入运输替换。本轮将活动策略代际与 `binding_policy_generation` 分开：前者更新签名路由和准入目录，后者保留 PacketPort、IO、owner、fence 与物理授权的初始代际。进程重新接管核对这两个身份，正常 hot-policy adoption 只续 owner lease，不执行 Guard、Prepare 或新 fence。

热更新要求 transport、trust、resource contract、基础设施、部署位置和本机身份均不变；新签名有效期必须覆盖原物理上限。新策略允许更晚到期，但不能延长旧物理 cap；有效期变短、信任轮换、资源或运输配置变化仍走 MBB。原物理 cap 到期前 120 秒、有更新授权时进入正式续期，不能靠后续策略无期限延用初始连接。上述分流和恢复边界已通过 Runtime Linux 回归；完整跨组件联动仍须后续门禁。

Runtime 在发送 Core 请求前落盘单个原始 signed snapshot intent；Core ACK 后再提交 Netd，最后才前移有效 plan 与进程记录。拒绝、ACK 丢失和 Netd 后置失败均保留原事务；即使 Cloud 又发布新版本，也必须先恢复确切旧 intent。Core 候选事务与 PolicyUpdate 共用互斥 fence：尚未触发操作的错误请求不会封锁健康策略更新；已发出但结果未知的操作不能被新策略越过。

Core 新增 managed 专用 `--policy-reload-socket`，只允许 PolicyUpdate，拒绝 Replace/Prepare/Commit/Abort/Suspend/Resume。收到转发器 ACK 后才发布完整 inbound snapshot 与实际策略状态。真实 Unix 接口正例通过：原物理代际、PID、就绪 token 保持；策略代际前移；同步 status 文件在返回 ACK 时已反映新策略；更晚有效期允许、缩短有效期拒绝；同一签名输入搬到不同目录不改变 authorization/resource 摘要。

Netd `ForwardPolicyUpdate` 使用原 Active owner，单调本地 policy revision 与精确 signed hash 绑定幂等重试。Linux 先安装目标路线，再原子替换 nft，最后删除旧路线；无 TUN 重建、接口地址/MTU变更或共享 sysctl 重置。部分失败落盘并重试原目标；到期或撤销先持久化取消，再隔离并清理不完整目标，不能重放已过期路线。取消后仅新增的目标前缀回到主机现有路由，本轮未引入永久 reject 新语义。

Netd Linux 真实内核门禁通过：20 轮 remote 路由和本地源集合更新，完整 TUN link/address、owner/fence 均不变；删除 nft 表注入“目标路线已安装、nft 更新失败”，到期后目标新增路线与 selector 清理、原 remote reject 保留。单元/集成及 all-target 严格 Clippy 通过。细节见 Runtime `docs/SDWAN_NETD_LIVE_POLICY_20261020.md`。

共享 listener 注册也必须将物理 dispatch 与活动策略拆开。原实现要求 `worker_authority_sha256 == 活动目录摘要`，会在 hot policy 后误拒绝正常 worker；同代目录变化还可能触发 host/pool 替换。现已分别核验原物理 authority 与活动目录摘要；本地 policy revision 仅在相同 worker incarnation 内单调，新 epoch 可以在相同 Cloud generation 使用新 Grant/hash 和 revision 0。热更新复用原 host/pool，不进入 drain。Linux registry 14 项通过，包含 status → record → plan → registration 各发布中间阶段轮询仍保留同一 host、原 lease 与连接，以及后续真实新 epoch 接管。

Core 的策略逻辑回执独立于周期遥测。actor 已确认而 status 文件写入失败时，内部活动策略仍前移，保留待发布回执并阻止后续 revision 越过；精确重试只补齐状态发布，不重复安装 actor。周期遥测、错误及停机状态写入都在同一 watch 写锁内合并回执，不能把 policy revision/hash 回退。真实 managed Unix 接口覆盖上述故障、后续 revision 拒绝、精确重试和更短授权拒绝；真实 packet actor 的周期 tick 覆盖回执保持。

Runtime 在编译与确认期间续保原 owner 的 30 秒短租约，但仍受初始物理授权 cap 限制。恢复时允许读取并采用同一物理 owner 已续新的 lease，仅更新 journal 的租约字段，不能改变原 policy intent。确切 IO/Netd 身份、无候选/未决副作用、Netd Revoked 及租约或授权到期证据同时成立时，保留完整终态与签名 snapshot 后归档，进入正式续期；UNKNOWN 继续保留屏障，不能伪造 ACTIVE。新 journal 创建前也核验 Netd 的实际 revision/gen/hash，避免覆盖来源不明的活动策略。

## 本轮最终验证与提交

- Core `a245f75`、`08fb4b2`、`686ddd8`：应用完整 **134/134**、Linux registry 14/14；真实 QUIC/OPEN 与 owner IPC、managed Unix 故障恢复及周期遥测回执门禁通过。Prepare 的超时、回复丢失和 actor 暂时不可用现在重放同一个不可变 Prepare，再查询双方回执；永久拒绝不会重放。候选相关测试 22/22，Core process/carrier-runtime/carrier-server 的 lib/tests 严格 Clippy 通过。使用既有 x86_64 static Core 做真实 Docker server/client TCP 转发门禁通过，临时网络和容器已自动清理。本轮修改文件格式和 diff 检查通过；workspace 格式检查仍报告既有 `candy-carrier-runtime/src/lib.rs` 模块排序差异，未修改无关文件。
- Runtime `ac63469`：完整 signed inbound closure；cloud-sync 116 项通过、1 项沿用原条件忽略。`785857c`：Netd 原 owner 原位策略事务及真实 Linux 内核门禁。`f53119e`：managed policy 事务、租约恢复与注册；Linux agent 157/157，最终 managed-policy 定向 4/4、registration 2/2，all-target 严格 Clippy 通过。
- Cloud `0aa4df3`、`3d00dd9`、`98727a7`：发布 fencing、独立恢复和落后 Peer 精确重同步；上述隔离 MySQL、UI、Caddy 和部署事务证据保持有效。

隔离冻结制品的 MBB 组合门禁已有通过证据：`registered-mbb-release-v16` 上 bilateral candidate reload、四域 shared-pool 扩缩容和 successor server restart 均通过，相关结果在 Runtime `docs/artifacts/sdwan-20261016/{bilateral-mbb-final-v16,shared-pool-negotiated-final-v16,successor-server-restart-v16}/result.json`。这些测试覆盖实际 Core/Runtime/Netd 测试边界，但仍是隔离制品，不是线上发布制品；不能替代生产节点验收、平台架构门禁、吞吐测试或两小时持续测试。两小时持续测试按用户要求延期。本轮未修改、重启或压测生产节点，多代开关继续默认关闭；上线前仍须按 Cloud → Core → Runtime 顺序完成组合门禁。

详细事务与故障注入证据分别见 Runtime `docs/SDWAN_MANAGED_POLICY_HOT_UPDATE_20261020.md` 和 `docs/SDWAN_NETD_LIVE_POLICY_20261020.md`。
