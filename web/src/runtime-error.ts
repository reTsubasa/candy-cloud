export type RuntimeCounters = {
  configuredPeers?: number | null;
  activePeers?: number | null;
  requiredRouteOwners?: number | null;
  readyRouteOwners?: number | null;
};

export type RuntimeErrorDescriptor = {
  statusLabel: string;
  reason: string;
  category: 'core' | 'network' | 'activation' | 'authorization' | 'runtime';
  recovery: 'automatic' | 'configuration' | 'upgrade';
};

const core = (statusLabel: string, reason: string, recovery: RuntimeErrorDescriptor['recovery'] = 'automatic'): RuntimeErrorDescriptor => ({ statusLabel, reason, category: 'core', recovery });
const network = (statusLabel: string, reason: string, recovery: RuntimeErrorDescriptor['recovery'] = 'automatic'): RuntimeErrorDescriptor => ({ statusLabel, reason, category: 'network', recovery });
const activation = (statusLabel: string, reason: string, recovery: RuntimeErrorDescriptor['recovery'] = 'configuration'): RuntimeErrorDescriptor => ({ statusLabel, reason, category: 'activation', recovery });
const authorization = (statusLabel: string, reason: string, recovery: RuntimeErrorDescriptor['recovery'] = 'automatic'): RuntimeErrorDescriptor => ({ statusLabel, reason, category: 'authorization', recovery });
const runtime = (statusLabel: string, reason: string, recovery: RuntimeErrorDescriptor['recovery'] = 'automatic'): RuntimeErrorDescriptor => ({ statusLabel, reason, category: 'runtime', recovery });

const runtimeErrors: Record<string, RuntimeErrorDescriptor> = {
  all_peer_reads_failed: core('接收通道全部中断', '所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量'),
  all_peer_writes_failed: core('发送通道全部中断', '所有已配置 Peer 的发送通道均已失败，节点无法向任何远端发送流量'),
  all_peer_readers_stopped: core('接收任务全部停止', '所有 Peer 接收任务均已停止，节点已失去远端流量入口'),
  route_has_no_active_peer: core('路由无可用对端', '当前 SD-WAN 路由没有任何已认证且可转发的 Peer'),
  route_peer_missing: core('路由引用无效对端', '当前 SD-WAN 路由引用了 Core 配置中不存在的 Peer', 'configuration'),
  route_owner_failed: core('路由出口未就绪', '策略指定的路由出口未完成连接，当前流量不能交给该出口'),
  tun_read_failed: core('虚拟网卡读取失败', 'Candy Core 无法从本机 TUN 虚拟网卡读取待转发流量'),
  tun_write_failed: core('虚拟网卡写入失败', 'Candy Core 无法把远端流量写回本机 TUN 虚拟网卡'),
  peer_datagram_read_failed: core('对端数据读取失败', 'Candy Core 无法从对端 QUIC 会话读取数据报'),
  peer_datagram_write_failed: core('对端数据发送失败', 'Candy Core 无法向对端 QUIC 会话发送数据报'),
  core_exit: core('Core 进程已退出', 'Candy Core 进程意外退出，Runtime 已撤销其网络规则并等待自动重启'),
  core_start_failed: core('Core 启动失败', 'Runtime 无法启动 Candy Core 进程；当前使用本地降级出口'),
  core_process_inspection_failed: core('Core 进程检查失败', 'Runtime 无法读取 Candy Core 进程状态，已按数据面不可用处理'),
  core_status_unavailable: core('Core 状态文件不存在', 'Candy Core 未生成当前激活代次的状态文件，或状态文件已随异常退出丢失'),
  core_status_invalid: core('Core 状态无效', 'Candy Core 状态文件的代次、进程身份或字段校验不通过'),
  core_status_inspection_failed: core('Core 状态读取失败', 'Runtime 无法读取或校验 Candy Core 当前状态，已撤销 SD-WAN 网络规则'),
  core_readiness_failed: core('Core 未就绪', 'Candy Core 未达到接管流量所需的 Peer、路由出口和 TUN 就绪条件'),
  core_readiness_lost: core('Core 就绪状态丢失', 'Candy Core 运行中不再满足数据面就绪条件，Runtime 正在自动重连'),
  core_route_readiness_lost: core('策略出口失去就绪', '当前策略所需的一个或多个路由出口已断开，Runtime 正在自动重连'),
  core_runtime_failed: core('Core 运行失败', 'Candy Core 明确上报数据面失败，Runtime 已撤销路由并安排自动重启'),
  core_traffic_blackhole: core('旧版流量黑洞误判', '旧版 Runtime 根据聚合丢包计数判定流量黑洞；该计数包含正常策略丢弃，升级后不再以此触发整节点降级', 'upgrade'),
  core_readiness_timeout: core('Core 热加载超时', 'Candy Core 接受了新配置，但未在限定时间内上报新代次已就绪；Runtime 已恢复上一份可用配置'),
  core_exit_during_hot_reload: core('Core 热加载时退出', 'Candy Core 在应用新配置期间退出，Runtime 已拒绝该配置并保留降级转发'),
  core_hot_reload_failed: core('Core 热加载被拒绝', 'Candy Core 未接受新配置；Runtime 已恢复上一份可用配置'),
  hot_transition_failed: runtime('热切换恢复失败', '新配置热切换失败，且上一份 SD-WAN 配置未能完整恢复；Runtime 将在本地降级出口上自动重试'),
  proxy_fallback_failed: runtime('Proxy 降级失败', 'Runtime 无法在热切换期间启用 Candy Proxy 降级转发'),
  core_discovery_failed: core('Core 不可用', 'Runtime 未找到可启动的 Candy Core', 'upgrade'),
  core_verification_failed: core('Core 校验失败', 'Candy Core 文件的完整性或发布签名校验失败', 'upgrade'),
  core_compatibility_verification_failed: core('Core 版本不兼容', 'Candy Core 不支持当前 Runtime 平台或下发配置版本', 'upgrade'),
  invalid_generation: activation('配置代次无效', 'Cloud 下发的配置代次为零或不符合递增约束'),
  invalid_lease: activation('网络租约无效', '配置指定的本机网络规则租约时长超出 Runtime 支持范围'),
  invalid_readiness_timeout: activation('就绪超时参数无效', '配置指定的 Core 就绪等待时间超出 Runtime 支持范围'),
  signal_handler_failed: runtime('进程信号初始化失败', 'Runtime 无法安装停止和重启信号处理器'),
  declaration_invalid: activation('网络规则声明无效', 'Cloud 下发的路由、防火墙或 TUN 声明未通过 Runtime 校验'),
  instance_id_invalid: activation('运行实例标识无效', '当前 SD-WAN Runtime 实例标识格式错误'),
  readiness_token_failed: runtime('就绪凭据生成失败', 'Runtime 无法生成用于绑定 Core 进程和状态文件的一次性就绪凭据'),
  status_cleanup_failed: runtime('旧状态清理失败', 'Runtime 无法清理上一代 Core 状态文件，为避免读取旧状态已拒绝激活'),
  activation_receipt_failed: activation('激活结果写入失败', 'Runtime 无法持久化当前配置的激活结果，Cloud 不能确认该配置已生效'),
  activation_invalid: activation('候选配置无效', '新候选配置文件缺失、已被替换或未通过本地完整性校验'),
  candidate_inspection_failed: activation('候选配置检查失败', 'Runtime 无法读取或验证 Cloud 发布的候选配置'),
  runtime_activation_unavailable: activation('活动配置不可用', '本地 active 指针存在，但对应的已验证激活目录或证明文件不可用'),
  runtime_agent_exit: runtime('Runtime Agent 已退出', '负责维持网络租约和 Core 生命周期的 Runtime Agent 进程已退出'),
  local_activation_failed: activation('本地配置激活失败', '节点已收到配置，但无法在本地启动并激活 SD-WAN 数据面'),
  local_publish_failed: activation('本地配置发布失败', '节点无法把已验证的 SD-WAN 配置原子发布给 Runtime'),
  cloud_sync_failed: runtime('Cloud 同步失败', 'Runtime 无法完成配置拉取、校验、状态投影或遥测上报'),
  netd_prepare_failed: network('网络规则预检失败', '本机网络管理服务未能创建 TUN 或预检路由、防火墙规则'),
  netd_commit_failed: network('网络规则接管失败', 'Candy Core 已就绪，但本机网络管理服务未能提交路由和防火墙规则'),
  netd_lease_failed: network('网络规则租约续期失败', 'Runtime 未能续期本机网络规则租约；为避免残留劫持已撤销 SD-WAN 路由'),
  lease_clock_failed: network('网络租约时钟失败', 'Runtime 无法读取或计算本机单调时钟上的网络规则租约期限'),
  rollback_failed: network('网络规则回滚失败', 'SD-WAN 激活失败后，本机网络管理服务未能完整撤销路由或防火墙规则'),
  netd_reconfigure_failed: network('网络规则热更新失败', '旧版 Runtime 未能热更新本机路由或防火墙规则；请升级 Runtime 后重试', 'upgrade'),
  netd_reconfigure_invalid_transition: network('网络规则状态冲突', '本机网络规则不在可热更新的生命周期阶段；Runtime 已保留上一份可用配置', 'configuration'),
  netd_reconfigure_owner_conflict: network('网络规则租约冲突', '本机网络规则由另一进程或代次持有，当前 Runtime 无权覆盖'),
  netd_reconfigure_platform_failed: network('系统网络规则应用失败', '操作系统拒绝应用新路由、防火墙或虚拟网卡配置；Runtime 已保留上一份可用配置'),
  netd_reconfigure_unauthorized: network('网络管理权限校验失败', 'Runtime 进程身份未通过本机网络管理服务校验', 'configuration'),
  netd_reconfigure_system_failed: network('网络管理服务异常', '本机网络管理服务写入事务状态失败，未能完成热更新'),
  netd_reconfigure_ipc_failed: network('网络管理通信失败', 'Runtime 无法与本机网络管理服务完成热更新通信'),
  grant_resolution_failed: authorization('节点授权获取失败', 'Runtime 无法从 Cloud 获取或解析当前节点授权'),
  grant_service_unavailable: authorization('授权服务不可用', '节点授权服务暂时不可用，且本地没有仍可使用的授权'),
  grant_authorization_denied: authorization('节点授权被拒绝', 'Cloud 拒绝签发该节点的 SD-WAN 授权', 'configuration'),
  grant_core_verification_failed: authorization('授权签名校验失败', 'Candy Core 未通过节点授权签名校验', 'configuration'),
  grant_binding_mismatch: authorization('节点授权不匹配', '节点授权与当前节点、出口或策略代次不匹配', 'configuration'),
  grant_not_yet_valid: authorization('节点授权尚未生效', '节点授权尚未进入生效时间'),
  grant_expired: authorization('节点授权已过期', '节点授权已经过期，需要从 Cloud 获取新授权'),
  grant_response_mismatch: authorization('授权响应不一致', 'Cloud 授权响应与已签名授权内容不一致', 'configuration'),
  grant_state_invalid: authorization('本地授权状态异常', '节点本地授权状态损坏或与当前策略不匹配', 'configuration'),
  public_endpoint_required: activation('缺少公网端点', '作为中继或出口的节点没有可供其他站点连接的公网传输端点'),
};

export const RUNTIME_ERROR_CODES = Object.freeze(Object.keys(runtimeErrors).sort());

export function runtimeErrorDescriptor(code: unknown): RuntimeErrorDescriptor | null {
  if (typeof code !== 'string' || !code.trim()) return null;
  return runtimeErrors[code.trim()] ?? null;
}

function nonNegativeInteger(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

export function runtimeErrorReason(code: unknown): string | null {
  if (typeof code !== 'string' || !code.trim()) return null;
  const normalized = code.trim();
  return runtimeErrors[normalized] ? `${runtimeErrors[normalized].reason}（${normalized}）` : `Runtime 错误码：${normalized}`;
}

export function runtimeErrorStatusLabel(code: unknown): string | null {
  if (typeof code !== 'string' || !code.trim()) return null;
  return runtimeErrors[code.trim()]?.statusLabel ?? null;
}

export function runtimeErrorUserReason(code: unknown): string | null {
  if (typeof code !== 'string' || !code.trim()) return null;
  const normalized = code.trim();
  return runtimeErrors[normalized]?.reason ?? `Runtime 上报了未识别的错误（${normalized}）`;
}

export function runtimeCounterEvidence(counters: RuntimeCounters): string | null {
  const configuredPeers = nonNegativeInteger(counters.configuredPeers);
  const activePeers = nonNegativeInteger(counters.activePeers);
  const requiredRouteOwners = nonNegativeInteger(counters.requiredRouteOwners);
  const readyRouteOwners = nonNegativeInteger(counters.readyRouteOwners);
  const parts: string[] = [];
  if (configuredPeers !== null && activePeers !== null && (configuredPeers > 0 || activePeers > 0)) {
    parts.push(`Peer 连接 ${activePeers}/${configuredPeers}`);
  }
  if (requiredRouteOwners !== null && readyRouteOwners !== null && (requiredRouteOwners > 0 || readyRouteOwners > 0)) {
    parts.push(`路由就绪 ${readyRouteOwners}/${requiredRouteOwners}`);
  }
  return parts.length > 0 ? parts.join('，') : null;
}

export function runtimeUserFailureDetail(
  errorCode: unknown,
  counters: RuntimeCounters,
  fallback: string,
): string {
  const reason = runtimeErrorUserReason(errorCode) ?? fallback;
  const evidence = runtimeCounterEvidence(counters);
  return `原因：${reason}${evidence ? `；${evidence}` : ''}`;
}

export function runtimeFailureDetail(
  errorCode: unknown,
  counters: RuntimeCounters,
  fallback: string,
): string {
  const reason = runtimeErrorReason(errorCode) ?? fallback;
  const evidence = runtimeCounterEvidence(counters);
  return `原因：${reason}${evidence ? `；${evidence}` : ''}`;
}
