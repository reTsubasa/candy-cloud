export type RuntimeCounters = {
  configuredPeers?: number | null;
  activePeers?: number | null;
  requiredRouteOwners?: number | null;
  readyRouteOwners?: number | null;
};

type RuntimeErrorDescriptor = { statusLabel: string; reason: string };

const runtimeErrors: Record<string, RuntimeErrorDescriptor> = {
  all_peer_reads_failed: { statusLabel: '接收通道全部中断', reason: '所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量' },
  all_peer_writes_failed: { statusLabel: '发送通道全部中断', reason: '所有已配置 Peer 的发送通道均已失败，节点无法向任何远端发送流量' },
  all_peer_readers_stopped: { statusLabel: '接收任务全部停止', reason: '所有 Peer 接收任务均已停止，节点已失去远端流量入口' },
  route_has_no_active_peer: { statusLabel: '路由无可用对端', reason: '当前 SD-WAN 路由没有任何已连接且可转发的 Peer' },
  route_peer_missing: { statusLabel: '路由引用无效对端', reason: '当前 SD-WAN 路由引用了配置中不存在的 Peer' },
  tun_read_failed: { statusLabel: '虚拟网卡读取失败', reason: 'Runtime 无法从本机 TUN 虚拟网卡读取待转发流量' },
  tun_write_failed: { statusLabel: '虚拟网卡写入失败', reason: 'Runtime 无法把远端流量写入本机 TUN 虚拟网卡' },
  peer_datagram_read_failed: { statusLabel: '对端数据读取失败', reason: 'Runtime 无法从对端传输会话读取数据报' },
  peer_datagram_write_failed: { statusLabel: '对端数据发送失败', reason: 'Runtime 无法向对端传输会话写入数据报' },
  core_exit: { statusLabel: 'Core 进程已退出', reason: 'Candy Core 进程意外退出，Runtime 无法继续维持数据面' },
  core_readiness_failed: { statusLabel: 'Core 未就绪', reason: 'Candy Core 就绪检查失败，数据面未达到可接管流量的条件' },
  core_readiness_timeout: { statusLabel: 'Core 热加载超时', reason: 'Candy Core 接受了新配置，但未在限定时间内上报新代次已就绪；Runtime 已恢复上一份可用配置' },
  core_exit_during_hot_reload: { statusLabel: 'Core 热加载时退出', reason: 'Candy Core 在应用新配置期间退出，Runtime 已拒绝该配置并保留降级转发' },
  core_hot_reload_failed: { statusLabel: 'Core 热加载被拒绝', reason: 'Candy Core 未接受新配置；Runtime 已恢复上一份可用配置' },
  hot_transition_failed: { statusLabel: '热切换恢复失败', reason: '配置热切换未完成，且上一份 SD-WAN 配置未能完整恢复；Runtime 已保持本地降级转发' },
  core_discovery_failed: { statusLabel: 'Core 不可用', reason: 'Runtime 未找到可启动的 Candy Core' },
  core_verification_failed: { statusLabel: 'Core 校验失败', reason: 'Candy Core 完整性或签名验证失败' },
  core_compatibility_verification_failed: { statusLabel: 'Core 版本不兼容', reason: 'Candy Core 与当前 Runtime 或下发配置不兼容' },
  grant_resolution_failed: { statusLabel: '节点授权获取失败', reason: 'Runtime 无法从 Cloud 获取或解析当前节点授权' },
  grant_service_unavailable: { statusLabel: '授权服务不可用', reason: '节点授权服务暂时不可用，且本地没有仍可使用的授权' },
  grant_authorization_denied: { statusLabel: '节点授权被拒绝', reason: 'Cloud 拒绝签发该节点的 SD-WAN 授权' },
  grant_core_verification_failed: { statusLabel: '授权签名校验失败', reason: 'Candy Core 未通过节点授权签名校验' },
  grant_binding_mismatch: { statusLabel: '节点授权不匹配', reason: '节点授权与当前节点、出口或策略代次不匹配' },
  grant_not_yet_valid: { statusLabel: '节点授权尚未生效', reason: '节点授权尚未进入生效时间' },
  grant_expired: { statusLabel: '节点授权已过期', reason: '节点授权已经过期，需要从 Cloud 获取新授权' },
  grant_response_mismatch: { statusLabel: '授权响应不一致', reason: 'Cloud 授权响应与已签名授权内容不一致' },
  grant_state_invalid: { statusLabel: '本地授权状态异常', reason: '节点本地授权状态损坏或与当前策略不匹配' },
  local_activation_failed: { statusLabel: '本地配置激活失败', reason: '节点已收到配置，但无法在本地激活 SD-WAN 数据面' },
  local_publish_failed: { statusLabel: '本地配置发布失败', reason: '节点无法把已验证的 SD-WAN 配置发布给 Runtime' },
  netd_reconfigure_failed: { statusLabel: '网络规则热更新失败', reason: '旧版 Runtime 未能热更新本机路由或防火墙规则；请升级 Runtime 后重试' },
  netd_reconfigure_invalid_transition: { statusLabel: '网络规则状态冲突', reason: '本机网络规则不在可热更新的生命周期阶段；Runtime 已停止重试该配置并保留上一份可用配置' },
  netd_reconfigure_owner_conflict: { statusLabel: '网络规则租约冲突', reason: '本机网络规则由另一进程或代次持有，当前 Runtime 无权覆盖' },
  netd_reconfigure_platform_failed: { statusLabel: '系统网络规则应用失败', reason: '操作系统拒绝应用新路由、防火墙或虚拟网卡配置；Runtime 已保留上一份可用配置' },
  netd_reconfigure_unauthorized: { statusLabel: '网络管理权限校验失败', reason: 'Runtime 进程身份未通过本机网络管理服务校验' },
  netd_reconfigure_system_failed: { statusLabel: '网络管理服务异常', reason: '本机网络管理服务写入事务状态失败，未能完成热更新' },
  netd_reconfigure_ipc_failed: { statusLabel: '网络管理通信失败', reason: 'Runtime 无法与本机网络管理服务完成热更新通信' },
  public_endpoint_required: { statusLabel: '缺少公网端点', reason: '节点没有可供其他站点连接的公网传输端点' },
};

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
