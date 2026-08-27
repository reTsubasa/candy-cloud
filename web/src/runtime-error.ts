export type RuntimeCounters = {
  configuredPeers?: number | null;
  activePeers?: number | null;
  requiredRouteOwners?: number | null;
  readyRouteOwners?: number | null;
};

const runtimeErrorLabels: Record<string, string> = {
  all_peer_reads_failed: '所有 Peer 接收路径读取失败',
  all_peer_writes_failed: '所有 Peer 发送路径写入失败',
  all_peer_readers_stopped: '所有 Peer 接收任务已经停止',
  route_has_no_active_peer: '路由没有可用的活跃 Peer',
  route_peer_missing: '路由引用的 Peer 不存在',
  tun_read_failed: '读取 TUN 接口失败',
  tun_write_failed: '写入 TUN 接口失败',
  peer_datagram_read_failed: '读取 Peer 数据报失败',
  peer_datagram_write_failed: '写入 Peer 数据报失败',
  core_exit: 'Candy Core 进程已退出',
  core_readiness_failed: 'Candy Core 就绪检查失败',
  core_discovery_failed: '未找到可用的 Candy Core',
  core_verification_failed: 'Candy Core 验证失败',
  core_compatibility_verification_failed: 'Candy Core 与当前配置不兼容',
  grant_resolution_failed: '无法获取或解析节点授权',
  local_activation_failed: '本地配置激活失败',
  local_publish_failed: '本地配置发布失败',
  public_endpoint_required: '节点缺少可用的公网传输端点',
};

function nonNegativeInteger(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

export function runtimeErrorReason(code: unknown): string | null {
  if (typeof code !== 'string' || !code.trim()) return null;
  const normalized = code.trim();
  return runtimeErrorLabels[normalized] ? `${runtimeErrorLabels[normalized]}（${normalized}）` : `Runtime 错误码：${normalized}`;
}

export function runtimeCounterEvidence(counters: RuntimeCounters): string | null {
  const configuredPeers = nonNegativeInteger(counters.configuredPeers);
  const activePeers = nonNegativeInteger(counters.activePeers);
  const requiredRouteOwners = nonNegativeInteger(counters.requiredRouteOwners);
  const readyRouteOwners = nonNegativeInteger(counters.readyRouteOwners);
  const parts: string[] = [];
  if (configuredPeers !== null && activePeers !== null && (configuredPeers > 0 || activePeers > 0)) {
    parts.push(`Peer ${activePeers}/${configuredPeers}`);
  }
  if (requiredRouteOwners !== null && readyRouteOwners !== null && (requiredRouteOwners > 0 || readyRouteOwners > 0)) {
    parts.push(`路由 ${readyRouteOwners}/${requiredRouteOwners}`);
  }
  return parts.length > 0 ? parts.join('，') : null;
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
