import { runtimeErrorReason, runtimeFailureDetail } from './runtime-error';

function metadataNumber(metadata: Record<string, unknown>, key: string): number | null {
  const value = metadata[key];
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

export function runtimeAuditEventDescription(
  action: string,
  metadata: Record<string, unknown>,
  recoveredDetail: string | null = null,
): string | null {
  const counters = {
    configuredPeers: metadataNumber(metadata, 'configured_peers'),
    activePeers: metadataNumber(metadata, 'active_peers'),
    requiredRouteOwners: metadataNumber(metadata, 'required_route_owners'),
    readyRouteOwners: metadataNumber(metadata, 'ready_route_owners'),
  };
  if (action === 'RUNTIME_CONFIGURATION_REJECTED') {
    return `${runtimeFailureDetail(metadata.error_code, counters, '节点未上报配置拒绝原因')}；当前配置未生效。`;
  }
  if (action === 'RUNTIME_FAIL_OPEN_ENTERED') {
    return `${runtimeFailureDetail(metadata.error_code, counters, 'Runtime 未上报明确错误码')}；系统已撤销 SD-WAN 路由，未匹配流量继续按节点本地网络策略转发。`;
  }
  if (action === 'RUNTIME_LIFECYCLE_DEGRADED') {
    const lifecycle = typeof metadata.lifecycle === 'string' ? metadata.lifecycle : '异常';
    return `${runtimeFailureDetail(metadata.error_code, counters, `Runtime 状态：${lifecycle}`)}。`;
  }
  if (action === 'RUNTIME_FAIL_OPEN_RECOVERED' || action === 'RUNTIME_LIFECYCLE_RECOVERED') {
    const previousReason = runtimeErrorReason(metadata.previous_error_code);
    return `${recoveredDetail ?? 'Runtime 已恢复运行。'}${previousReason ? ` 恢复前原因：${previousReason}。` : ''}`;
  }
  return null;
}
