import { runtimeErrorReason, runtimeFailureDetail } from './runtime-error';

function appendRuntimeErrorDetail(description: string, metadata: Record<string, unknown>): string {
  const detail = typeof metadata.error_detail === 'string' ? metadata.error_detail.trim() : '';
  return detail ? `${description}；现场详情：${detail.slice(0, 512)}` : description;
}

function metadataNumber(metadata: Record<string, unknown>, key: string): number | null {
  const value = metadata[key];
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

function routeIssueSummary(metadata: Record<string, unknown>, key: 'active_issues' | 'last_recovered_issues'): string | null {
  const issues = metadata[key];
  if (!Array.isArray(issues) || issues.length === 0) return null;
  const first = issues[0];
  if (!first || typeof first !== 'object' || Array.isArray(first)) return null;
  const issue = first as Record<string, unknown>;
  const prefix = typeof issue.prefix === 'string' ? issue.prefix : null;
  const reason = typeof issue.reason === 'string' ? issue.reason : null;
  const table = metadataNumber(issue, 'table_id');
  if (!prefix || !reason) return null;
  const reasonLabels: Record<string, string> = {
    missing_route: '声明路由缺失',
    stale_failed_prefix_throw: '故障前缀的 throw 路由未恢复',
    stale_active_route: '已恢复前缀仍保留活动路由',
    route_metrics_mismatch: '路由 MTU 或 TCP MSS 与声明不一致',
    route_attributes_mismatch: '路由属性与声明不一致',
    undeclared_route: '存在声明之外的残留路由',
  };
  return `首个异常 ${prefix}${table !== null ? `（表 ${table}）` : ''}：${reasonLabels[reason] ?? reason}${issues.length > 1 ? `，另有 ${issues.length - 1} 条` : ''}`;
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
    return appendRuntimeErrorDetail(`${runtimeFailureDetail(metadata.error_code, counters, '节点未上报配置拒绝原因')}；当前配置未生效。`, metadata);
  }
  if (action === 'RUNTIME_FAIL_OPEN_ENTERED') {
    return appendRuntimeErrorDetail(`${runtimeFailureDetail(metadata.error_code, counters, '旧版 Runtime 在撤销路由前未持久化原始故障码，本事件无法还原具体数据面故障；升级后每次降级都会保留明确错误码')}；系统已撤销 SD-WAN 路由，未匹配流量继续按节点本地网络策略转发。`, metadata);
  }
  if (action === 'RUNTIME_LIFECYCLE_DEGRADED') {
    const lifecycle = typeof metadata.lifecycle === 'string' ? metadata.lifecycle : '异常';
    return appendRuntimeErrorDetail(`${runtimeFailureDetail(metadata.error_code, counters, `Runtime 状态：${lifecycle}`)}。`, metadata);
  }
  if (action === 'RUNTIME_DATAPLANE_PHASE_CHANGED') {
    const phase = typeof metadata.dataplane_phase === 'string' ? metadata.dataplane_phase : '未知阶段';
    const previous = typeof metadata.previous_dataplane_phase === 'string' ? metadata.previous_dataplane_phase : null;
    return appendRuntimeErrorDetail(`数据面阶段：${previous ? `${previous} → ` : ''}${phase}`, metadata);
  }
  if (action === 'RUNTIME_ROUTE_DRIFT_DETECTED' || action === 'RUNTIME_ROUTE_RECONCILIATION_ATTEMPTED') {
    const expected = metadataNumber(metadata, 'expected_routes');
    const observed = metadataNumber(metadata, 'observed_routes');
    const orphaned = metadataNumber(metadata, 'orphaned_routes');
    const attempts = metadataNumber(metadata, 'reconcile_attempts');
    const successes = metadataNumber(metadata, 'reconcile_successes');
    const counts = expected !== null && observed !== null && orphaned !== null
      ? `声明 ${expected} 条，内核实测 ${observed} 条，孤儿路由 ${orphaned} 条`
      : '节点未上报完整路由计数';
    const history = attempts !== null && successes !== null ? `；累计自愈 ${successes}/${attempts} 次成功` : '';
    const reason = runtimeErrorReason(metadata.error_code);
    const issue = routeIssueSummary(metadata, 'active_issues');
    return `${counts}${history}${issue ? `；${issue}` : ''}${reason ? `；原因：${reason}` : ''}。`;
  }
  if (action === 'RUNTIME_ROUTE_RECONCILIATION_RECOVERED') {
    const duration = metadataNumber(metadata, 'last_recovery_duration_ms');
    const attempts = metadataNumber(metadata, 'reconcile_attempts');
    const successes = metadataNumber(metadata, 'reconcile_successes');
    const issue = routeIssueSummary(metadata, 'last_recovered_issues');
    return `内核路由已与声明快照重新一致${duration !== null ? `，本次恢复耗时 ${duration} ms` : ''}${attempts !== null && successes !== null ? `；累计自愈 ${successes}/${attempts} 次成功` : ''}${issue ? `；已处理：${issue}` : ''}。`;
  }
  if (action === 'RUNTIME_PACKET_PROBE_FAILED' || action === 'RUNTIME_PACKET_PROBE_RECOVERED') {
    const targets = metadataNumber(metadata, 'probe_targets');
    const successes = metadataNumber(metadata, 'probe_successes');
    const rtt = metadataNumber(metadata, 'probe_rtt_ms');
    const result = targets !== null && successes !== null ? `${successes}/${targets} 个目标通过` : '节点未上报完整目标计数';
    if (action === 'RUNTIME_PACKET_PROBE_FAILED') return `真实数据包探测失败：${result}。链路不会仅凭协商成功被标记为健康。`;
    return `真实数据包探测恢复：${result}${rtt !== null ? `，往返时延 ${rtt} ms` : ''}。`;
  }
  if (action === 'RUNTIME_FAIL_OPEN_RECOVERED' || action === 'RUNTIME_LIFECYCLE_RECOVERED') {
    const previousReason = runtimeErrorReason(metadata.previous_error_code);
    return `${recoveredDetail ?? 'Runtime 已恢复运行。'}${previousReason ? ` 恢复前原因：${previousReason}。` : ''}`;
  }
  return null;
}
