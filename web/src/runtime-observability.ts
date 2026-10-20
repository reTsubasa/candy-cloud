import type { RuntimePathTelemetry, RuntimeRouteDiagnostics, RuntimeStreamTelemetry, RuntimeTelemetry } from './types';

/** The phase names are the wire values emitted by candy-sdwan-agent/Core. */
export const DATAPLANE_PHASE_LABELS: Record<string, string> = {
  control_received: '已接收控制配置',
  control_verified: '控制配置已校验',
  config_compiled: '配置已编译',
  netd_prepared: '主机网络已准备',
  core_policy_staged: 'Core 策略已暂存',
  peer_connecting: 'Peer 连接中',
  peer_authenticated: 'Peer 已认证',
  stream_opening: 'Stream 建立中',
  stream_ready: 'Stream 已就绪',
  route_owners_ready: '路由 owner 已就绪',
  steering_committed: '流量接管已提交',
  data_plane_active: '数据面运行中',
  degraded: '数据面已降级',
  recovering: '数据面恢复中',
  failed: '数据面故障',
  stopping: '停止中',
  stopped: '已停止',
};

export function dataplanePhaseLabel(phase: string | null | undefined): string {
  if (!phase) return '未上报数据面阶段';
  return DATAPLANE_PHASE_LABELS[phase] ?? `未知阶段（${phase}）`;
}

export function routeDiagnosticsFault(diagnostics: RuntimeRouteDiagnostics | null | undefined): string | null {
  if (!diagnostics) return null;
  if (diagnostics.integrity === 'failed') return diagnostics.last_error_code ?? 'route_reconciliation_failed';
  if (diagnostics.integrity === 'drifted') return diagnostics.last_error_code ?? 'route_snapshot_mismatch';
  if (diagnostics.probe_state === 'failed') return diagnostics.last_error_code ?? 'route_probe_failed';
  if (diagnostics.active_issues.length > 0) return diagnostics.last_error_code ?? 'route_snapshot_mismatch';
  return null;
}

export function runtimeDataPlaneReady(runtime: RuntimeTelemetry): boolean {
  // This mirrors candy-cloud-sync::core_data_plane_ready and adds the
  // operator-visible route/probe evidence forwarded by Runtime. The phase is
  // explanatory only because older Core versions did not emit it.
  return runtime.lifecycle === 'active'
    && runtime.required_route_owners > 0
    && runtime.ready_route_owners === runtime.required_route_owners
    && !runtime.fail_open_required
    && !runtime.last_error_code
    && !routeDiagnosticsFault(runtime.route_diagnostics);
}

export type PathHealth = 'ready' | 'backpressured' | 'degraded' | 'fault' | 'starting' | 'unknown';

export function streamHealth(stream: RuntimeStreamTelemetry): 'ready' | 'backpressured' | 'fault' | 'starting' {
  // Counters and last_error_code survive recoverable congestion drops. The
  // current state determines readiness; retain historical evidence separately.
  if (['failed', 'closed', 'reset', 'fault'].includes(stream.state)) return 'fault';
  if (stream.state !== 'ready') return 'starting';
  if (stream.queue_limit > 0 && stream.queue_depth >= stream.queue_limit * 0.8) return 'backpressured';
  return 'ready';
}

export function pathHealth(path: RuntimePathTelemetry): PathHealth {
  const streams = path.streams ?? [];
  if (streams.length > 0) {
    const states = streams.map(streamHealth);
    const usable = states.filter((state) => state === 'ready' || state === 'backpressured');
    if (usable.length === 0) return states.some((state) => state === 'fault') ? 'fault' : 'starting';
    // One lane failing cannot invalidate healthy lanes on the same Peer. Still
    // expose the reduced capacity and current errors instead of painting green.
    if (usable.length < streams.length || (path.ready_streams != null && path.stream_count != null && path.ready_streams < path.stream_count)
      || (path.probe_misses ?? 0) > 0) return 'degraded';
    if (usable.some((state) => state === 'backpressured')) return 'backpressured';
    return 'ready';
  }
  // Summary readiness is per Peer. Host-wide active_peers, traffic counters,
  // RTT and connection_epoch cannot establish this particular Peer's health.
  if (path.ready_streams != null && path.ready_streams > 0) {
    if ((path.stream_count != null && path.ready_streams < path.stream_count) || (path.probe_misses ?? 0) > 0) return 'degraded';
    if (path.queue_limit != null && path.queue_limit > 0 && (path.queue_depth ?? 0) >= path.queue_limit * 0.8) return 'backpressured';
    return 'ready';
  }
  if (path.ready_streams != null || path.stream_count != null) return 'starting';
  return 'unknown';
}

export function runtimeAttention(runtime: RuntimeTelemetry): string | null {
  if (runtime.failed_route_prefixes?.length) return `故障前缀 ${runtime.failed_route_prefixes.join('、')}`;
  const routeFault = routeDiagnosticsFault(runtime.route_diagnostics);
  if (routeFault) return routeFault;
  if (runtime.dataplane_phase && ['failed', 'degraded'].includes(runtime.dataplane_phase)) return dataplanePhaseLabel(runtime.dataplane_phase);
  const path = runtime.paths.find((item) => pathHealth(item) !== 'ready');
  if (path) {
    const health = pathHealth(path);
    if (health === 'backpressured') return 'Stream 队列接近上限';
    if (health === 'degraded') return 'Peer 部分 Stream 不可用或探测丢失，其余 Stream 仍可转发';
    if (health === 'unknown') return '缺少当前 Peer 的 Stream 就绪证据';
    return health === 'fault' ? 'Peer Stream 故障' : 'Stream 尚未稳定';
  }
  return null;
}
