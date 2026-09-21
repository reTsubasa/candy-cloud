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

export function streamHealth(stream: RuntimeStreamTelemetry): 'ready' | 'backpressured' | 'fault' | 'starting' {
  if (stream.last_error_code || stream.decode_errors > 0) return 'fault';
  if (stream.state !== 'ready') return 'starting';
  if (stream.queue_limit > 0 && stream.queue_depth >= stream.queue_limit * 0.8) return 'backpressured';
  return 'ready';
}

export function pathHealth(path: RuntimePathTelemetry): 'ready' | 'backpressured' | 'fault' | 'starting' {
  const streams = path.streams ?? [];
  if (streams.some((stream) => streamHealth(stream) === 'fault')) return 'fault';
  if (streams.some((stream) => streamHealth(stream) === 'backpressured')) return 'backpressured';
  if (streams.length > 0 && !streams.some((stream) => stream.state === 'ready')) return 'starting';
  if (path.stream_count != null && (path.ready_streams ?? 0) === 0) return 'starting';
  return 'ready';
}

export function runtimeAttention(runtime: RuntimeTelemetry): string | null {
  if (runtime.failed_route_prefixes?.length) return `故障前缀 ${runtime.failed_route_prefixes.join('、')}`;
  const routeFault = routeDiagnosticsFault(runtime.route_diagnostics);
  if (routeFault) return routeFault;
  if (runtime.dataplane_phase && ['failed', 'degraded'].includes(runtime.dataplane_phase)) return dataplanePhaseLabel(runtime.dataplane_phase);
  const path = runtime.paths.find((item) => pathHealth(item) !== 'ready');
  if (path) return pathHealth(path) === 'backpressured' ? 'Stream 队列接近上限' : 'Stream 尚未稳定';
  return null;
}
