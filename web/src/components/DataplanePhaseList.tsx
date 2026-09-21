import type { OperationalNode } from '../operational-topology';
import { dataplanePhaseLabel } from '../runtime-observability';

export function DataplanePhaseList({ nodes }: { nodes: OperationalNode[] }) {
  if (!nodes.length) return null;
  return <div className="dataplane-phase-list">{nodes.map((node) => {
    const phase = node.telemetry?.dataplane_phase;
    const offline = !node.registered || node.telemetryState !== 'online';
    const label = !node.registered ? '未注册'
      : node.telemetryState === 'stale' ? '离线 · 遥测已过期'
      : node.telemetryState === 'unreported' ? '未上报遥测'
      : dataplanePhaseLabel(phase);
    const failed = node.telemetry?.failed_route_prefixes ?? [];
    const routeDetail = failed.length ? `；回程路由故障：${failed.join(', ')}` : '';
    const errorDetail = node.telemetry?.last_error_detail ? `；原因：${node.telemetry.last_error_detail}` : '';
    const detail = node.telemetry
      ? `${offline ? `最后上报：${node.telemetry.reported_at}；历史阶段：` : '阶段：'}${dataplanePhaseLabel(phase)}${routeDetail}${errorDetail}${offline ? '。当前状态无法确认。' : ''}`
      : undefined;
    return <div key={node.id}><span>{node.name}</span><strong title={detail}>{label}</strong></div>;
  })}</div>;
}
