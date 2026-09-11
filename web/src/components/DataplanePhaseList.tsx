import type { OperationalNode } from '../operational-topology';

const labels: Record<string, string> = {
  control_received: '已接收控制配置', control_verified: '控制配置已校验', config_compiled: '配置已编译',
  netd_prepared: '主机网络已准备', core_policy_staged: 'Core 策略已暂存', peer_connecting: 'Peer 连接中',
  peer_authenticated: 'Peer 已认证', stream_opening: 'Stream 建立中', stream_ready: 'Stream 已就绪',
  route_owners_ready: '路由 owner 已就绪', steering_committed: '流量接管已提交', data_plane_active: '数据面运行中',
  degraded: '数据面已降级', recovering: '数据面恢复中', failed: '数据面故障', stopping: '停止中', stopped: '已停止',
};

export function DataplanePhaseList({ nodes }: { nodes: OperationalNode[] }) {
  if (!nodes.length) return null;
  return <div className="dataplane-phase-list">{nodes.map((node) => {
    const phase = node.telemetry?.dataplane_phase;
    const offline = !node.registered || node.telemetryState !== 'online';
    const label = !node.registered ? '未注册'
      : node.telemetryState === 'stale' ? '离线 · 遥测已过期'
      : node.telemetryState === 'unreported' ? '未上报遥测'
      : phase ? labels[phase] ?? '未知数据面阶段' : '未上报数据面阶段';
    const detail = offline && node.telemetry
      ? `最后上报：${node.telemetry.reported_at}；历史阶段：${phase ? labels[phase] ?? phase : '未上报'}。当前状态无法确认。`
      : undefined;
    return <div key={node.id}><span>{node.name}</span><strong title={detail}>{label}</strong></div>;
  })}</div>;
}
