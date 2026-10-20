import type { RuntimeTelemetry } from './types';
import { runtimeErrorStatusLabel, runtimeUserFailureDetail } from './runtime-error';

export type OperationalTone = 'green' | 'orange' | 'red' | 'gray';

export type OperationalStatus<Code extends string = string> = {
  code: Code;
  label: string;
  detail: string;
  tone: OperationalTone;
};

export type NodeOperationalCode =
  | 'unregistered'
  | 'registered'
  | 'telemetry_stale'
  | 'starting'
  | 'healthy'
  | 'runtime_fault';

export type LinkOperationalCode =
  | 'not_configured'
  | 'endpoint_offline'
  | 'authenticating'
  | 'one_way'
  | 'telemetry_stale'
  | 'active'
  | 'endpoint_failed'
  | 'path_failed'
  | 'degraded'
  | 'evidence_unknown';

export type NodeOperationalInput = {
  registered: boolean;
  attached: boolean;
  applyState: 'active' | 'rejected' | 'pending' | 'unknown';
  errorCode: string | null;
  telemetryState: 'online' | 'stale' | 'unreported';
  lifecycle: RuntimeTelemetry['lifecycle'] | null;
  configuredPeers: number;
  activePeers: number;
  requiredRouteOwners: number;
  readyRouteOwners: number;
  failOpenRequired: boolean;
  runtimeErrorCode: string | null;
  runtimeErrorDetail?: string | null;
  dataPlaneReady?: boolean;
  operationalAttention?: string | null;
  operationalTransition?: boolean;
};

export type LinkOperationalInput = {
  configuredPathCount: number;
  endpointOffline?: boolean;
  activeDirectionCount: number;
  staleDirectionCount: number;
  endpointFailed: boolean;
  missingDirectionLabels?: readonly string[];
  staleDirectionLabels?: readonly string[];
  failedEndpointLabels?: readonly string[];
  degradedPathLabels?: readonly string[];
  failedPathLabels?: readonly string[];
  unknownPathLabels?: readonly string[];
};

export const NODE_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '灰色', detail: '节点未认证、未接入、尚未上报或遥测已中断，当前不在线。' },
  { tone: 'green' as const, label: '绿色', detail: '节点身份已认证且 Runtime 遥测在线，Core 运行正常。' },
  { tone: 'orange' as const, label: '橙色', detail: 'Runtime 正在启动、恢复或切换状态。路由策略应用进度单独显示。' },
  { tone: 'red' as const, label: '红色', detail: 'Runtime 本身明确异常；路由策略应用失败单独显示。' },
];

export const SITE_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '未上线', detail: '没有在线节点，或节点遥测已中断。' },
  { tone: 'green' as const, label: '在线', detail: '已认证节点在线，Runtime 稳定上报。' },
  { tone: 'orange' as const, label: '处理中', detail: 'Runtime 正在启动或恢复。路由策略状态单独显示。' },
  { tone: 'red' as const, label: '异常', detail: '站点内 Runtime 明确异常。' },
];

export const LINK_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '链路断开', detail: '端点没有在线节点，或遥测已过期。' },
  { tone: 'orange' as const, label: '链路协商中', detail: '双向路径尚未全部建立。' },
  { tone: 'green' as const, label: '链路正常', detail: '双向数据面已建立，遥测持续更新。' },
  { tone: 'orange' as const, label: '链路性能降级', detail: '链路部分可用，Stream 背压、部分 Stream 故障或探测丢失影响容量。' },
  { tone: 'gray' as const, label: '证据不足', detail: '节点在线，但缺少当前 Peer 的就绪证据，不能确认链路可达。' },
  { tone: 'red' as const, label: '链路故障', detail: '端点或配置明确失败，当前不可转发。' },
];

export function nodeOperationalStatus(input: NodeOperationalInput): OperationalStatus<NodeOperationalCode> {
  if (!input.registered) return { code: 'unregistered', label: '未注册', detail: 'Cloud 中没有有效的节点身份', tone: 'gray' };
  if (!input.attached) return { code: 'registered', label: '未接入', detail: '节点身份已签发，但当前未接入 SD-WAN 网络', tone: 'gray' };
  if (input.telemetryState === 'stale') return { code: 'telemetry_stale', label: '离线', detail: '超过遥测新鲜度窗口没有收到节点上报', tone: 'gray' };
  if (input.telemetryState === 'unreported') return { code: 'registered', label: '未上线', detail: '节点身份已完成认证，但 Runtime 尚未上报在线状态', tone: 'gray' };
  const counters = {
    configuredPeers: input.configuredPeers,
    activePeers: input.activePeers,
    requiredRouteOwners: input.requiredRouteOwners,
    readyRouteOwners: input.readyRouteOwners,
  };
  if (input.telemetryState === 'online' && (input.failOpenRequired || input.lifecycle === 'fail_open' || input.lifecycle === 'degraded' || input.lifecycle === 'stopped')) {
    return { code: 'runtime_fault', label: runtimeErrorStatusLabel(input.runtimeErrorCode) ?? '运行异常', detail: input.runtimeErrorDetail || runtimeUserFailureDetail(input.runtimeErrorCode, counters, `Runtime 状态：${input.lifecycle}`), tone: 'red' };
  }
  if (input.lifecycle === 'starting' || input.lifecycle === 'unknown' || input.lifecycle === null) {
    return { code: 'starting', label: '正在启动', detail: 'Runtime 在线，但数据面尚未进入稳定运行状态', tone: 'orange' };
  }
  if (input.operationalTransition) return { code: 'starting', label: '数据面自愈中', detail: input.operationalAttention ?? 'Runtime 正在恢复数据面一致性', tone: 'orange' };
  return { code: 'healthy', label: '在线', detail: '节点身份已认证，Runtime 正常上报；Lane 状态在线路中单独判定', tone: 'green' };
}

export function linkOperationalStatus(input: LinkOperationalInput): OperationalStatus<LinkOperationalCode> {
  if (input.endpointOffline) return { code: 'endpoint_offline', label: '链路断开', detail: '至少一个端点站点没有在线节点，当前没有可用链路', tone: 'gray' };
  if (input.configuredPathCount === 0) return { code: 'not_configured', label: '线路未配置', detail: '互联关系已建立，但尚未设置候选线路', tone: 'orange' };
  if (input.endpointFailed) return { code: 'endpoint_failed', label: '链路故障', detail: input.failedEndpointLabels?.length ? `${input.failedEndpointLabels.join('、')}没有可工作的节点` : '至少一端没有可工作的节点', tone: 'red' };
  if (input.failedPathLabels?.length) return {
    code: input.activeDirectionCount > 0 ? 'degraded' : 'path_failed',
    label: input.activeDirectionCount > 0 ? '链路部分可用' : 'Peer 路径故障',
    detail: `${input.failedPathLabels.join('、')} Stream 故障；${input.activeDirectionCount > 0 ? '其余就绪路径仍可转发' : '当前没有就绪路径'}${input.degradedPathLabels?.length ? `；${input.degradedPathLabels.join('、')} 容量或探测异常` : ''}`,
    tone: input.activeDirectionCount > 0 ? 'orange' : 'red',
  };
  if (input.unknownPathLabels?.length && input.activeDirectionCount < 2) return {
    code: 'evidence_unknown', label: '链路状态待确认',
    detail: `${input.unknownPathLabels.join('、')} 缺少该 Peer 的 Stream 就绪证据，不能用其他 Peer 的活跃数量判定`, tone: 'gray',
  };
  if (input.degradedPathLabels?.length) return { code: 'degraded', label: '链路性能降级', detail: `${input.degradedPathLabels.join('、')} 存在 Stream 容量或探测异常，可用 Stream 仍可转发，但吞吐或时延可能受影响`, tone: 'orange' };
  if (input.activeDirectionCount === 2) return { code: 'active', label: '链路正常', detail: '双向数据面已建立，链路遥测持续更新', tone: 'green' };
  if (input.activeDirectionCount === 1) return { code: 'one_way', label: '链路协商中', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 尚未建立；正在等待另一方向完成协商` : '一侧路径已建立，正在等待另一方向完成协商', tone: 'orange' };
  if (input.staleDirectionCount > 0) return { code: 'telemetry_stale', label: '链路断开', detail: input.staleDirectionLabels?.length ? `${input.staleDirectionLabels.join('、')} 的链路遥测已过期，当前无法确认可达性` : '链路遥测已过期，当前无法确认可达性', tone: 'orange' };
  return { code: 'authenticating', label: '链路协商中', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 尚未建立；正在等待两端完成认证和路径协商` : '正在等待两端完成认证和路径协商', tone: 'orange' };
}
