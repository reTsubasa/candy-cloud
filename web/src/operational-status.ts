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
  | 'policy_updating'
  | 'telemetry_stale'
  | 'starting'
  | 'healthy'
  | 'policy_rejected'
  | 'runtime_fault';

export type LinkOperationalCode =
  | 'not_configured'
  | 'endpoint_offline'
  | 'policy_updating'
  | 'authenticating'
  | 'one_way'
  | 'telemetry_stale'
  | 'active'
  | 'configuration_failed'
  | 'endpoint_failed';

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
  policyUpdating: boolean;
  configurationFailed: boolean;
  endpointFailed: boolean;
  missingDirectionLabels?: readonly string[];
  staleDirectionLabels?: readonly string[];
  failedEndpointLabels?: readonly string[];
  degradedPathLabels?: readonly string[];
};

export const NODE_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '灰色', detail: '节点未认证、未接入、尚未上报或遥测已中断，当前不在线。' },
  { tone: 'green' as const, label: '绿色', detail: '节点身份已认证且 Runtime 遥测在线，数据面正常上报。' },
  { tone: 'orange' as const, label: '橙色', detail: '节点正在注册、启动、应用策略或执行其他状态切换。' },
  { tone: 'red' as const, label: '红色', detail: '节点拒绝配置，或 Runtime 本身明确异常；不包含 Lane、Peer 和路由故障。' },
];

export const SITE_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '灰色', detail: '站点没有在线节点；已认证但未上线、遥测中断或全体离线都显示灰色。' },
  { tone: 'green' as const, label: '绿色', detail: '站点内已认证节点均在线且 Runtime 稳定；Lane 状态不影响站点颜色。' },
  { tone: 'orange' as const, label: '橙色', detail: '站点存在节点状态变化，或仅部分节点在线；全体离线不使用橙色。' },
  { tone: 'red' as const, label: '红色', detail: '站点至少有一个节点拒绝配置或 Runtime 明确异常。' },
];

export const LINK_STATUS_BOUNDARIES = [
  { tone: 'gray' as const, label: '链路断开', detail: '任一端站点没有在线节点，或链路遥测已过期。' },
  { tone: 'green' as const, label: '链路正常', detail: '两端均有新鲜的双向数据面遥测，链路可正常转发。' },
  { tone: 'orange' as const, label: '链路处理中', detail: '链路正在协商、更新或性能降级；具体原因显示在链路状态中。' },
  { tone: 'red' as const, label: '链路故障', detail: '端点或配置明确失败，当前链路不可正常转发。' },
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
  if (input.applyState === 'rejected') return { code: 'policy_rejected', label: '策略应用失败', detail: runtimeUserFailureDetail(input.errorCode, counters, '节点拒绝了当前策略，但未上报错误码'), tone: 'red' };
  if (input.telemetryState === 'online' && (input.failOpenRequired || input.lifecycle === 'fail_open' || input.lifecycle === 'degraded' || input.lifecycle === 'stopped')) {
    return { code: 'runtime_fault', label: runtimeErrorStatusLabel(input.runtimeErrorCode) ?? '运行异常', detail: input.runtimeErrorDetail || runtimeUserFailureDetail(input.runtimeErrorCode, counters, `Runtime 状态：${input.lifecycle}`), tone: 'red' };
  }
  if (input.applyState === 'pending') return { code: 'policy_updating', label: '策略更新中', detail: '等待 Cloud 发布或节点确认当前策略', tone: 'orange' };
  if (input.lifecycle === 'starting' || input.lifecycle === 'unknown' || input.lifecycle === null) {
    return { code: 'starting', label: '正在启动', detail: 'Runtime 在线，但数据面尚未进入稳定运行状态', tone: 'orange' };
  }
  if (input.operationalTransition) return { code: 'starting', label: '数据面自愈中', detail: input.operationalAttention ?? 'Runtime 正在恢复数据面一致性', tone: 'orange' };
  if (input.telemetryState === 'online' && input.dataPlaneReady === false) {
    return { code: 'runtime_fault', label: '数据面未就绪', detail: input.operationalAttention ?? 'Runtime 在线，但数据面尚未达到可转发条件', tone: 'red' };
  }
  return { code: 'healthy', label: '在线', detail: '节点身份已认证，Runtime 正常上报；Lane 状态在线路中单独判定', tone: 'green' };
}

export function linkOperationalStatus(input: LinkOperationalInput): OperationalStatus<LinkOperationalCode> {
  if (input.endpointOffline) return { code: 'endpoint_offline', label: '链路断开', detail: '至少一个端点站点没有在线节点，当前没有可用链路', tone: 'gray' };
  if (input.configuredPathCount === 0) return { code: 'not_configured', label: '线路未配置', detail: '互联关系已建立，但尚未设置候选线路', tone: 'orange' };
  if (input.configurationFailed) return { code: 'configuration_failed', label: '链路故障', detail: input.failedEndpointLabels?.length ? `${input.failedEndpointLabels.join('、')}拒绝了当前互联策略` : '至少一个端点拒绝了当前互联策略', tone: 'red' };
  if (input.endpointFailed) return { code: 'endpoint_failed', label: '链路故障', detail: input.failedEndpointLabels?.length ? `${input.failedEndpointLabels.join('、')}没有可工作的节点` : '至少一端没有可工作的节点', tone: 'red' };
  if (input.policyUpdating) return { code: 'policy_updating', label: '策略更新中', detail: '互联配置正在发布或等待端点确认', tone: 'orange' };
  if (input.degradedPathLabels?.length) return { code: 'telemetry_stale', label: '链路性能降级', detail: `${input.degradedPathLabels.join('、')} 出现 Stream 背压，链路仍可达但吞吐或时延可能受影响`, tone: 'orange' };
  if (input.activeDirectionCount === 2) return { code: 'active', label: '链路正常', detail: '双向数据面已建立，链路遥测持续更新', tone: 'green' };
  if (input.activeDirectionCount === 1) return { code: 'one_way', label: '链路协商中', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 尚未建立；正在等待另一方向完成协商` : '一侧路径已建立，正在等待另一方向完成协商', tone: 'orange' };
  if (input.staleDirectionCount > 0) return { code: 'telemetry_stale', label: '链路断开', detail: input.staleDirectionLabels?.length ? `${input.staleDirectionLabels.join('、')} 的链路遥测已过期，当前无法确认可达性` : '链路遥测已过期，当前无法确认可达性', tone: 'orange' };
  return { code: 'authenticating', label: '链路协商中', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 尚未建立；正在等待两端完成认证和路径协商` : '正在等待两端完成认证和路径协商', tone: 'orange' };
}
