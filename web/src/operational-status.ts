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
  | 'waiting_telemetry'
  | 'telemetry_stale'
  | 'starting'
  | 'peer_negotiating'
  | 'route_incomplete'
  | 'healthy'
  | 'policy_rejected'
  | 'fail_open'
  | 'runtime_fault';

export type LinkOperationalCode =
  | 'not_configured'
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
  applyState: 'active' | 'rejected' | 'pending';
  errorCode: string | null;
  telemetryState: 'online' | 'stale' | 'unreported';
  lifecycle: RuntimeTelemetry['lifecycle'] | null;
  configuredPeers: number;
  activePeers: number;
  requiredRouteOwners: number;
  readyRouteOwners: number;
  failOpenRequired: boolean;
  runtimeErrorCode: string | null;
};

export type LinkOperationalInput = {
  configuredPathCount: number;
  activeDirectionCount: number;
  staleDirectionCount: number;
  policyUpdating: boolean;
  configurationFailed: boolean;
  endpointFailed: boolean;
  missingDirectionLabels?: string[];
  staleDirectionLabels?: string[];
  failedEndpointLabels?: string[];
};

export const NODE_STATUS_BOUNDARIES = [
  { tone: 'green' as const, label: '绿色', detail: '节点已完成注册；接入网络后，还需策略生效且数据面健康。' },
  { tone: 'orange' as const, label: '黄色', detail: '策略更新、等待上报、Peer 协商或遥测中断，尚不能判定为故障。' },
  { tone: 'red' as const, label: '红色', detail: '策略被拒绝、SD-WAN 已自动降级，或 Runtime 明确处于异常/停止状态。' },
];

export const LINK_STATUS_BOUNDARIES = [
  { tone: 'green' as const, label: '绿色', detail: '两端均有新鲜的已协商认证路径遥测，双向数据面成立。' },
  { tone: 'orange' as const, label: '黄色', detail: '仅完成配置、正在更新/认证、只有单向成立，或链路遥测已过期。' },
  { tone: 'red' as const, label: '红色', detail: '配置应用失败，或至少一端没有可工作的节点。' },
];

export function nodeOperationalStatus(input: NodeOperationalInput): OperationalStatus<NodeOperationalCode> {
  if (!input.registered) return { code: 'unregistered', label: '未注册', detail: 'Cloud 中没有有效的节点身份', tone: 'gray' };
  const counters = {
    configuredPeers: input.configuredPeers,
    activePeers: input.activePeers,
    requiredRouteOwners: input.requiredRouteOwners,
    readyRouteOwners: input.readyRouteOwners,
  };
  if (input.applyState === 'rejected') return { code: 'policy_rejected', label: '策略应用失败', detail: runtimeUserFailureDetail(input.errorCode, counters, '节点拒绝了当前策略，但未上报错误码'), tone: 'red' };
  if (input.failOpenRequired) return {
    code: 'fail_open',
    label: runtimeErrorStatusLabel(input.runtimeErrorCode) ?? 'SD-WAN 已自动降级',
    detail: `${runtimeUserFailureDetail(input.runtimeErrorCode, counters, 'Runtime 未上报明确错误码')}；系统已撤销故障 SD-WAN 路由，并保持 Candy Proxy 或节点本地网络降级转发`,
    tone: 'red',
  };
  if (input.telemetryState === 'online' && (input.lifecycle === 'degraded' || input.lifecycle === 'stopped')) {
    return { code: 'runtime_fault', label: runtimeErrorStatusLabel(input.runtimeErrorCode) ?? '运行异常', detail: runtimeUserFailureDetail(input.runtimeErrorCode, counters, `Runtime 状态：${input.lifecycle}`), tone: 'red' };
  }
  if (!input.attached) return { code: 'registered', label: '已注册', detail: '节点身份已签发，尚未接入 SD-WAN 网络', tone: 'green' };
  if (input.applyState === 'pending') return { code: 'policy_updating', label: '策略更新中', detail: '等待 Cloud 发布或节点确认当前策略', tone: 'orange' };
  if (input.telemetryState === 'stale') return { code: 'telemetry_stale', label: '状态中断', detail: '超过遥测新鲜度窗口没有收到节点上报', tone: 'orange' };
  if (input.telemetryState === 'unreported') return { code: 'waiting_telemetry', label: '等待上报', detail: '节点已注册并收到策略，等待 Runtime 首次上报', tone: 'orange' };
  if (input.lifecycle === 'starting' || input.lifecycle === 'unknown' || input.lifecycle === null) {
    return { code: 'starting', label: '正在启动', detail: 'Runtime 在线，但数据面尚未进入稳定运行状态', tone: 'orange' };
  }
  const peersReady = input.activePeers === input.configuredPeers;
  const routesReady = input.readyRouteOwners === input.requiredRouteOwners;
  if (peersReady && !routesReady) {
    return {
      code: 'route_incomplete',
      label: '路由未就绪',
      detail: `已有 Peer 正常，但仅 ${input.readyRouteOwners}/${input.requiredRouteOwners} 个路由节点可达`,
      tone: 'orange',
    };
  }
  if (!peersReady || !routesReady) {
    return {
      code: 'peer_negotiating',
      label: 'Peer 协商中',
      detail: `Peer ${input.activePeers}/${input.configuredPeers}，路由 ${input.readyRouteOwners}/${input.requiredRouteOwners}`,
      tone: 'orange',
    };
  }
  return { code: 'healthy', label: '运行正常', detail: '策略已生效，Peer 与路由状态完整', tone: 'green' };
}

export function linkOperationalStatus(input: LinkOperationalInput): OperationalStatus<LinkOperationalCode> {
  if (input.configuredPathCount === 0) return { code: 'not_configured', label: '线路未配置', detail: '互联关系已建立，但尚未设置候选线路', tone: 'orange' };
  if (input.configurationFailed) return { code: 'configuration_failed', label: '配置失败', detail: input.failedEndpointLabels?.length ? `${input.failedEndpointLabels.join('、')}拒绝了当前互联策略` : '至少一个端点拒绝了当前互联策略', tone: 'red' };
  if (input.endpointFailed) return { code: 'endpoint_failed', label: '端点故障', detail: input.failedEndpointLabels?.length ? `${input.failedEndpointLabels.join('、')}没有可工作的节点` : '至少一端没有可工作的节点', tone: 'red' };
  if (input.policyUpdating) return { code: 'policy_updating', label: '策略更新中', detail: '互联配置正在发布或等待端点确认', tone: 'orange' };
  if (input.activeDirectionCount === 2) return { code: 'active', label: '双向已认证', detail: '两端协商认证完成，双向路径遥测新鲜', tone: 'green' };
  if (input.activeDirectionCount === 1) return { code: 'one_way', label: '单向路径异常', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 未建立；检查发起端策略、认证日志和公网 UDP 端点` : '只有一个方向完成路径认证，检查另一端策略、认证日志和公网 UDP 端点', tone: 'orange' };
  if (input.staleDirectionCount > 0) return { code: 'telemetry_stale', label: '链路状态过期', detail: input.staleDirectionLabels?.length ? `${input.staleDirectionLabels.join('、')} 的路径遥测已超过新鲜度窗口` : '曾收到路径状态，但已超过遥测新鲜度窗口', tone: 'orange' };
  return { code: 'authenticating', label: '路径未建立', detail: input.missingDirectionLabels?.length ? `${input.missingDirectionLabels.join('、')} 均未上报路径；检查发起端策略、认证日志和公网 UDP 端点` : '线路已配置但没有路径遥测；检查发起端策略、认证日志和公网 UDP 端点', tone: 'orange' };
}
