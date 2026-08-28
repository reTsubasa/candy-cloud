import { describe, expect, it } from 'vitest';
import { linkOperationalStatus, nodeOperationalStatus, type NodeOperationalInput } from './operational-status';

const node = (overrides: Partial<NodeOperationalInput> = {}): NodeOperationalInput => ({
  registered: true,
  attached: true,
  applyState: 'active',
  errorCode: null,
  telemetryState: 'online',
  lifecycle: 'active',
  configuredPeers: 2,
  activePeers: 2,
  requiredRouteOwners: 2,
  readyRouteOwners: 2,
  failOpenRequired: false,
  runtimeErrorCode: null,
  ...overrides,
});

describe('operational status boundaries', () => {
  it('keeps registration green without claiming SD-WAN is active', () => {
    expect(nodeOperationalStatus(node({ attached: false, applyState: 'pending', telemetryState: 'unreported' }))).toMatchObject({
      code: 'registered', label: '已注册', tone: 'green',
    });
  });

  it('uses yellow for transitions and red only for explicit faults', () => {
    expect(nodeOperationalStatus(node({ applyState: 'pending' })).code).toBe('policy_updating');
    expect(nodeOperationalStatus(node({ activePeers: 1 })).code).toBe('peer_negotiating');
    expect(nodeOperationalStatus(node({ requiredRouteOwners: 2, readyRouteOwners: 1 }))).toMatchObject({ code: 'route_incomplete', label: '路由未就绪' });
    expect(nodeOperationalStatus(node({ telemetryState: 'stale' })).tone).toBe('orange');
    expect(nodeOperationalStatus(node({ applyState: 'rejected', errorCode: 'invalid_policy' }))).toMatchObject({ code: 'policy_rejected', tone: 'red' });
    expect(nodeOperationalStatus(node({ failOpenRequired: true }))).toMatchObject({ code: 'fail_open', tone: 'red' });
  });

  it('includes the translated cause and counter evidence in a node fault', () => {
    expect(nodeOperationalStatus(node({
      failOpenRequired: true,
      runtimeErrorCode: 'all_peer_reads_failed',
      configuredPeers: 2,
      activePeers: 1,
      requiredRouteOwners: 1,
      readyRouteOwners: 0,
    }))).toMatchObject({
      label: '接收通道全部中断',
      detail: '原因：所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量；Peer 连接 1/2，路由就绪 0/1；系统已撤销 SD-WAN 路由，未匹配流量继续按节点本地网络策略转发',
    });
  });

  it('turns a link green only after fresh bidirectional authentication', () => {
    const configured = { configuredPathCount: 2, activeDirectionCount: 0, staleDirectionCount: 0, policyUpdating: false, configurationFailed: false, endpointFailed: false };
    expect(linkOperationalStatus(configured)).toMatchObject({ code: 'authenticating', label: '路径未建立', tone: 'orange' });
    expect(linkOperationalStatus({ ...configured, activeDirectionCount: 1 })).toMatchObject({ code: 'one_way', tone: 'orange' });
    expect(linkOperationalStatus({ ...configured, activeDirectionCount: 2 })).toMatchObject({ code: 'active', tone: 'green' });
    expect(linkOperationalStatus({ ...configured, activeDirectionCount: 2, policyUpdating: true })).toMatchObject({ code: 'policy_updating', tone: 'orange' });
    expect(linkOperationalStatus({ ...configured, configurationFailed: true })).toMatchObject({ code: 'configuration_failed', tone: 'red' });
    expect(linkOperationalStatus({
      ...configured,
      activeDirectionCount: 1,
      missingDirectionLabels: ['香港 -> 美国'],
    }).detail).toBe('香港 -> 美国 未建立；检查发起端策略、认证日志和公网 UDP 端点');
  });

  it.each([
    ['unregistered', { registered: false }, 'gray'],
    ['registered', { attached: false }, 'green'],
    ['policy_updating', { applyState: 'pending' }, 'orange'],
    ['waiting_telemetry', { telemetryState: 'unreported' }, 'orange'],
    ['telemetry_stale', { telemetryState: 'stale' }, 'orange'],
    ['starting', { lifecycle: 'starting' }, 'orange'],
    ['peer_negotiating', { activePeers: 1 }, 'orange'],
    ['route_incomplete', { readyRouteOwners: 1 }, 'orange'],
    ['healthy', {}, 'green'],
    ['policy_rejected', { applyState: 'rejected' }, 'red'],
    ['fail_open', { failOpenRequired: true }, 'red'],
    ['runtime_fault', { lifecycle: 'degraded' }, 'red'],
  ] as const)('classifies node state %s', (code, overrides, tone) => {
    expect(nodeOperationalStatus(node(overrides))).toMatchObject({ code, tone });
  });

  it.each([
    ['not_configured', { configuredPathCount: 0 }, 'orange'],
    ['policy_updating', { policyUpdating: true }, 'orange'],
    ['authenticating', {}, 'orange'],
    ['one_way', { activeDirectionCount: 1 }, 'orange'],
    ['telemetry_stale', { staleDirectionCount: 1 }, 'orange'],
    ['active', { activeDirectionCount: 2 }, 'green'],
    ['configuration_failed', { configurationFailed: true }, 'red'],
    ['endpoint_failed', { endpointFailed: true }, 'red'],
  ] as const)('classifies link state %s', (code, overrides, tone) => {
    expect(linkOperationalStatus({
      configuredPathCount: 2,
      activeDirectionCount: 0,
      staleDirectionCount: 0,
      policyUpdating: false,
      configurationFailed: false,
      endpointFailed: false,
      ...overrides,
    })).toMatchObject({ code, tone });
  });
});
