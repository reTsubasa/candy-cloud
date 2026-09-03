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
  it('keeps an authenticated but offline node gray, green only when online', () => {
    expect(nodeOperationalStatus(node({ attached: false, applyState: 'pending', telemetryState: 'unreported' }))).toMatchObject({
      code: 'registered', label: '未接入', tone: 'gray',
    });
  });

  it('uses orange only for transitions, gray for offline, and red for explicit faults', () => {
    expect(nodeOperationalStatus(node({ applyState: 'pending' })).code).toBe('policy_updating');
    expect(nodeOperationalStatus(node({ applyState: 'pending', telemetryState: 'unreported' })).tone).toBe('gray');
    expect(nodeOperationalStatus(node({ telemetryState: 'stale' })).tone).toBe('gray');
    expect(nodeOperationalStatus(node({ applyState: 'rejected', errorCode: 'invalid_policy' }))).toMatchObject({ code: 'policy_rejected', tone: 'red' });
    expect(nodeOperationalStatus(node({ lifecycle: 'degraded' }))).toMatchObject({ code: 'runtime_fault', tone: 'red' });
  });

  it('keeps Lane, Peer and route failures out of node identity status', () => {
    expect(nodeOperationalStatus(node({
      failOpenRequired: true,
      runtimeErrorCode: 'all_peer_reads_failed',
      configuredPeers: 2,
      activePeers: 1,
      requiredRouteOwners: 1,
      readyRouteOwners: 0,
    }))).toMatchObject({
      code: 'healthy',
      label: '在线',
      tone: 'green',
    });
    expect(nodeOperationalStatus(node({ telemetryState: 'unreported', lifecycle: null }))).toMatchObject({ code: 'registered', label: '未上线', tone: 'gray' });
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
    ['registered', { attached: false }, 'gray'],
    ['policy_updating', { applyState: 'pending' }, 'orange'],
    ['registered', { telemetryState: 'unreported' }, 'gray'],
    ['telemetry_stale', { telemetryState: 'stale' }, 'gray'],
    ['starting', { lifecycle: 'starting' }, 'orange'],
    ['healthy', {}, 'green'],
    ['policy_rejected', { applyState: 'rejected' }, 'red'],
    ['healthy', { failOpenRequired: true, lifecycle: 'degraded' }, 'green'],
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
