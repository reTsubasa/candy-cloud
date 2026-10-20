import { describe, expect, it } from 'vitest';
import { LINK_STATUS_BOUNDARIES, SITE_STATUS_BOUNDARIES, linkOperationalStatus, nodeOperationalStatus, type NodeOperationalInput } from './operational-status';

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
  it('uses user-facing status names in the topology legend', () => {
    expect(SITE_STATUS_BOUNDARIES.map((item) => item.label)).toEqual(['未上线', '在线', '处理中', '异常']);
    expect(LINK_STATUS_BOUNDARIES.map((item) => item.label)).toEqual(['链路断开', '链路协商中', '链路正常', '链路性能降级', '链路故障']);
  });

  it('keeps an authenticated but offline node gray, green only when online', () => {
    expect(nodeOperationalStatus(node({ attached: false, applyState: 'pending', telemetryState: 'unreported' }))).toMatchObject({
      code: 'registered', label: '未接入', tone: 'gray',
    });
  });

  it('keeps policy rollout state out of Runtime health', () => {
    expect(nodeOperationalStatus(node({ applyState: 'pending' })).code).toBe('healthy');
    expect(nodeOperationalStatus(node({ applyState: 'pending', telemetryState: 'unreported' })).tone).toBe('gray');
    expect(nodeOperationalStatus(node({ telemetryState: 'stale' })).tone).toBe('gray');
    expect(nodeOperationalStatus(node({ applyState: 'rejected', errorCode: 'invalid_policy' }))).toMatchObject({ code: 'healthy', tone: 'green' });
    expect(nodeOperationalStatus(node({ lifecycle: 'degraded' }))).toMatchObject({ code: 'runtime_fault', tone: 'red' });
  });

  it.each(['stale', 'unreported'] as const)('keeps rejected %s nodes gray', (telemetryState) => {
    expect(nodeOperationalStatus(node({
      telemetryState, applyState: 'rejected', errorCode: 'invalid_policy', lifecycle: 'degraded',
    })).tone).toBe('gray');
  });

  it('shows fail-open as a Runtime fault even while telemetry remains fresh', () => {
    expect(nodeOperationalStatus(node({
      failOpenRequired: true,
      runtimeErrorCode: 'core_runtime_failed',
      runtimeErrorDetail: 'netd recovery failed',
      configuredPeers: 2,
      activePeers: 1,
      requiredRouteOwners: 1,
      readyRouteOwners: 0,
    }))).toMatchObject({
      code: 'runtime_fault',
      tone: 'red',
      detail: 'netd recovery failed',
    });
    expect(nodeOperationalStatus(node({ telemetryState: 'unreported', lifecycle: null }))).toMatchObject({ code: 'registered', label: '未上线', tone: 'gray' });
  });

  it('keeps Runtime startup and recovery transitions orange', () => {
    expect(nodeOperationalStatus(node({ lifecycle: 'starting', dataPlaneReady: false }))).toMatchObject({ code: 'starting', tone: 'orange' });
    expect(nodeOperationalStatus(node({ applyState: 'pending', lifecycle: 'active', dataPlaneReady: false }))).toMatchObject({ code: 'healthy', tone: 'green' });
    expect(nodeOperationalStatus(node({ lifecycle: 'active', dataPlaneReady: false, operationalAttention: 'route_snapshot_mismatch' }))).toMatchObject({ code: 'healthy', tone: 'green' });
    expect(nodeOperationalStatus(node({ lifecycle: 'active', dataPlaneReady: false, operationalTransition: true, operationalAttention: '数据面自愈中' }))).toMatchObject({ code: 'starting', tone: 'orange', detail: '数据面自愈中' });
  });

  it('turns a link green only after fresh bidirectional authentication', () => {
    const configured = { configuredPathCount: 2, activeDirectionCount: 0, staleDirectionCount: 0, endpointFailed: false };
    expect(linkOperationalStatus(configured)).toMatchObject({ code: 'authenticating', label: '链路协商中', tone: 'orange' });
    expect(linkOperationalStatus({ ...configured, activeDirectionCount: 1 })).toMatchObject({ code: 'one_way', tone: 'orange' });
    expect(linkOperationalStatus({ ...configured, activeDirectionCount: 2 })).toMatchObject({ code: 'active', label: '链路正常', tone: 'green' });
    expect(linkOperationalStatus({
      ...configured,
      activeDirectionCount: 1,
      missingDirectionLabels: ['香港 -> 美国'],
    }).detail).toBe('香港 -> 美国 尚未建立；正在等待另一方向完成协商');
    expect(linkOperationalStatus({ ...configured, endpointOffline: true })).toMatchObject({ code: 'endpoint_offline', tone: 'gray' });
  });

  it.each([
    ['unregistered', { registered: false }, 'gray'],
    ['registered', { attached: false }, 'gray'],
    ['healthy', { applyState: 'pending' }, 'green'],
    ['registered', { telemetryState: 'unreported' }, 'gray'],
    ['telemetry_stale', { telemetryState: 'stale' }, 'gray'],
    ['starting', { lifecycle: 'starting' }, 'orange'],
    ['healthy', {}, 'green'],
    ['healthy', { applyState: 'rejected' }, 'green'],
    ['runtime_fault', { failOpenRequired: true, lifecycle: 'degraded' }, 'red'],
    ['runtime_fault', { lifecycle: 'degraded' }, 'red'],
  ] as const)('classifies node state %s', (code, overrides, tone) => {
    expect(nodeOperationalStatus(node(overrides))).toMatchObject({ code, tone });
  });

  it.each([
    ['not_configured', { configuredPathCount: 0 }, 'orange'],
    ['endpoint_offline', { endpointOffline: true }, 'gray'],
    ['authenticating', {}, 'orange'],
    ['one_way', { activeDirectionCount: 1 }, 'orange'],
    ['telemetry_stale', { staleDirectionCount: 1 }, 'orange'],
    ['active', { activeDirectionCount: 2 }, 'green'],
    ['endpoint_failed', { endpointFailed: true }, 'red'],
    ['telemetry_stale', { activeDirectionCount: 2, degradedPathLabels: ['杭州 -> 美国'] }, 'orange'],
  ] as const)('classifies link state %s', (code, overrides, tone) => {
    expect(linkOperationalStatus({
      configuredPathCount: 2,
      activeDirectionCount: 0,
      staleDirectionCount: 0,
      endpointFailed: false,
      ...overrides,
    })).toMatchObject({ code, tone });
  });

  it('lets endpoint offline override an unconfigured or failed line', () => {
    expect(linkOperationalStatus({ configuredPathCount: 0, activeDirectionCount: 0, staleDirectionCount: 0, endpointFailed: true, endpointOffline: true })).toMatchObject({ code: 'endpoint_offline', tone: 'gray' });
  });
});
