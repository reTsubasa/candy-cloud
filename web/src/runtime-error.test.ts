import { describe, expect, it } from 'vitest';
import { runtimeCounterEvidence, runtimeErrorReason, runtimeErrorStatusLabel, runtimeFailureDetail, runtimeUserFailureDetail } from './runtime-error';

describe('runtime error display', () => {
  it('translates bounded Runtime error codes without hiding the original code', () => {
    expect(runtimeErrorReason('all_peer_reads_failed')).toBe('所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量（all_peer_reads_failed）');
    expect(runtimeErrorStatusLabel('all_peer_reads_failed')).toBe('接收通道全部中断');
    expect(runtimeErrorReason('future_error')).toBe('Runtime 错误码：future_error');
    expect(runtimeErrorReason(null)).toBeNull();
  });

  it('shows peer and route evidence when the counters are meaningful', () => {
    expect(runtimeCounterEvidence({ configuredPeers: 2, activePeers: 1, requiredRouteOwners: 1, readyRouteOwners: 0 }))
      .toBe('Peer 连接 1/2，路由就绪 0/1');
    expect(runtimeCounterEvidence({ configuredPeers: 0, activePeers: 0, requiredRouteOwners: 0, readyRouteOwners: 0 }))
      .toBeNull();
  });

  it('states explicitly when Runtime did not report a bounded error code', () => {
    expect(runtimeFailureDetail(null, { configuredPeers: 1, activePeers: 0 }, 'Runtime 未上报明确错误码'))
      .toBe('原因：Runtime 未上报明确错误码；Peer 连接 0/1');
  });

  it('keeps raw error codes out of the overview explanation', () => {
    expect(runtimeUserFailureDetail('all_peer_reads_failed', {
      configuredPeers: 1, activePeers: 0, requiredRouteOwners: 1, readyRouteOwners: 0,
    }, '未知错误')).toBe('原因：所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量；Peer 连接 0/1，路由就绪 0/1');
  });
});
