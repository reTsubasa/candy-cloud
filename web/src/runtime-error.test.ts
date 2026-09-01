import { describe, expect, it } from 'vitest';
import { RUNTIME_ERROR_CODES, runtimeCounterEvidence, runtimeErrorDescriptor, runtimeErrorReason, runtimeErrorStatusLabel, runtimeFailureDetail, runtimeUserFailureDetail } from './runtime-error';

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

  it('covers every error emitted by Core, the SD-WAN agent, Cloud sync and netd', () => {
    const emittedCodes = [
      'activation_invalid', 'activation_receipt_failed', 'all_peer_readers_stopped',
      'all_peer_reads_failed', 'all_peer_writes_failed', 'candidate_inspection_failed',
      'peer_negotiation_failed',
      'cloud_sync_failed', 'core_compatibility_verification_failed', 'core_discovery_failed',
      'core_exit', 'core_exit_during_hot_reload', 'core_hot_reload_failed',
      'core_process_inspection_failed', 'core_readiness_failed', 'core_readiness_lost',
      'core_readiness_timeout', 'core_route_readiness_lost', 'core_runtime_failed',
      'core_start_failed', 'core_status_inspection_failed', 'core_status_invalid',
      'core_status_unavailable', 'core_traffic_blackhole', 'declaration_invalid',
      'grant_authorization_denied', 'grant_binding_mismatch', 'grant_core_verification_failed',
      'grant_expired', 'grant_not_yet_valid', 'grant_resolution_failed',
      'grant_response_mismatch', 'grant_service_unavailable', 'grant_state_invalid',
      'hot_transition_failed', 'instance_id_invalid', 'invalid_generation', 'invalid_lease',
      'invalid_readiness_timeout', 'lease_clock_failed', 'local_activation_failed',
      'local_publish_failed', 'netd_commit_failed', 'netd_lease_failed',
      'netd_prepare_failed', 'netd_reconfigure_failed', 'netd_reconfigure_invalid_transition',
      'netd_reconfigure_ipc_failed', 'netd_reconfigure_owner_conflict',
      'netd_reconfigure_platform_failed', 'netd_reconfigure_system_failed',
      'netd_reconfigure_unauthorized', 'peer_datagram_read_failed',
      'peer_datagram_write_failed', 'proxy_fallback_failed', 'public_endpoint_required',
      'readiness_token_failed', 'rollback_failed', 'route_has_no_active_peer',
      'route_owner_failed', 'route_peer_missing', 'runtime_activation_unavailable',
      'runtime_agent_exit', 'signal_handler_failed', 'status_cleanup_failed',
      'tun_read_failed', 'tun_write_failed',
    ];
    expect(emittedCodes.filter((code) => !runtimeErrorDescriptor(code))).toEqual([]);
    expect(RUNTIME_ERROR_CODES).toEqual(expect.arrayContaining(emittedCodes));
    for (const code of emittedCodes) {
      const descriptor = runtimeErrorDescriptor(code);
      expect(descriptor?.reason.length, code).toBeGreaterThan(10);
      expect(descriptor?.statusLabel.length, code).toBeGreaterThan(2);
    }
  });
});
