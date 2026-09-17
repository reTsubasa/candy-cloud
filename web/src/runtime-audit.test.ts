import { describe, expect, it } from 'vitest';
import { runtimeAuditEventDescription } from './runtime-audit';

describe('runtime audit event descriptions', () => {
  it('reports the translated fail-open reason and counter evidence', () => {
    const description = runtimeAuditEventDescription('RUNTIME_FAIL_OPEN_ENTERED', {
      error_code: 'all_peer_reads_failed', configured_peers: 2, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 0,
    });
    expect(description).toContain('所有已配置 Peer 的接收通道均已失败，节点无法接收任何远端流量（all_peer_reads_failed）');
    expect(description).toContain('Peer 连接 1/2，路由就绪 0/1');
    expect(description).toContain('系统已撤销 SD-WAN 路由');
    expect(description).toContain('未匹配流量继续按节点本地网络策略转发');
  });

  it('does not invent a cause when Runtime omitted its error code', () => {
    expect(runtimeAuditEventDescription('RUNTIME_LIFECYCLE_DEGRADED', {
      lifecycle: 'STOPPED', error_code: null, configured_peers: 0, active_peers: 0,
      required_route_owners: 0, ready_route_owners: 0,
    })).toBe('原因：Runtime 状态：STOPPED。');
    expect(runtimeAuditEventDescription('RUNTIME_FAIL_OPEN_ENTERED', {
      error_code: null, configured_peers: 0, active_peers: 0,
      required_route_owners: 0, ready_route_owners: 0,
    })).toContain('旧版 Runtime 在撤销路由前未持久化原始故障码');
  });

  it('distinguishes an authorization binding mismatch from a generic rejection', () => {
    expect(runtimeAuditEventDescription('RUNTIME_CONFIGURATION_REJECTED', {
      error_code: 'grant_binding_mismatch',
    })).toBe('原因：节点授权与当前节点、出口或策略代次不匹配（grant_binding_mismatch）；当前配置未生效。');
  });

  it('includes the bounded node-side negotiation detail', () => {
    const description = runtimeAuditEventDescription('RUNTIME_LIFECYCLE_DEGRADED', {
      error_code: 'peer_negotiation_failed',
      error_detail: 'peer abc candidate def negotiation failed: connection refused',
    });
    expect(description).toContain('节点无法完成该 Peer 的认证、隧道建立或路径协商');
    expect(description).toContain('现场详情：peer abc candidate def negotiation failed: connection refused');
  });

  it('preserves route drift and reconciliation evidence in audit descriptions', () => {
    expect(runtimeAuditEventDescription('RUNTIME_ROUTE_DRIFT_DETECTED', {
      expected_routes: 3,
      observed_routes: 4,
      orphaned_routes: 1,
      reconcile_attempts: 7,
      reconcile_successes: 6,
      error_code: 'route_snapshot_mismatch',
      active_issues: [{ prefix: '10.0.0.0/24', table_id: 20475, reason: 'stale_failed_prefix_throw' }],
    })).toBe('声明 3 条，内核实测 4 条，孤儿路由 1 条；累计自愈 6/7 次成功；首个异常 10.0.0.0/24（表 20475）：故障前缀的 throw 路由未恢复；原因：节点内核中的 Candy 路由与当前签名声明不一致，可能存在缺失、属性不匹配或未释放的孤儿路由（route_snapshot_mismatch）。');

    expect(runtimeAuditEventDescription('RUNTIME_ROUTE_RECONCILIATION_RECOVERED', {
      reconcile_attempts: 8,
      reconcile_successes: 7,
      last_recovery_duration_ms: 34,
      last_recovered_issues: [{ prefix: '10.0.0.0/24', table_id: 20475, reason: 'stale_failed_prefix_throw' }],
    })).toBe('内核路由已与声明快照重新一致，本次恢复耗时 34 ms；累计自愈 7/8 次成功；已处理：首个异常 10.0.0.0/24（表 20475）：故障前缀的 throw 路由未恢复。');
  });

  it('distinguishes a negotiated tunnel from successful packet delivery', () => {
    expect(runtimeAuditEventDescription('RUNTIME_PACKET_PROBE_FAILED', {
      probe_targets: 2,
      probe_successes: 1,
    })).toBe('真实数据包探测失败：1/2 个目标通过。链路不会仅凭协商成功被标记为健康。');
    expect(runtimeAuditEventDescription('RUNTIME_PACKET_PROBE_RECOVERED', {
      probe_targets: 2,
      probe_successes: 2,
      probe_rtt_ms: 9,
    })).toBe('真实数据包探测恢复：2/2 个目标通过，往返时延 9 ms。');
  });
});
