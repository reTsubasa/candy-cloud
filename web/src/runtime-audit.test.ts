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
});
