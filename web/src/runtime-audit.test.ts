import { describe, expect, it } from 'vitest';
import { runtimeAuditEventDescription } from './runtime-audit';

describe('runtime audit event descriptions', () => {
  it('reports the translated fail-open reason and counter evidence', () => {
    const description = runtimeAuditEventDescription('RUNTIME_FAIL_OPEN_ENTERED', {
      error_code: 'all_peer_reads_failed', configured_peers: 2, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 0,
    });
    expect(description).toContain('所有 Peer 接收路径读取失败（all_peer_reads_failed）');
    expect(description).toContain('Peer 1/2，路由 0/1');
    expect(description).toContain('基础网络保持可用');
  });

  it('does not invent a cause when Runtime omitted its error code', () => {
    expect(runtimeAuditEventDescription('RUNTIME_LIFECYCLE_DEGRADED', {
      lifecycle: 'STOPPED', error_code: null, configured_peers: 0, active_peers: 0,
      required_route_owners: 0, ready_route_owners: 0,
    })).toBe('原因：Runtime 状态：STOPPED。');
  });
});
