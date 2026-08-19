import { describe, expect, it } from 'vitest';
import { activationDisplay } from './activation-status';
import type { RuntimeActivationReadiness } from './types';

function readiness(input: Partial<RuntimeActivationReadiness> = {}): RuntimeActivationReadiness {
  return {
    schema_version: 1,
    segment_id: 'segment',
    ready: false,
    candidate_count: 2,
    ready_candidate_count: 0,
    missing_transport_count: 0,
    reason_codes: [],
    ...input,
  };
}

describe('activation display', () => {
  it('distinguishes loading, failure, and an unread state', () => {
    expect(activationDisplay(null, null, true).label).toBe('读取中');
    expect(activationDisplay(null, '请求超时', false)).toEqual(expect.objectContaining({ label: '读取失败', detail: '请求超时' }));
    expect(activationDisplay(null, null, false).label).toBe('待检查');
  });

  it('maps each activation outcome to product language', () => {
    expect(activationDisplay(readiness({ ready: true }), null, false).label).toBe('已启用');
    expect(activationDisplay(readiness({ reason_codes: ['service_not_enabled'] }), null, false).label).toBe('服务未开通');
    expect(activationDisplay(readiness({ reason_codes: ['node_offline'], missing_transport_count: 2 }), null, false).detail).toContain('2 条线路');
    expect(activationDisplay(readiness({ reason_codes: ['config_pending'] }), null, false).label).toBe('配置发布中');
  });
});
