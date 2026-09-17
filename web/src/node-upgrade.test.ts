import { describe, expect, it } from 'vitest';
import type { NodeUpgradeJob } from './api';
import { latestNodeUpgradeJobs, nodeUpgradePresentation } from './node-upgrade';

function job(overrides: Partial<NodeUpgradeJob> = {}): NodeUpgradeJob {
  return {
    id: 'job-1',
    state: 'running',
    phase: 'installing',
    error_code: null,
    error_detail: null,
    target: {
      component: 'runtime', current_version: '0.4.0-r130', version: '0.4.0-r131',
      version_key: 'v0_4_0_r131', digest: 'a'.repeat(64),
    },
    created_at: '2026-09-17T10:00:00Z',
    updated_at: '2026-09-17T10:01:00Z',
    ...overrides,
  };
}

describe('node upgrade status', () => {
  it('selects the newest task independently for Runtime and Core', () => {
    const oldRuntime = job({ id: 'old', state: 'failed', updated_at: '2026-09-17T10:02:00Z' });
    const currentRuntime = job({ id: 'new', state: 'succeeded', phase: 'succeeded', updated_at: '2026-09-17T10:03:00Z' });
    const core = job({
      id: 'core', updated_at: '2026-09-17T10:04:00Z',
      target: { ...job().target, component: 'core' },
    });
    expect(latestNodeUpgradeJobs([oldRuntime, core, currentRuntime])).toEqual({
      runtime: currentRuntime,
      core,
    });
  });

  it('keeps exact failure phase, code, and safe detail visible', () => {
    expect(nodeUpgradePresentation(job({
      state: 'failed',
      phase: 'health_check',
      error_code: 'upgrade_health_check_failed',
      error_detail: 'service remained unhealthy after rollback',
    }))).toEqual({
      tone: 'failed',
      summary: '失败 · phase=health_check · error=upgrade_health_check_failed',
      detail: 'service remained unhealthy after rollback',
    });
  });
});
