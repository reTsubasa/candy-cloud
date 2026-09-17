import type { NodeUpgradeJob } from './api';

export type UpgradeComponent = 'runtime' | 'core';

export type NodeUpgradePresentation = {
  tone: 'pending' | 'running' | 'succeeded' | 'failed' | 'expired';
  summary: string;
  detail: string | null;
};

function timestamp(job: NodeUpgradeJob): number {
  const parsed = Date.parse(job.updated_at || job.created_at);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function latestNodeUpgradeJobs(
  jobs: NodeUpgradeJob[],
): Partial<Record<UpgradeComponent, NodeUpgradeJob>> {
  const latest: Partial<Record<UpgradeComponent, NodeUpgradeJob>> = {};
  for (const job of jobs) {
    if (job.target.component !== 'runtime' && job.target.component !== 'core') continue;
    const component = job.target.component;
    if (!latest[component] || timestamp(job) > timestamp(latest[component])) {
      latest[component] = job;
    }
  }
  return latest;
}

export function nodeUpgradePresentation(job: NodeUpgradeJob | undefined): NodeUpgradePresentation | null {
  if (!job) return null;
  const phase = job.phase || job.state;
  if (job.state === 'failed') {
    return {
      tone: 'failed',
      summary: `失败 · phase=${phase} · error=${job.error_code ?? 'missing_error_code'}`,
      detail: job.error_detail || null,
    };
  }
  const labels: Record<string, string> = {
    pending: '等待执行',
    running: '执行中',
    succeeded: '已完成',
    expired: '已过期',
  };
  const tone = job.state === 'pending' || job.state === 'running' || job.state === 'succeeded' || job.state === 'expired'
    ? job.state
    : 'expired';
  return { tone, summary: `${labels[job.state] ?? job.state} · phase=${phase}`, detail: null };
}
