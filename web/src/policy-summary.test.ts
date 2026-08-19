import { describe, expect, it } from 'vitest';
import type { ControlResource } from './types';
import { compactPolicyValues, summarizePolicy, type PolicyReferences } from './policy-summary';

const references: PolicyReferences = {
  segments: { 'segment-id': '办公网络' },
  sites: { 'site-hz': '杭州办公室', 'site-hk': '香港节点' },
  egresses: { 'egress-hk': '香港互联网出口' },
};

function policy(spec: Record<string, unknown>): ControlResource {
  return {
    metadata: { schema_version: 1, id: 'policy-id', tenant_id: 'tenant-id', revision: 1, state: 'ACTIVE' },
    resource: { kind: 'SERVICE_POLICY', spec },
  };
}

describe('policy summary', () => {
  it('resolves the network, sites and canonical remote egress action', () => {
    const summary = summarizePolicy(policy({ segment_id: 'segment-id', rules: [{
      id: 'remote-rule', priority: 200, source_site_ids: ['site-hz'],
      destination_prefixes: [{ network: '0.0.0.0', prefix_len: 1 }],
      domains: ['video.example.com'], traffic_classes: ['realtime'],
      action: { type: 'REMOTE_EGRESS', egress_id: 'egress-hk' },
    }] }), references);

    expect(summary.segmentName).toBe('办公网络');
    expect(summary.rules[0]).toEqual({
      id: 'remote-rule', priority: 200, sources: ['杭州办公室'],
      conditions: ['0.0.0.0/1', 'video.example.com', '实时音视频'],
      action: '香港互联网出口', remote: true,
    });
  });

  it('makes empty source and match conditions explicit for a local action', () => {
    const summary = summarizePolicy(policy({ segment_id: 'segment-id', rules: [{
      priority: 100, source_site_ids: [], destination_cidrs: [], domains: [], traffic_classes: [],
      action_type: 'LOCAL_EGRESS',
    }] }), references);

    expect(summary.rules[0]).toMatchObject({ sources: ['全部站点'], conditions: ['全部流量'], action: '本站出口', remote: false });
  });

  it('sorts rules by ascending priority', () => {
    const summary = summarizePolicy(policy({ segment_id: 'segment-id', rules: [
      { id: 'later', priority: 300, action: { type: 'LOCAL_EGRESS' } },
      { id: 'first', priority: 10, action: { type: 'LOCAL_EGRESS' } },
    ] }), references);

    expect(summary.rules.map((rule) => rule.id)).toEqual(['first', 'later']);
  });

  it('never exposes unresolved resource identifiers', () => {
    const summary = summarizePolicy(policy({ segment_id: 'missing-segment', rules: [{
      priority: 100, source_site_ids: ['missing-site'],
      action: { type: 'REMOTE_EGRESS', egress_id: 'missing-egress' },
    }] }), references);

    expect(summary.segmentName).toBe('未知网络');
    expect(summary.rules[0]).toMatchObject({ sources: ['未知站点'], action: '未知出口' });
    expect(JSON.stringify(summary)).not.toContain('missing-');
  });

  it('describes a zero-rule policy as the default local behavior', () => {
    expect(summarizePolicy(policy({ segment_id: 'segment-id', rules: [] }), references)).toEqual({
      segmentName: '办公网络', rules: [], defaultAction: '全部流量保持本站出口',
    });
  });

  it('compacts long match lists without hiding their total size', () => {
    expect(compactPolicyValues(['杭州', '香港', '美国'])).toBe('杭州 · 香港 等 3 项');
  });
});
