import { describe, expect, it } from 'vitest';
import type { ControlResource, RuntimeActivationReadiness } from '../types';
import {
  activationMessage,
  matchingPrefix,
  matchingSegmentPrefix,
  nextOverlayAddress,
  pathDirection,
  samePair,
} from '../quick-setup-orchestration';

function resource(id: string, kind: string, spec: Record<string, unknown>): ControlResource {
  return {
    metadata: { schema_version: 1, id, tenant_id: 'tenant', revision: 1, state: 'ACTIVE' },
    resource: { kind, spec },
  };
}

const selection = {
  siteA: 'site-a',
  siteB: 'site-b',
  nodeA: 'node-a',
  nodeB: 'node-b',
  segment: 'segment',
  attachmentA: 'attachment-a',
  attachmentB: 'attachment-b',
  peer: 'peer',
};

describe('quick setup orchestration helpers', () => {
  it('reuses a peer regardless of endpoint order', () => {
    const peer = resource('peer', 'PEER', {
      segment_id: 'segment', site_a_id: 'site-b', site_b_id: 'site-a',
    });
    expect(samePair(peer, selection)).toBe(true);
  });

  it('matches only the requested path direction', () => {
    const path = resource('path', 'PATH_CANDIDATE', {
      segment_id: 'segment', peer_id: 'peer',
      source_attachment_id: 'attachment-a', destination_attachment_id: 'attachment-b',
    });
    expect(pathDirection(path, 'attachment-a', 'attachment-b', selection)).toBe(true);
    expect(pathDirection(path, 'attachment-b', 'attachment-a', selection)).toBe(false);
  });

  it('skips occupied overlay addresses deterministically', () => {
    const segment = resource('segment', 'SEGMENT', {
      overlay_prefix: { network: '100.64.0.0', prefix_len: 24 },
    });
    const attachments = [resource('attachment', 'ATTACHMENT', { overlay_router_ipv4: '100.64.0.2' })];
    expect(nextOverlayAddress(segment, attachments, 2)).toBe('100.64.0.3');
  });

  it('finds an existing published prefix without creating a duplicate', () => {
    const prefix = resource('prefix', 'PREFIX', {
      site_id: 'site-a', segment_id: 'segment', prefix: { network: '192.168.1.0', prefix_len: 24 },
    });
    expect(matchingPrefix([prefix], 'site-a', 'segment', '192.168.1.0/24')).toBe(prefix);
    expect(matchingPrefix([prefix], 'site-b', 'segment', '192.168.1.0/24')).toBeUndefined();
  });

  it('finds a segment prefix owned by the wrong site so quick setup can reassign it', () => {
    const prefix = resource('prefix', 'PREFIX', {
      site_id: 'site-hong-kong', segment_id: 'segment', prefix: { network: '172.17.0.0', prefix_len: 16 },
    });
    expect(matchingPrefix([prefix], 'site-united-states', 'segment', '172.17.0.0/16')).toBeUndefined();
    expect(matchingSegmentPrefix([prefix], 'segment', '172.17.0.0/16')).toBe(prefix);
    expect(matchingSegmentPrefix([prefix], 'other-segment', '172.17.0.0/16')).toBeUndefined();
  });

  it('turns activation blockers into actionable product language', () => {
    const readiness: RuntimeActivationReadiness = {
      schema_version: 1,
      segment_id: 'segment',
      ready: false,
      candidate_count: 2,
      ready_candidate_count: 0,
      missing_transport_count: 2,
      pending_apply_count: 0,
      failed_apply_count: 0,
      apply_error_codes: [],
      reason_codes: ['node_offline', 'service_not_enabled'],
    };
    expect(activationMessage(readiness)).toContain('SD-WAN 服务尚未开通');
    expect(activationMessage(readiness)).toContain('2 条线路等待公网节点发布 UDP 端点');
  });
});
