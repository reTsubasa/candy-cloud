import { describe, expect, it, vi } from 'vitest';
import { buildResourceSpec, normalizeSpecForEditor, parseCidr, validateResourceEditor } from './resource-form';

describe('resource form contract mapping', () => {
  it('accepts canonical IPv4 CIDR and rejects host addresses', () => {
    expect(parseCidr('10.20.0.0/16')).toEqual({ network: '10.20.0.0', prefix_len: 16 });
    expect(parseCidr('10.20.1.1/16')).toBeNull();
    expect(parseCidr('300.20.0.0/16')).toBeNull();
  });

  it('converts human capacity units without losing the wire contract', () => {
    const editor = normalizeSpecForEditor({ kind: 'EGRESS', spec: { name: 'Shanghai', site_id: 'site', attachment_id: 'attachment', max_sessions: 1000, max_bits_per_second: 250_000_000 } });
    expect(editor.capacity_mbps).toBe(250);
    expect(buildResourceSpec('EGRESS', { ...editor, capacity_mbps: 500 })).toEqual({
      kind: 'EGRESS',
      spec: { name: 'Shanghai', site_id: 'site', attachment_id: 'attachment', max_sessions: 1000, max_bits_per_second: 500_000_000 },
    });
  });

  it('serializes structured policy rules and remote egress action', () => {
    vi.stubGlobal('crypto', { randomUUID: () => '019ff9c1-ac24-7303-a6c3-905768fe5905' });
    expect(buildResourceSpec('SERVICE_POLICY', {
      segment_id: '019ff9c1-ac24-7303-a6c3-905768fe5901', generation: 2,
      rules: [{ priority: 100, source_site_ids: [], destination_cidrs: ['10.20.0.0/16'], domains: ['app.corp.test'], traffic_classes: ['interactive'], action_type: 'REMOTE_EGRESS', egress_id: '019ff9c1-ac24-7303-a6c3-905768fe5902' }],
    }).spec.rules).toEqual([{
      id: '019ff9c1-ac24-7303-a6c3-905768fe5905', priority: 100, source_site_ids: [],
      destination_prefixes: [{ network: '10.20.0.0', prefix_len: 16 }], domains: ['app.corp.test'], traffic_classes: ['interactive'],
      action: { type: 'REMOTE_EGRESS', egress_id: '019ff9c1-ac24-7303-a6c3-905768fe5902' },
    }]);
    vi.unstubAllGlobals();
  });

  it('reports duplicate policy priorities before submission', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    expect(validateResourceEditor('SERVICE_POLICY', { segment_id: uuid, generation: 1, rules: [
      { priority: 100, destination_cidrs: [], domains: [], action_type: 'LOCAL_EGRESS' },
      { priority: 100, destination_cidrs: [], domains: [], action_type: 'LOCAL_EGRESS' },
    ] })).toContain('rules.1.priority:unique');
  });

  it('rejects malformed path endpoints and DNS address values', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    expect(validateResourceEditor('PATH_CANDIDATE', {
      segment_id: uuid, peer_id: uuid, source_attachment_id: uuid,
      destination_attachment_id: uuid, kind: 'DIRECT', endpoint: '300.1.1.1:70000', priority: 1,
    })).toContain('endpoint:endpoint');
    expect(validateResourceEditor('DNS_INTENT', {
      segment_id: uuid, site_id: uuid, zone: 'corp.test',
      records: [{ name: 'host.corp.test', type: 'AAAA', value: '2001:::10', ttl_seconds: 60 }],
    })).toContain('records.0.value:ipv6');
  });

  it('validates network attachment addresses and epochs', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    const attachment = {
      segment_id: uuid, site_id: uuid, node_id: uuid, overlay_router_ipv4: '100.64.0.2', epoch_floor: 1,
    };
    expect(validateResourceEditor('ATTACHMENT', attachment)).toEqual([]);
    expect(buildResourceSpec('ATTACHMENT', { ...attachment, epoch_floor: '2' })).toEqual({
      kind: 'ATTACHMENT', spec: { ...attachment, epoch_floor: 2 },
    });
    expect(validateResourceEditor('ATTACHMENT', {
      segment_id: uuid, site_id: uuid, node_id: uuid, overlay_router_ipv4: '127.0.0.1', epoch_floor: 0,
    })).toEqual(expect.arrayContaining(['overlay_router_ipv4:ipv4', 'epoch_floor:positive']));
  });

  it('serializes DNS rows into tagged record data', () => {
    expect(buildResourceSpec('DNS_INTENT', {
      segment_id: 'segment', site_id: 'site', zone: 'corp.test', records: [
        { name: 'gateway.corp.test', type: 'A', value: '10.0.0.10', ttl_seconds: 60, required_prefix_id: '' },
      ],
    }).spec.records).toEqual([{ name: 'gateway.corp.test', ttl_seconds: 60, data: { type: 'A', value: '10.0.0.10' }, required_prefix_id: null }]);
  });
});
