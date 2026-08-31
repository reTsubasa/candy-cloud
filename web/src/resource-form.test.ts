import { describe, expect, it, vi } from 'vitest';
import { buildResourceSpec, normalizeSpecForEditor, parseCidr, policyRulesForEditor, validateResourceEditor } from './resource-form';

describe('resource form contract mapping', () => {
  it('accepts canonical IPv4 CIDR and rejects host addresses', () => {
    expect(parseCidr('0.0.0.0/0')).toEqual({ network: '0.0.0.0', prefix_len: 0 });
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

  it('accepts localized relay regions and normalizes display text', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    const editor = {
      service_node_id: uuid, name: ' 美国搬瓦工 ', region: ' 美国 ',
      max_sessions: 10000, capacity_mbps: 1000,
    };
    expect(validateResourceEditor('RELAY', editor)).toEqual([]);
    expect(buildResourceSpec('RELAY', editor)).toEqual({
      kind: 'RELAY',
      spec: {
        service_node_id: uuid, name: '美国搬瓦工', region: '美国',
        max_sessions: 10000, max_bits_per_second: 1_000_000_000,
      },
    });
  });

  it('rejects relay regions longer than the V1 contract limit', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    expect(validateResourceEditor('RELAY', {
      service_node_id: uuid, name: 'Relay', region: '区'.repeat(81),
      max_sessions: 10000, capacity_mbps: 1000,
    })).toContain('region:length');
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

  it('stores an empty remote-egress destination as the canonical default route', () => {
    vi.stubGlobal('crypto', { randomUUID: () => '019ff9c1-ac24-7303-a6c3-905768fe5905' });
    const document = buildResourceSpec('SERVICE_POLICY', {
      segment_id: '019ff9c1-ac24-7303-a6c3-905768fe5901', generation: 2,
      rules: [{ priority: 100, source_site_ids: [], destination_cidrs: [], domains: [], traffic_classes: [], action_type: 'REMOTE_EGRESS', egress_id: '019ff9c1-ac24-7303-a6c3-905768fe5902' }],
    });
    expect(document).toMatchObject({ spec: { rules: [{ destination_prefixes: [
      { network: '0.0.0.0', prefix_len: 0 },
    ] }] } });
    vi.unstubAllGlobals();
  });

  it('keeps a default route intact from the editor to the Cloud resource', () => {
    vi.stubGlobal('crypto', { randomUUID: () => '019ff9c1-ac24-7303-a6c3-905768fe5905' });
    const document = buildResourceSpec('SERVICE_POLICY', {
      segment_id: '019ff9c1-ac24-7303-a6c3-905768fe5901', generation: 2,
      rules: [{ priority: 100, source_site_ids: [], destination_cidrs: ['0.0.0.0/0'], domains: [], traffic_classes: [], action_type: 'REMOTE_EGRESS', egress_id: '019ff9c1-ac24-7303-a6c3-905768fe5902' }],
    });
    expect(document.spec.rules).toMatchObject([{ destination_prefixes: [
      { network: '0.0.0.0', prefix_len: 0 },
    ] }]);
    expect(policyRulesForEditor(document.spec.rules)[0].destination_cidrs).toEqual(['0.0.0.0/0']);
    vi.unstubAllGlobals();
  });

  it('reports duplicate policy priorities before submission', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    expect(validateResourceEditor('SERVICE_POLICY', { segment_id: uuid, generation: 1, rules: [
      { priority: 100, destination_cidrs: [], domains: [], action_type: 'LOCAL_EGRESS' },
      { priority: 100, destination_cidrs: [], domains: [], action_type: 'LOCAL_EGRESS' },
    ] })).toContain('rules.1.priority:unique');
  });

  it('requires a transport node and rejects malformed DNS address values', () => {
    const uuid = '019ff9c1-ac24-7303-a6c3-905768fe5901';
    expect(validateResourceEditor('PATH_CANDIDATE', {
      segment_id: uuid, peer_id: uuid, source_attachment_id: uuid,
      destination_attachment_id: uuid, kind: 'DIRECT', transport_node_id: '', priority: 1,
    })).toContain('transport_node_id:required');
    expect(validateResourceEditor('DNS_INTENT', {
      segment_id: uuid, publish_scope: 'ALL', site_ids: [], zone: 'corp.test',
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
    const document = buildResourceSpec('DNS_INTENT', {
      segment_id: 'segment', publish_scope: 'SELECTED', site_ids: ['site-a', 'site-b'], zone: 'corp.test', records: [
        { name: 'gateway.corp.test', type: 'A', value: '10.0.0.10', ttl_seconds: 60, required_prefix_id: '' },
      ],
    });
    expect(document.spec.site_ids).toEqual(['site-a', 'site-b']);
    expect(document.spec).not.toHaveProperty('site_id');
    expect(document.spec).not.toHaveProperty('publish_scope');
    expect(document.spec.records).toEqual([{ name: 'gateway.corp.test', ttl_seconds: 60, data: { type: 'A', value: '10.0.0.10' }, required_prefix_id: null }]);
  });

  it('normalizes legacy DNS scope and validates selected-site publication', () => {
    const siteId = '019ff9c1-ac24-7303-a6c3-905768fe5902';
    expect(normalizeSpecForEditor({ kind: 'DNS_INTENT', spec: {
      segment_id: 'segment', site_id: siteId, zone: 'corp.test', records: [],
    } })).toMatchObject({ publish_scope: 'SELECTED', site_ids: [siteId] });
    expect(validateResourceEditor('DNS_INTENT', {
      segment_id: '019ff9c1-ac24-7303-a6c3-905768fe5901', publish_scope: 'SELECTED', site_ids: [], zone: 'corp.test', records: [],
    })).toContain('site_ids:required');
  });
});
