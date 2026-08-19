import { describe, expect, it } from 'vitest';
import type { ControlResource, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimeTelemetry } from './types';
import { buildOperationalTopology, emptyOperationalResources, type OperationalResources } from './operational-topology';

function resource(id: string, kind: string, spec: Record<string, unknown>): ControlResource {
  return { metadata: { schema_version: 1, id, tenant_id: 'tenant', revision: 1, state: 'ACTIVE' }, resource: { kind, spec } };
}

function fixture(): OperationalResources {
  return {
    ...emptyOperationalResources,
    sites: [resource('site-a', 'SITE', { name: '上海', kind: 'EDGE' }), resource('site-b', 'SITE', { name: '东京', kind: 'PRIVATE_CLOUD' })],
    nodes: [
      resource('node-a', 'NODE', { display_name: 'OpenWrt', site_id: 'site-a', device_id: 'device-a', device_key_id: 'key-a' }),
      resource('node-b', 'NODE', { display_name: 'Linux', site_id: 'site-b', device_id: 'device-b', device_key_id: 'key-b' }),
    ],
    segments: [resource('segment', 'SEGMENT', { name: '生产网络', overlay_prefix: { network: '100.64.0.0', prefix_len: 24 } })],
    attachments: [
      resource('attachment-a', 'ATTACHMENT', { segment_id: 'segment', site_id: 'site-a', node_id: 'node-a' }),
      resource('attachment-b', 'ATTACHMENT', { segment_id: 'segment', site_id: 'site-b', node_id: 'node-b' }),
    ],
    prefixes: [resource('prefix', 'PREFIX', { segment_id: 'segment', site_id: 'site-a', prefix: { network: '192.168.1.0', prefix_len: 24 } })],
    peers: [resource('peer', 'PEER', { segment_id: 'segment', site_a_id: 'site-a', site_b_id: 'site-b' })],
    paths: [
      resource('path-a', 'PATH_CANDIDATE', { segment_id: 'segment', peer_id: 'peer', kind: 'DIRECT' }),
      resource('path-b', 'PATH_CANDIDATE', { segment_id: 'segment', peer_id: 'peer', kind: 'DIRECT' }),
    ],
    egress: [resource('egress', 'EGRESS', { name: '东京出口', site_id: 'site-b', attachment_id: 'attachment-b' })],
    policies: [resource('policy', 'SERVICE_POLICY', { segment_id: 'segment', rules: [{ id: 'rule' }] })],
    dns: [resource('dns', 'DNS_INTENT', { segment_id: 'segment', zone: 'internal.test', records: [{ name: 'app' }] })],
  };
}

describe('operational topology', () => {
  it('joins resources and runtime receipts without inventing telemetry', () => {
    const status: RuntimeConfigurationStatus = {
      device_id: 'device-a', device_key_id: 'key-a', projection_publication_id: 'projection',
      state: 'active', error_code: null, reported_at: '2026-08-18T00:00:00Z', current: true,
    };
    const readiness: RuntimeActivationReadiness = {
      schema_version: 1, segment_id: 'segment', ready: true, candidate_count: 2,
      ready_candidate_count: 2, missing_transport_count: 0, reason_codes: [],
    };
    const snapshot = buildOperationalTopology(fixture(), [status], { segment: readiness }, 'segment');
    expect(snapshot.segment?.overlayCidr).toBe('100.64.0.0/24');
    expect(snapshot.sites).toHaveLength(2);
    expect(snapshot.activeNodeCount).toBe(1);
    expect(snapshot.pendingNodeCount).toBe(1);
    expect(snapshot.activeLinkCount).toBe(0);
    expect(snapshot.routeLabels).toEqual(['192.168.1.0/24']);
    expect(snapshot.egressLabels).toEqual(['东京出口']);
    expect(snapshot.policyRuleCount).toBe(1);
    expect(snapshot.dnsRecordCount).toBe(1);
  });

  it('does not present a configured path as active before readiness', () => {
    const snapshot = buildOperationalTopology(fixture(), [], {}, 'segment');
    expect(snapshot.links[0].state).toBe('pending');
    expect(snapshot.readinessLabel).toBe('等待 Cloud 生成配置');
  });

  it('keeps the default topology global instead of selecting one segment', () => {
    const secondSegment = resource('segment-2', 'SEGMENT', { name: '办公网络', overlay_prefix: { network: '100.65.0.0', prefix_len: 24 } });
    const secondSite = resource('site-c', 'SITE', { name: '深圳', kind: 'EDGE' });
    const secondNode = resource('node-c', 'NODE', { display_name: '深圳网关', site_id: 'site-c', device_id: 'device-c', device_key_id: 'key-c' });
    const global = buildOperationalTopology({
      ...fixture(),
      segments: [...fixture().segments, secondSegment],
      sites: [...fixture().sites, secondSite],
      nodes: [...fixture().nodes, secondNode],
      attachments: [...fixture().attachments, resource('attachment-c', 'ATTACHMENT', { segment_id: 'segment-2', site_id: 'site-c', node_id: 'node-c' })],
      prefixes: [...fixture().prefixes, resource('prefix-c', 'PREFIX', { segment_id: 'segment-2', site_id: 'site-c', prefix: { network: '10.20.0.0', prefix_len: 16 } })],
    }, [], {}, '');
    expect(global.segment?.name).toBe('全部网络');
    const unassignedSite = resource('site-unassigned', 'SITE', { name: '北京待配置', kind: 'EDGE' });
    const withUnassigned = buildOperationalTopology({ ...fixture(), sites: [...fixture().sites, unassignedSite], nodes: [...fixture().nodes, resource('node-unassigned', 'NODE', { display_name: '待接入节点', site_id: 'site-unassigned', device_id: 'device-unassigned', device_key_id: 'key-unassigned' })] }, [], {}, '');
    expect(global.sites.map((site) => site.id)).toEqual(['site-a', 'site-b', 'site-c']);
    expect(withUnassigned.sites.map((site) => site.id)).toContain('site-unassigned');
    expect(global.routeLabels).toEqual(['192.168.1.0/24', '10.20.0.0/16']);
  });

  it('distinguishes fresh data-plane telemetry from stale configuration receipts', () => {
    const now = Date.parse('2026-08-18T10:00:00Z');
    const active: RuntimeTelemetry = {
      device_id: 'device-a', device_key_id: 'key-a', boot_id: 'boot-a', sequence: 120,
      lifecycle: 'active', configured_peers: 1, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 1, fail_open_required: false,
      last_error_code: null, rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 12_500,
      rx_bps: 20_000_000, tx_bps: 10_000_000, reconnects: 2, path_changes: 1,
      paths: [{ peer_attachment_id: 'attachment-b', candidate_id: null, path_kind: 'direct', transport: 'quic_udp', connection_epoch: 3, rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 12_500, rx_bps: 20_000_000, tx_bps: 10_000_000, reconnects: 2, path_changes: 1 }],
      reported_at: '2026-08-18T09:59:40Z',
    };
    const stale = { ...active, device_id: 'device-b', device_key_id: 'key-b', reported_at: '2026-08-18T09:57:00Z' };
    const snapshot = buildOperationalTopology(fixture(), [], {}, 'segment', [active, stale], 90, now);
    expect(snapshot.onlineNodeCount).toBe(1);
    expect(snapshot.staleNodeCount).toBe(1);
    expect(snapshot.dataPlaneActiveNodeCount).toBe(1);
    expect(snapshot.telemetryCoverageCount).toBe(1);
    expect(snapshot.activeLinkCount).toBe(1);
    expect(snapshot.links[0].activePathCount).toBe(1);
    expect(snapshot.averageRttMs).toBe(42);
    expect(snapshot.averagePacketLossPpm).toBe(12_500);
    expect(snapshot.rxBps).toBe(20_000_000);
  });
});
