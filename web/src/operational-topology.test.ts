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

const threeSiteIds = {
  segment: 'segment-production',
  sites: { wrt: 'site-wrt', us: 'site-us', hk: 'site-hk' },
  nodes: { wrt: 'node-wrt', us: 'node-us', hk: 'node-hk' },
  attachments: { wrt: '4813e5d7...', us: '2647e64a...', hk: '45e68f9d...' },
  peers: { wrtHk: 'peer-wrt-hk', hkUs: 'peer-hk-us', wrtUs: 'peer-wrt-us' },
} as const;

function telemetry(
  location: keyof typeof threeSiteIds.nodes,
  peerAttachmentIds: string[],
): RuntimeTelemetry {
  const configuredPeers = peerAttachmentIds.length;
  return {
    device_id: `device-${location}`, device_key_id: `key-${location}`,
    boot_id: `boot-${location}`, sequence: 1, lifecycle: 'active',
    configured_peers: configuredPeers, active_peers: configuredPeers,
    required_route_owners: configuredPeers, ready_route_owners: configuredPeers,
    fail_open_required: false, last_error_code: null,
    rtt_ms: 30, jitter_ms: 2, packet_loss_ppm: 0,
    rx_bps: 20_000, tx_bps: 10_000, reconnects: 0, path_changes: 0,
    paths: peerAttachmentIds.map((peerAttachmentId, index) => ({
      peer_attachment_id: peerAttachmentId, candidate_id: null,
      path_kind: 'direct', transport: 'quic_udp', connection_epoch: index + 1,
      rtt_ms: 30, jitter_ms: 2, packet_loss_ppm: 0,
      rx_bps: 20_000, tx_bps: 10_000, reconnects: 0, path_changes: 0,
    })),
    local_networks: [], reported_at: '2026-08-26T05:59:50Z',
  };
}

function configurationStatus(device: string): RuntimeConfigurationStatus {
  return {
    device_id: `device-${device}`, device_key_id: `key-${device}`,
    projection_publication_id: `projection-${device}`, state: 'active',
    error_code: null, reported_at: '2026-08-26T05:59:45Z', current: true,
  };
}

function threeSiteFixture(): { resources: OperationalResources; telemetry: RuntimeTelemetry[] } {
  const { segment, sites, nodes, attachments, peers } = threeSiteIds;
  const peer = (id: string, siteAId: string, siteBId: string): ControlResource => resource(id, 'PEER', {
    segment_id: segment, site_a_id: siteAId, site_b_id: siteBId,
  });
  const candidates = (peerId: string): ControlResource[] => [1, 2].map((direction) => resource(
    `${peerId}-path-${direction}`, 'PATH_CANDIDATE',
    { segment_id: segment, peer_id: peerId, kind: 'DIRECT' },
  ));
  return {
    resources: {
      ...emptyOperationalResources,
      sites: [
        resource(sites.wrt, 'SITE', { name: '杭州', kind: 'EDGE' }),
        resource(sites.us, 'SITE', { name: '美国搬瓦工', kind: 'PRIVATE_CLOUD' }),
        resource(sites.hk, 'SITE', { name: '香港', kind: 'PRIVATE_CLOUD' }),
      ],
      nodes: [
        resource(nodes.wrt, 'NODE', { display_name: '192.168.1.1', site_id: sites.wrt, device_id: 'device-wrt', device_key_id: 'key-wrt' }),
        resource(nodes.us, 'NODE', { display_name: '104.243.28.153', site_id: sites.us, device_id: 'device-us', device_key_id: 'key-us' }),
        resource(nodes.hk, 'NODE', { display_name: '47.83.1.189', site_id: sites.hk, device_id: 'device-hk', device_key_id: 'key-hk' }),
      ],
      segments: [resource(segment, 'SEGMENT', { name: '生产网络', overlay_prefix: { network: '100.64.0.0', prefix_len: 24 } })],
      attachments: [
        resource(attachments.wrt, 'ATTACHMENT', { segment_id: segment, site_id: sites.wrt, node_id: nodes.wrt }),
        resource(attachments.us, 'ATTACHMENT', { segment_id: segment, site_id: sites.us, node_id: nodes.us }),
        resource(attachments.hk, 'ATTACHMENT', { segment_id: segment, site_id: sites.hk, node_id: nodes.hk }),
      ],
      peers: [
        peer(peers.wrtHk, sites.wrt, sites.hk),
        peer(peers.hkUs, sites.hk, sites.us),
        peer(peers.wrtUs, sites.wrt, sites.us),
      ],
      paths: [
        ...candidates(peers.wrtHk),
        ...candidates(peers.hkUs),
        ...candidates(peers.wrtUs),
      ],
    },
    telemetry: [
      telemetry('wrt', [attachments.hk]),
      telemetry('us', [attachments.hk]),
      telemetry('hk', [attachments.wrt, attachments.us]),
    ],
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
      ready_candidate_count: 2, missing_transport_count: 0, pending_apply_count: 0, failed_apply_count: 0, apply_error_codes: [], reason_codes: [],
    };
    const snapshot = buildOperationalTopology(fixture(), [status], { segment: readiness }, 'segment');
    expect(snapshot.segment?.overlayCidr).toBe('100.64.0.0/24');
    expect(snapshot.sites).toHaveLength(2);
    expect(snapshot.sites.map((site) => site.registeredNodeCount)).toEqual([1, 1]);
    expect(snapshot.activeNodeCount).toBe(1);
    expect(snapshot.pendingNodeCount).toBe(0);
    expect(snapshot.activeLinkCount).toBe(0);
    expect(snapshot.routeLabels).toEqual(['192.168.1.0/24']);
    expect(snapshot.egressLabels).toEqual(['东京出口']);
    expect(snapshot.policyRuleCount).toBe(1);
    expect(snapshot.dnsRecordCount).toBe(1);
  });

  it('does not present a configured path as active before readiness', () => {
    const snapshot = buildOperationalTopology(fixture(), [], {}, 'segment');
    expect(snapshot.links[0].state).toBe('endpoint_offline');
    expect(snapshot.links[0].status.tone).toBe('gray');
    expect(snapshot.readinessLabel).toBe('等待 Cloud 生成配置');
  });

  it('keeps an online OpenWrt node green while its Lane failure stays on the link', () => {
    const { resources, telemetry: runtimeTelemetry } = threeSiteFixture();
    const failedTelemetry = runtimeTelemetry.map((item) => item.device_id === 'device-wrt' ? {
      ...item,
      lifecycle: 'degraded' as const,
      active_peers: 0,
      ready_route_owners: 0,
      fail_open_required: true,
      last_error_code: 'all_peer_reads_failed',
      paths: [],
    } : item);
    const snapshot = buildOperationalTopology(
      resources,
      [configurationStatus('wrt'), configurationStatus('us'), configurationStatus('hk')],
      {},
      threeSiteIds.segment,
      failedTelemetry,
      90,
      Date.parse('2026-08-26T06:00:00Z'),
    );
    const wrtSite = snapshot.sites.find((site) => site.id === threeSiteIds.sites.wrt);
    const wrtNode = snapshot.nodes.find((node) => node.id === threeSiteIds.nodes.wrt);
    const wrtHkLink = snapshot.links.find((link) => link.id === threeSiteIds.peers.wrtHk);

    expect(wrtSite).toMatchObject({ registeredNodeCount: 1, onlineNodeCount: 1, status: { code: 'healthy', tone: 'green' } });
    expect(wrtNode?.status).toMatchObject({ code: 'healthy', tone: 'green' });
    expect(wrtHkLink?.status).toMatchObject({ code: 'endpoint_failed', tone: 'red' });
  });

  it.each([
    ['OpenWrt', 'node-a', 'device-a', 'key-a'],
    ['Linux', 'node-b', 'device-b', 'key-b'],
  ])('marks authenticated %s offline nodes and their sites gray', (_platform, nodeId, deviceId, deviceKeyId) => {
    const resources = fixture();
    const snapshot = buildOperationalTopology(resources, [{
      device_id: deviceId,
      device_key_id: deviceKeyId,
      projection_publication_id: 'projection',
      state: 'active',
      error_code: null,
      reported_at: '2026-08-18T00:00:00Z',
      current: true,
    }], {}, 'segment', [], 90, Date.parse('2026-08-18T10:00:00Z'));
    const node = snapshot.nodes.find((item) => item.id === nodeId);
    const site = snapshot.sites.find((item) => item.id === node?.siteId);
    expect(node?.status).toMatchObject({ tone: 'gray', label: '未上线' });
    expect(site?.status).toMatchObject({ tone: 'gray', code: 'unregistered' });
  });

  it('keeps a site gray when every authenticated node is offline, including pending nodes', () => {
    const resources = fixture();
    const snapshot = buildOperationalTopology(resources, [{
      device_id: 'device-a',
      device_key_id: 'key-a',
      projection_publication_id: 'projection',
      state: 'active',
      error_code: null,
      reported_at: '2026-08-18T00:00:00Z',
      current: false,
    }], {}, 'segment', [], 90, Date.parse('2026-08-18T10:00:00Z'));
    const site = snapshot.sites.find((item) => item.id === 'site-a');
    expect(site?.status).toMatchObject({ tone: 'gray', code: 'unregistered', label: '离线' });
  });

  it('marks a mixed online and offline site orange instead of green', () => {
    const { resources, telemetry } = threeSiteFixture();
    const extraNode = resource('node-a-offline', 'NODE', {
      display_name: '东京备用网关', site_id: threeSiteIds.sites.wrt,
      device_id: 'device-a-offline', device_key_id: 'key-a-offline',
    });
    const extraAttachment = resource('attachment-a-offline', 'ATTACHMENT', {
      segment_id: threeSiteIds.segment, site_id: threeSiteIds.sites.wrt, node_id: extraNode.metadata.id,
    });
    const snapshot = buildOperationalTopology({ ...resources, nodes: [...resources.nodes, extraNode], attachments: [...resources.attachments, extraAttachment] }, [], {}, threeSiteIds.segment, telemetry, 90, Date.parse('2026-08-26T06:00:00Z'));
    const site = snapshot.sites.find((item) => item.id === threeSiteIds.sites.wrt);
    expect(site?.status).toMatchObject({ tone: 'orange', code: 'warning', label: '部分在线' });
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
    expect(global.segment?.aggregate).toBe(true);
    const unassignedSite = resource('site-unassigned', 'SITE', { name: '北京待配置', kind: 'EDGE' });
    const withUnassigned = buildOperationalTopology({ ...fixture(), sites: [...fixture().sites, unassignedSite], nodes: [...fixture().nodes, resource('node-unassigned', 'NODE', { display_name: '待接入节点', site_id: 'site-unassigned', device_id: 'device-unassigned', device_key_id: 'key-unassigned' })] }, [], {}, '');
    expect(global.sites.map((site) => site.name)).toEqual(['东京', '上海', '深圳']);
    expect(withUnassigned.sites.map((site) => site.id)).toContain('site-unassigned');
    expect(global.routeLabels).toEqual(['192.168.1.0/24', '10.20.0.0/16']);
  });

  it('explains why an aggregate network is not ready', () => {
    const readiness: RuntimeActivationReadiness = {
      schema_version: 1, segment_id: 'segment', ready: false, candidate_count: 2,
      ready_candidate_count: 0, missing_transport_count: 0, pending_apply_count: 0, failed_apply_count: 0, apply_error_codes: [], reason_codes: ['config_pending'],
    };
    const snapshot = buildOperationalTopology(fixture(), [], { segment: readiness }, '');
    expect(snapshot.readinessLabel).toBe('0/1 个网络已就绪 · 配置发布中');
  });

  it('distinguishes fresh data-plane telemetry from stale configuration receipts', () => {
    const now = Date.parse('2026-08-18T10:00:00Z');
    const active: RuntimeTelemetry = {
      device_id: 'device-a', device_key_id: 'key-a', boot_id: 'boot-a', sequence: 120,
      lifecycle: 'active', configured_peers: 2, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 1, fail_open_required: false,
      last_error_code: null, rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 12_500,
      rx_bps: 20_000_000, tx_bps: 10_000_000, reconnects: 2, path_changes: 1,
      paths: [{ peer_attachment_id: 'attachment-b', candidate_id: null, path_kind: 'direct', transport: 'quic_udp', connection_epoch: 3, rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 12_500, rx_bps: 20_000_000, tx_bps: 10_000_000, reconnects: 2, path_changes: 1 }],
      local_networks: [{ network_id: '30bfd718e3f4b79faf151e52915f15928bf9c63b57a7963b807c8c1f7f502ae5', interface_name: 'br-lan', cidr: '192.168.10.0/24', address: '192.168.10.1', kind: 'direct_ipv4' }],
      reported_at: '2026-08-18T09:59:40Z',
    };
    const stale = { ...active, device_id: 'device-b', device_key_id: 'key-b', reported_at: '2026-08-18T09:57:00Z' };
    const snapshot = buildOperationalTopology(fixture(), [configurationStatus('a'), configurationStatus('b')], {}, 'segment', [active, stale], 90, now);
    expect(snapshot.onlineNodeCount).toBe(1);
    expect(snapshot.staleNodeCount).toBe(1);
    expect(snapshot.dataPlaneActiveNodeCount).toBe(1);
    expect(snapshot.telemetryCoverageCount).toBe(1);
    expect(snapshot.activeLinkCount).toBe(0);
    expect(snapshot.links[0].activeDirectionCount).toBe(1);
    expect(snapshot.links[0]).toMatchObject({ siteAName: '上海', siteBName: '东京', state: 'endpoint_offline' });
    expect(snapshot.links[0].status.detail).toContain('线路随站点状态置灰');
    expect(snapshot.links[0].activePathCount).toBe(1);
    expect(snapshot.links[0].activePaths[0].sourceSiteId).toBe('site-a');
    expect(snapshot.links[0].activePaths[0].destinationSiteId).toBe('site-b');
    expect(snapshot.links[0].activePaths[0].sampledAt).toBe(active.reported_at);
    expect(snapshot.averageRttMs).toBe(42);
    expect(snapshot.averagePacketLossPpm).toBe(12_500);
    expect(snapshot.rxBps).toBe(20_000_000);
  });

  it('propagates an offline site to its control and data-plane link state', () => {
    const now = Date.parse('2026-08-18T10:00:00Z');
    const online = fixture();
    const snapshot = buildOperationalTopology(online, [configurationStatus('a'), configurationStatus('b')], {}, 'segment', [], 90, now);
    expect(snapshot.sites.every((site) => site.status.tone === 'gray')).toBe(true);
    expect(snapshot.links[0].status).toMatchObject({ code: 'endpoint_offline', tone: 'gray' });
  });

  it('marks a link active only with fresh telemetry in both endpoint directions', () => {
    const now = Date.parse('2026-08-18T10:00:00Z');
    const path = {
      candidate_id: null, path_kind: 'direct' as const, transport: 'quic_udp', connection_epoch: 3,
      rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 0, rx_bps: 20_000, tx_bps: 10_000,
      reconnects: 0, path_changes: 0,
    };
    const base: RuntimeTelemetry = {
      device_id: 'device-a', device_key_id: 'key-a', boot_id: 'boot-a', sequence: 1,
      lifecycle: 'active', configured_peers: 1, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 1, fail_open_required: false,
      last_error_code: null, rtt_ms: 42, jitter_ms: 7, packet_loss_ppm: 0,
      rx_bps: 20_000, tx_bps: 10_000, reconnects: 0, path_changes: 0,
      paths: [{ ...path, peer_attachment_id: 'attachment-b' }], local_networks: [],
      reported_at: '2026-08-18T09:59:50Z',
    };
    const reverse: RuntimeTelemetry = {
      ...base, device_id: 'device-b', device_key_id: 'key-b', boot_id: 'boot-b',
      paths: [{ ...path, peer_attachment_id: 'attachment-a' }],
    };
    const snapshot = buildOperationalTopology(fixture(), [configurationStatus('a'), configurationStatus('b')], {}, 'segment', [base, reverse], 90, now);
    expect(snapshot.activeLinkCount).toBe(1);
    expect(snapshot.links[0].activeDirectionCount).toBe(2);
    expect(snapshot.links[0].activePaths.map((item) => [item.sourceSiteId, item.destinationSiteId])).toEqual([
      ['site-a', 'site-b'], ['site-b', 'site-a'],
    ]);
  });

  it('does not attach telemetry from a third site to an unrelated peer edge', () => {
    const thirdSite = resource('site-c', 'SITE', { name: '纽约', kind: 'PRIVATE_CLOUD' });
    const thirdNode = resource('node-c', 'NODE', { display_name: '纽约节点', site_id: 'site-c', device_id: 'device-c', device_key_id: 'key-c' });
    const thirdAttachment = resource('attachment-c', 'ATTACHMENT', { segment_id: 'segment', site_id: 'site-c', node_id: 'node-c' });
    const telemetry: RuntimeTelemetry = {
      device_id: 'device-c', device_key_id: 'key-c', boot_id: 'boot-c', sequence: 1,
      lifecycle: 'active', configured_peers: 1, active_peers: 1,
      required_route_owners: 1, ready_route_owners: 1, fail_open_required: false,
      last_error_code: null, rtt_ms: 30, jitter_ms: 2, packet_loss_ppm: 0,
      rx_bps: 100, tx_bps: 100, reconnects: 0, path_changes: 0,
      paths: [{ peer_attachment_id: 'attachment-b', candidate_id: null, path_kind: 'direct', transport: 'quic_udp', connection_epoch: 1, rtt_ms: 30, jitter_ms: 2, packet_loss_ppm: 0, rx_bps: 100, tx_bps: 100, reconnects: 0, path_changes: 0 }],
      local_networks: [], reported_at: '2026-08-18T09:59:50Z',
    };
    const resources = fixture();
    const snapshot = buildOperationalTopology({
      ...resources,
      sites: [...resources.sites, thirdSite],
      nodes: [...resources.nodes, thirdNode],
      attachments: [...resources.attachments, thirdAttachment],
    }, [configurationStatus('a'), configurationStatus('b')], {}, 'segment', [telemetry], 90, Date.parse('2026-08-18T10:00:00Z'));
    expect(snapshot.links[0].activePathCount).toBe(0);
    expect(snapshot.links[0].state).toBe('endpoint_offline');
  });

  it('binds the three-site field telemetry to the correct peer endpoints', () => {
    const { resources, telemetry: runtimeTelemetry } = threeSiteFixture();
    const snapshot = buildOperationalTopology(
      resources, [configurationStatus('wrt'), configurationStatus('us'), configurationStatus('hk')], {}, threeSiteIds.segment, runtimeTelemetry, 90,
      Date.parse('2026-08-26T06:00:00Z'),
    );
    const linksById = Object.fromEntries(snapshot.links.map((link) => [link.id, link]));
    const siteNames = Object.fromEntries(snapshot.sites.map((site) => [site.id, site.name]));
    const namedPaths = (linkId: string): string[][] => linksById[linkId].activePaths.map((path) => [
      siteNames[path.sourceSiteId], siteNames[path.destinationSiteId], path.peer_attachment_id,
    ]);

    expect(snapshot.activeLinkCount).toBe(2);
    expect(linksById[threeSiteIds.peers.wrtHk]).toMatchObject({ state: 'active', activeDirectionCount: 2 });
    expect(namedPaths(threeSiteIds.peers.wrtHk)).toEqual([
      ['杭州', '香港', threeSiteIds.attachments.hk],
      ['香港', '杭州', threeSiteIds.attachments.wrt],
    ]);
    expect(linksById[threeSiteIds.peers.hkUs]).toMatchObject({ state: 'active', activeDirectionCount: 2 });
    expect(namedPaths(threeSiteIds.peers.hkUs)).toEqual([
      ['美国搬瓦工', '香港', threeSiteIds.attachments.hk],
      ['香港', '美国搬瓦工', threeSiteIds.attachments.us],
    ]);
    expect(linksById[threeSiteIds.peers.wrtUs]).toMatchObject({
      state: 'authenticating', activeDirectionCount: 0, activePathCount: 0,
    });
    expect(namedPaths(threeSiteIds.peers.wrtUs)).toEqual([]);
  });
});
