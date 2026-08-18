import type { ControlResource, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimeTelemetry } from './types';

export type OperationalResourceKey = 'sites' | 'nodes' | 'segments' | 'attachments' | 'prefixes' | 'peers' | 'paths' | 'egress' | 'policies' | 'dns' | 'relays';
export type OperationalResources = Record<OperationalResourceKey, ControlResource[]>;
export type ResourceLoadErrors = Partial<Record<OperationalResourceKey, string>>;

export const emptyOperationalResources: OperationalResources = {
  sites: [], nodes: [], segments: [], attachments: [], prefixes: [], peers: [], paths: [],
  egress: [], policies: [], dns: [], relays: [],
};

export type OperationalNode = {
  id: string;
  name: string;
  siteId: string;
  applyState: 'active' | 'rejected' | 'pending';
  errorCode: string | null;
  reportedAt: string | null;
  telemetryState: 'online' | 'stale' | 'unreported';
  lifecycle: RuntimeTelemetry['lifecycle'] | null;
  dataPlaneActive: boolean;
  configuredPeers: number;
  activePeers: number;
  requiredRouteOwners: number;
  readyRouteOwners: number;
  failOpenRequired: boolean;
  telemetry: RuntimeTelemetry | null;
};

export type OperationalSite = {
  id: string;
  name: string;
  kindLabel: string;
  nodes: OperationalNode[];
  nodeNames: string[];
  activeNodeCount: number;
  onlineNodeCount: number;
  dataPlaneActiveNodeCount: number;
  failOpenNodeCount: number;
  hasRejectedNode: boolean;
  routeCount: number;
  egressCount: number;
};

export type OperationalLink = {
  id: string;
  siteAId: string;
  siteBId: string;
  directionCount: number;
  kindLabel: string;
  state: 'active' | 'pending';
};

export type OperationalTopologySnapshot = {
  segment: { id: string; name: string; overlayCidr: string } | null;
  readiness: RuntimeActivationReadiness | null;
  readinessLabel: string;
  sites: OperationalSite[];
  nodes: OperationalNode[];
  links: OperationalLink[];
  activeNodeCount: number;
  onlineNodeCount: number;
  staleNodeCount: number;
  dataPlaneActiveNodeCount: number;
  failOpenNodeCount: number;
  rejectedNodeCount: number;
  pendingNodeCount: number;
  activeLinkCount: number;
  pathCount: number;
  routeCount: number;
  routeLabels: string[];
  egressCount: number;
  egressLabels: string[];
  policyRuleCount: number;
  dnsRecordCount: number;
  dnsZoneCount: number;
  telemetryCoverageCount: number;
  averageRttMs: number | null;
  averageJitterMs: number | null;
  averagePacketLossPpm: number | null;
  rxBps: number | null;
  txBps: number | null;
};

function value(item: ControlResource | undefined, key: string): string {
  return String(item?.resource.spec[key] ?? '');
}

function name(item: ControlResource | undefined): string {
  if (!item) return '未知资源';
  return String(item.resource.spec.name ?? item.resource.spec.display_name ?? item.metadata.id);
}

function cidr(input: unknown): string {
  const prefix = input as { network?: string; prefix_len?: number } | undefined;
  return prefix?.network && prefix.prefix_len ? `${prefix.network}/${prefix.prefix_len}` : '未配置地址池';
}

function readinessLabel(readiness: RuntimeActivationReadiness | null): string {
  if (!readiness) return '等待 Cloud 生成配置';
  if (readiness.ready) return '数据面已就绪';
  if (readiness.reason_codes.includes('service_not_enabled')) return '服务尚未开通';
  if (readiness.reason_codes.includes('node_offline')) return '等待节点端点';
  if (readiness.reason_codes.includes('config_pending')) return '配置发布中';
  return '等待激活';
}

export function buildOperationalTopology(
  resources: OperationalResources,
  statuses: RuntimeConfigurationStatus[],
  readinessBySegment: Record<string, RuntimeActivationReadiness>,
  selectedSegmentId: string,
  telemetry: RuntimeTelemetry[] = [],
  staleAfterSeconds = 90,
  nowMs = Date.now(),
): OperationalTopologySnapshot {
  const segmentResource = resources.segments.find((item) => item.metadata.id === selectedSegmentId);
  const segmentId = segmentResource?.metadata.id ?? '';
  const selectedAttachments = resources.attachments.filter((item) => value(item, 'segment_id') === segmentId);
  const attachedNodeIds = new Set(selectedAttachments.map((item) => value(item, 'node_id')));
  const selectedNodes = resources.nodes.filter((item) => attachedNodeIds.has(item.metadata.id));
  const statusByIdentity = new Map(statuses.map((status) => [`${status.device_id}:${status.device_key_id}`, status]));
  const telemetryByIdentity = new Map(telemetry.map((item) => [`${item.device_id}:${item.device_key_id}`, item]));
  const nodes: OperationalNode[] = selectedNodes.map((item) => {
    const identity = `${value(item, 'device_id')}:${value(item, 'device_key_id')}`;
    const status = statusByIdentity.get(identity);
    const runtime = telemetryByIdentity.get(identity) ?? null;
    const reportedMs = runtime ? Date.parse(runtime.reported_at) : Number.NaN;
    const telemetryState = !runtime || !Number.isFinite(reportedMs)
      ? 'unreported'
      : nowMs - reportedMs <= staleAfterSeconds * 1000 ? 'online' : 'stale';
    const dataPlaneActive = telemetryState === 'online'
      && runtime?.lifecycle === 'active'
      && !runtime.fail_open_required
      && runtime.ready_route_owners === runtime.required_route_owners;
    const applyState = status?.current && status.state === 'active'
      ? 'active'
      : status?.current && status.state === 'rejected' ? 'rejected' : 'pending';
    return {
      id: item.metadata.id,
      name: name(item),
      siteId: value(item, 'site_id'),
      applyState,
      errorCode: status?.error_code ?? null,
      reportedAt: status?.reported_at ?? null,
      telemetryState,
      lifecycle: runtime?.lifecycle ?? null,
      dataPlaneActive,
      configuredPeers: runtime?.configured_peers ?? 0,
      activePeers: runtime?.active_peers ?? 0,
      requiredRouteOwners: runtime?.required_route_owners ?? 0,
      readyRouteOwners: runtime?.ready_route_owners ?? 0,
      failOpenRequired: runtime?.fail_open_required ?? false,
      telemetry: runtime,
    };
  });
  const selectedPrefixes = resources.prefixes.filter((item) => value(item, 'segment_id') === segmentId);
  const selectedEgresses = resources.egress.filter((item) => selectedAttachments.some((attachment) => attachment.metadata.id === value(item, 'attachment_id')));
  const siteIds = new Set(selectedAttachments.map((item) => value(item, 'site_id')));
  const sites: OperationalSite[] = resources.sites
    .filter((item) => siteIds.has(item.metadata.id))
    .map((item) => {
      const siteNodes = nodes.filter((node) => node.siteId === item.metadata.id);
      return {
        id: item.metadata.id,
        name: name(item),
        kindLabel: value(item, 'kind') === 'PRIVATE_CLOUD' ? '私有云' : '边缘站点',
        nodes: siteNodes,
        nodeNames: siteNodes.map((node) => node.name),
        activeNodeCount: siteNodes.filter((node) => node.applyState === 'active').length,
        onlineNodeCount: siteNodes.filter((node) => node.telemetryState === 'online').length,
        dataPlaneActiveNodeCount: siteNodes.filter((node) => node.dataPlaneActive).length,
        failOpenNodeCount: siteNodes.filter((node) => node.failOpenRequired).length,
        hasRejectedNode: siteNodes.some((node) => node.applyState === 'rejected'),
        routeCount: selectedPrefixes.filter((prefix) => value(prefix, 'site_id') === item.metadata.id).length,
        egressCount: selectedEgresses.filter((egress) => value(egress, 'site_id') === item.metadata.id).length,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
  const readiness = readinessBySegment[segmentId] ?? null;
  const links: OperationalLink[] = resources.peers
    .filter((peer) => value(peer, 'segment_id') === segmentId)
    .map((peer) => {
      const paths = resources.paths.filter((path) => value(path, 'peer_id') === peer.metadata.id && value(path, 'segment_id') === segmentId);
      const kinds = new Set(paths.map((path) => value(path, 'kind')));
      return {
        id: peer.metadata.id,
        siteAId: value(peer, 'site_a_id'),
        siteBId: value(peer, 'site_b_id'),
        directionCount: Math.min(2, paths.length),
        kindLabel: kinds.has('RELAY') ? '中继' : '直连',
        state: readiness?.ready && paths.length >= 2 ? 'active' : 'pending',
      };
    });
  const routeLabels = selectedPrefixes.map((item) => cidr(item.resource.spec.prefix));
  const egressLabels = selectedEgresses.map(name);
  const selectedPolicies = resources.policies.filter((item) => value(item, 'segment_id') === segmentId);
  const selectedDns = resources.dns.filter((item) => value(item, 'segment_id') === segmentId);
  const freshTelemetry = nodes
    .filter((node) => node.telemetryState === 'online')
    .map((node) => node.telemetry)
    .filter((item): item is RuntimeTelemetry => item !== null);
  const average = (values: number[]): number | null => values.length > 0
    ? Math.round(values.reduce((sum, item) => sum + item, 0) / values.length)
    : null;
  type NumericTelemetryKey = 'rtt_ms' | 'jitter_ms' | 'packet_loss_ppm' | 'rx_bps' | 'tx_bps';
  const numeric = (key: NumericTelemetryKey): number[] => freshTelemetry
    .map((item) => item[key])
    .filter((item): item is number => typeof item === 'number');
  const rates = (key: 'rx_bps' | 'tx_bps'): number | null => {
    const values = numeric(key);
    return values.length > 0 ? values.reduce((sum, item) => sum + item, 0) : null;
  };
  return {
    segment: segmentResource ? { id: segmentId, name: name(segmentResource), overlayCidr: cidr(segmentResource.resource.spec.overlay_prefix) } : null,
    readiness,
    readinessLabel: readinessLabel(readiness),
    sites,
    nodes,
    links,
    activeNodeCount: nodes.filter((node) => node.applyState === 'active').length,
    onlineNodeCount: nodes.filter((node) => node.telemetryState === 'online').length,
    staleNodeCount: nodes.filter((node) => node.telemetryState === 'stale').length,
    dataPlaneActiveNodeCount: nodes.filter((node) => node.dataPlaneActive).length,
    failOpenNodeCount: nodes.filter((node) => node.failOpenRequired).length,
    rejectedNodeCount: nodes.filter((node) => node.applyState === 'rejected').length,
    pendingNodeCount: nodes.filter((node) => node.applyState === 'pending').length,
    activeLinkCount: links.filter((link) => link.state === 'active').length,
    pathCount: resources.paths.filter((item) => value(item, 'segment_id') === segmentId).length,
    routeCount: selectedPrefixes.length,
    routeLabels,
    egressCount: selectedEgresses.length,
    egressLabels,
    policyRuleCount: selectedPolicies.reduce((count, item) => count + (Array.isArray(item.resource.spec.rules) ? item.resource.spec.rules.length : 0), 0),
    dnsRecordCount: selectedDns.reduce((count, item) => count + (Array.isArray(item.resource.spec.records) ? item.resource.spec.records.length : 0), 0),
    dnsZoneCount: selectedDns.length,
    telemetryCoverageCount: freshTelemetry.filter((item) => [item.rtt_ms, item.jitter_ms, item.packet_loss_ppm, item.rx_bps, item.tx_bps].some((metric) => metric !== null)).length,
    averageRttMs: average(numeric('rtt_ms')),
    averageJitterMs: average(numeric('jitter_ms')),
    averagePacketLossPpm: average(numeric('packet_loss_ppm')),
    rxBps: rates('rx_bps'),
    txBps: rates('tx_bps'),
  };
}
