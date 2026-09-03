import type { ControlResource, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimePathTelemetry, RuntimeTelemetry } from './types';
import {
  linkOperationalStatus,
  nodeOperationalStatus,
  type LinkOperationalCode,
  type NodeOperationalCode,
  type OperationalStatus,
} from './operational-status';

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
  registered: boolean;
  applyState: 'active' | 'rejected' | 'pending' | 'unknown';
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
  status: OperationalStatus<NodeOperationalCode>;
};

export type OperationalSite = {
  id: string;
  name: string;
  kindLabel: string;
  nodes: OperationalNode[];
  nodeNames: string[];
  registeredNodeCount: number;
  activeNodeCount: number;
  onlineNodeCount: number;
  dataPlaneActiveNodeCount: number;
  failOpenNodeCount: number;
  hasRejectedNode: boolean;
  routeCount: number;
  egressCount: number;
  status: OperationalStatus<'empty' | 'unregistered' | 'healthy' | 'warning' | 'fault'>;
};

export type OperationalPathTelemetry = RuntimePathTelemetry & {
  sourceSiteId: string;
  destinationSiteId: string;
  sourceNodeName: string;
  sampledAt: string;
};

export type OperationalLink = {
  id: string;
  siteAId: string;
  siteBId: string;
  siteAName: string;
  siteBName: string;
  directionCount: number;
  kindLabel: string;
  state: LinkOperationalCode;
  status: OperationalStatus<LinkOperationalCode>;
  activeDirectionCount: number;
  staleDirectionCount: number;
  activePathCount: number;
  activePaths: OperationalPathTelemetry[];
};

export type OperationalTopologySnapshot = {
  segment: { id: string; name: string; overlayCidr: string; aggregate: boolean } | null;
  readiness: RuntimeActivationReadiness | null;
  readinessLabel: string;
  sites: OperationalSite[];
  nodes: OperationalNode[];
  links: OperationalLink[];
  activeNodeCount: number;
  registeredNodeCount: number;
  healthyNodeCount: number;
  warningNodeCount: number;
  errorNodeCount: number;
  onlineNodeCount: number;
  staleNodeCount: number;
  dataPlaneActiveNodeCount: number;
  failOpenNodeCount: number;
  rejectedNodeCount: number;
  pendingNodeCount: number;
  activeLinkCount: number;
  warningLinkCount: number;
  failedLinkCount: number;
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
  if (readiness.reason_codes.includes('node_apply_failed')) return '节点应用失败';
  if (readiness.reason_codes.includes('activation_blocked')) return '发布已阻断';
  if (readiness.reason_codes.includes('node_offline')) return '等待节点端点';
  if (readiness.reason_codes.includes('config_pending')) return '配置发布中';
  if (readiness.reason_codes.includes('activation_preparing')) return '全网准备中';
  if (readiness.reason_codes.includes('activation_committing')) return '统一提交中';
  if (readiness.reason_codes.includes('node_apply_pending')) return '等待节点应用';
  return '等待激活';
}

function siteOperationalStatus(nodes: OperationalNode[]): OperationalSite['status'] {
  if (nodes.length === 0) return { code: 'empty', label: '暂无节点', detail: '站点尚未配置节点', tone: 'gray' };
  const fault = nodes.find((node) => node.status.tone === 'red');
  if (fault) return { code: 'fault', label: '节点故障', detail: fault.status.detail, tone: 'red' };

  // A site is gray when no node is currently online. Registration or a pending
  // configuration does not make an offline site operationally orange.
  const onlineNodes = nodes.filter((node) => node.telemetryState === 'online');
  if (onlineNodes.length === 0) return { code: 'unregistered', label: '离线', detail: '站点当前没有在线节点', tone: 'gray' };

  const transition = nodes.find((node) => node.status.tone === 'orange');
  if (transition) return { code: 'warning', label: '状态变化', detail: transition.status.detail, tone: 'orange' };
  if (onlineNodes.length !== nodes.length) {
    return { code: 'warning', label: '部分在线', detail: `${onlineNodes.length}/${nodes.length} 个节点在线，其余节点当前离线`, tone: 'orange' };
  }
  return { code: 'healthy', label: '节点在线', detail: '站点内已认证节点均在线且 Runtime 稳定', tone: 'green' };
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
  const segmentMatches = (item: ControlResource): boolean => !selectedSegmentId || value(item, 'segment_id') === selectedSegmentId;
  const selectedAttachments = resources.attachments.filter(segmentMatches);
  const attachedNodeIds = new Set(selectedAttachments.map((item) => value(item, 'node_id')));
  const selectedNodes = selectedSegmentId
    ? resources.nodes.filter((item) => attachedNodeIds.has(item.metadata.id))
    : resources.nodes;
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
    const applyState = !status
      ? 'unknown'
      : status.current && status.state === 'active'
      ? 'active'
      : status?.current && status.state === 'rejected' ? 'rejected' : 'pending';
    const registered = item.metadata.state === 'ACTIVE';
    const operationalStatus = nodeOperationalStatus({
      registered,
      attached: attachedNodeIds.has(item.metadata.id),
      applyState,
      errorCode: status?.error_code ?? null,
      telemetryState,
      lifecycle: runtime?.lifecycle ?? null,
      configuredPeers: runtime?.configured_peers ?? 0,
      activePeers: runtime?.active_peers ?? 0,
      requiredRouteOwners: runtime?.required_route_owners ?? 0,
      readyRouteOwners: runtime?.ready_route_owners ?? 0,
      failOpenRequired: runtime?.fail_open_required ?? false,
      runtimeErrorCode: runtime?.last_error_code ?? null,
      runtimeErrorDetail: runtime?.last_error_detail ?? null,
    });
    const dataPlaneActive = registered
      && applyState === 'active'
      && telemetryState === 'online'
      && runtime?.lifecycle === 'active'
      && !runtime.fail_open_required
      && runtime.required_route_owners > 0
      && runtime.ready_route_owners === runtime.required_route_owners;
    return {
      id: item.metadata.id,
      name: name(item),
      siteId: value(item, 'site_id'),
      registered,
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
      status: operationalStatus,
    };
  });
  const selectedPrefixes = resources.prefixes.filter(segmentMatches);
  const selectedEgresses = resources.egress.filter((item) => selectedAttachments.some((attachment) => attachment.metadata.id === value(item, 'attachment_id')));
  const siteIds = selectedSegmentId
    ? new Set(selectedAttachments.map((item) => value(item, 'site_id')))
    : new Set(resources.sites.map((item) => item.metadata.id));
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
        registeredNodeCount: siteNodes.filter((node) => node.registered).length,
        activeNodeCount: siteNodes.filter((node) => node.applyState === 'active').length,
        onlineNodeCount: siteNodes.filter((node) => node.telemetryState === 'online').length,
        dataPlaneActiveNodeCount: siteNodes.filter((node) => node.dataPlaneActive).length,
        failOpenNodeCount: siteNodes.filter((node) => node.failOpenRequired).length,
        hasRejectedNode: siteNodes.some((node) => node.applyState === 'rejected'),
        routeCount: selectedPrefixes.filter((prefix) => value(prefix, 'site_id') === item.metadata.id).length,
        egressCount: selectedEgresses.filter((egress) => value(egress, 'site_id') === item.metadata.id).length,
        status: siteOperationalStatus(siteNodes),
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
  const readiness = selectedSegmentId
    ? readinessBySegment[segmentId] ?? null
    : resources.segments.length > 0 && resources.segments.every((segment) => readinessBySegment[segment.metadata.id])
      ? resources.segments.reduce<RuntimeActivationReadiness>((summary, segment, index) => {
        const item = readinessBySegment[segment.metadata.id];
        if (index === 0) return { ...item, segment_id: '' };
        return {
          ...summary,
          ready: summary.ready && item.ready,
          candidate_count: summary.candidate_count + item.candidate_count,
          ready_candidate_count: summary.ready_candidate_count + item.ready_candidate_count,
          missing_transport_count: summary.missing_transport_count + item.missing_transport_count,
          pending_apply_count: summary.pending_apply_count + item.pending_apply_count,
          failed_apply_count: summary.failed_apply_count + item.failed_apply_count,
          apply_error_codes: [...new Set([...summary.apply_error_codes, ...item.apply_error_codes])],
          reason_codes: [...new Set([...summary.reason_codes, ...item.reason_codes])],
        };
      }, readinessBySegment[resources.segments[0].metadata.id])
      : null;
  const aggregateReadinessLabel = !selectedSegmentId && resources.segments.length > 0
    ? readiness ? (readiness.ready ? '全部网络已就绪' : `${resources.segments.filter((segment) => readinessBySegment[segment.metadata.id]?.ready).length}/${resources.segments.length} 个网络已就绪 · ${readinessLabel(readiness)}`) : `${resources.segments.length} 个网络分段 · 全局视图`
    : readinessLabel(readiness);
  const siteNameById = new Map(sites.map((site) => [site.id, site.name]));
  const links: OperationalLink[] = resources.peers
    .filter(segmentMatches)
    .map((peer) => {
      const paths = resources.paths.filter((path) => value(path, 'peer_id') === peer.metadata.id && segmentMatches(path));
      const kinds = new Set(paths.map((path) => value(path, 'kind')));
      const siteAId = value(peer, 'site_a_id');
      const siteBId = value(peer, 'site_b_id');
      const siteAName = siteNameById.get(siteAId) ?? '端点 A';
      const siteBName = siteNameById.get(siteBId) ?? '端点 B';
      const attachmentIdsBySite = new Map([
        [siteAId, new Set(selectedAttachments.filter((attachment) => value(attachment, 'site_id') === siteAId).map((attachment) => attachment.metadata.id))],
        [siteBId, new Set(selectedAttachments.filter((attachment) => value(attachment, 'site_id') === siteBId).map((attachment) => attachment.metadata.id))],
      ]);
      const activePaths: OperationalPathTelemetry[] = nodes.flatMap((node) => {
        if (node.telemetryState !== 'online' || node.lifecycle !== 'active' || node.failOpenRequired || (node.siteId !== siteAId && node.siteId !== siteBId)) return [];
        const destinationSiteId = node.siteId === siteAId ? siteBId : siteAId;
        const destinationAttachmentIds = attachmentIdsBySite.get(destinationSiteId) ?? new Set<string>();
        return (node.telemetry?.paths ?? [])
          .filter((path) => destinationAttachmentIds.has(path.peer_attachment_id))
          .map((path) => ({
            ...path,
            sourceSiteId: node.siteId,
            destinationSiteId,
            sourceNodeName: node.name,
            sampledAt: node.telemetry?.reported_at ?? '',
          }));
      });
      const activeDirections = new Set(activePaths.map((path) => `${path.sourceSiteId}:${path.destinationSiteId}`));
      const activeDirectionCount = activeDirections.size;
      const staleDirections = nodes.flatMap((node) => {
        if (node.telemetryState !== 'stale' || !node.telemetry || (node.siteId !== siteAId && node.siteId !== siteBId)) return [];
        const destinationSiteId = node.siteId === siteAId ? siteBId : siteAId;
        const destinationAttachmentIds = attachmentIdsBySite.get(destinationSiteId) ?? new Set<string>();
        return node.telemetry.paths
          .filter((path) => destinationAttachmentIds.has(path.peer_attachment_id))
          .map(() => `${node.siteId}:${destinationSiteId}`);
      });
      const staleDirectionKeys = new Set(staleDirections);
      const staleDirectionCount = staleDirectionKeys.size;
      const peerReadiness = readinessBySegment[value(peer, 'segment_id')];
      const endpointNodes = [nodes.filter((node) => node.siteId === siteAId), nodes.filter((node) => node.siteId === siteBId)];
      const rejectedNodes = endpointNodes.flat().filter((node) => node.applyState === 'rejected');
      const failedEndpointLabels = endpointNodes.flatMap((siteNodes, index) => (
        siteNodes.length > 0 && siteNodes.every((node) => (
          !node.registered
          || node.failOpenRequired
          || (node.telemetryState === 'online' && (node.lifecycle === 'degraded' || node.lifecycle === 'stopped'))
        ))
          ? [index === 0 ? siteAName : siteBName]
          : []
      ));
      const configurationFailed = peerReadiness?.reason_codes.includes('node_apply_failed') === true
        || rejectedNodes.length > 0;
      const endpointFailed = failedEndpointLabels.length > 0;
      const endpointOffline = endpointNodes.some((siteNodes) => (
        siteNodes.length === 0 || siteNodes.every((node) => node.status.tone === 'gray')
      ));
      const policyUpdating = !configurationFailed && (
        peerReadiness?.reason_codes.some((code) => code === 'config_pending' || code === 'node_apply_pending') === true
        || endpointNodes.some((siteNodes) => siteNodes.some((node) => node.applyState === 'pending'))
      );
      const expectedDirections = [
        { key: `${siteAId}:${siteBId}`, label: `${siteAName} -> ${siteBName}` },
        { key: `${siteBId}:${siteAId}`, label: `${siteBName} -> ${siteAName}` },
      ];
      const operationalStatus = linkOperationalStatus({
        configuredPathCount: paths.length,
        endpointOffline,
        activeDirectionCount,
        staleDirectionCount,
        policyUpdating,
        configurationFailed,
        endpointFailed,
        missingDirectionLabels: expectedDirections.filter((direction) => !activeDirections.has(direction.key)).map((direction) => direction.label),
        staleDirectionLabels: expectedDirections.filter((direction) => staleDirectionKeys.has(direction.key)).map((direction) => direction.label),
        failedEndpointLabels: rejectedNodes.length > 0 ? rejectedNodes.map((node) => node.name) : failedEndpointLabels,
      });
      return {
        id: peer.metadata.id,
        siteAId,
        siteBId,
        siteAName,
        siteBName,
        directionCount: Math.min(2, paths.length),
        kindLabel: kinds.has('RELAY') ? '中继' : '直连',
        state: operationalStatus.code,
        status: operationalStatus,
        activeDirectionCount,
        staleDirectionCount,
        activePathCount: activePaths.length,
        activePaths,
      };
    });
  const routeLabels = selectedPrefixes.map((item) => cidr(item.resource.spec.prefix));
  const egressLabels = selectedEgresses.map(name);
  const selectedPolicies = resources.policies.filter(segmentMatches);
  const selectedDns = resources.dns.filter(segmentMatches);
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
    segment: segmentResource
      ? { id: segmentId, name: name(segmentResource), overlayCidr: cidr(segmentResource.resource.spec.overlay_prefix), aggregate: false }
      : resources.segments.length > 0
        ? { id: '', name: '全部网络', overlayCidr: `${resources.segments.length} 个网络分段`, aggregate: true }
        : null,
    readiness,
    readinessLabel: aggregateReadinessLabel,
    sites,
    nodes,
    links,
    activeNodeCount: nodes.filter((node) => node.applyState === 'active').length,
    registeredNodeCount: nodes.filter((node) => node.registered).length,
    healthyNodeCount: nodes.filter((node) => node.status.code === 'healthy').length,
    warningNodeCount: nodes.filter((node) => node.status.tone === 'orange').length,
    errorNodeCount: nodes.filter((node) => node.status.tone === 'red').length,
    onlineNodeCount: nodes.filter((node) => node.telemetryState === 'online').length,
    staleNodeCount: nodes.filter((node) => node.telemetryState === 'stale').length,
    dataPlaneActiveNodeCount: nodes.filter((node) => node.dataPlaneActive).length,
    failOpenNodeCount: nodes.filter((node) => node.failOpenRequired).length,
    rejectedNodeCount: nodes.filter((node) => node.applyState === 'rejected').length,
    pendingNodeCount: nodes.filter((node) => node.applyState === 'pending').length,
    activeLinkCount: links.filter((link) => link.state === 'active').length,
    warningLinkCount: links.filter((link) => link.status.tone === 'orange').length,
    failedLinkCount: links.filter((link) => link.status.tone === 'red').length,
    pathCount: resources.paths.filter(segmentMatches).length,
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
