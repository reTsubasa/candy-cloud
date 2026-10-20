import type { ControlResource, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimePathTelemetry, RuntimeTelemetry } from './types';
import {
  linkOperationalStatus,
  nodeOperationalStatus,
  type LinkOperationalCode,
  type NodeOperationalCode,
  type OperationalStatus,
} from './operational-status';
import { pathHealth, routeDiagnosticsFault, runtimeDataPlaneReady } from './runtime-observability';

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
  applyStatus: OperationalStatus<'active' | 'pending' | 'rejected' | 'unknown'>;
  routeStatus: OperationalStatus<'ready' | 'recovering' | 'failed' | 'unknown'>;
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
  pendingApplyNodeCount: number;
  rejectedApplyNodeCount: number;
  failedRouteNodeCount: number;
  recoveringRouteNodeCount: number;
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
  relayNodeNames: string[];
  state: LinkOperationalCode;
  status: OperationalStatus<LinkOperationalCode>;
  applyStatus: OperationalStatus<'active' | 'pending' | 'rejected' | 'unknown'>;
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
  if (!readiness) return '配置状态待确认';
  if (readiness.ready) return '配置已应用';
  if (readiness.reason_codes.includes('service_not_enabled')) return '服务尚未开通';
  if (readiness.reason_codes.includes('node_apply_failed')) return '配置应用失败';
  if (readiness.reason_codes.includes('activation_blocked')) return '配置发布已阻断';
  if (readiness.reason_codes.includes('node_offline')) return '等待节点端点';
  if (readiness.reason_codes.includes('config_pending')) return '配置发布中';
  if (readiness.reason_codes.includes('activation_preparing')) return '配置准备中';
  if (readiness.reason_codes.includes('activation_committing')) return '配置提交中';
  if (readiness.reason_codes.includes('node_apply_pending')) return '等待节点应用配置';
  return '等待配置';
}

function configurationApplyStatus(state: OperationalNode['applyState'], mode: RuntimeConfigurationStatus['activation_mode']): OperationalNode['applyStatus'] {
  const item = mode === 'POLICY_ONLY' ? '路由策略' : '网络配置';
  if (state === 'active') return { code: 'active', label: `${item}已应用`, detail: '当前配置回执已确认', tone: 'green' };
  if (state === 'pending') return { code: 'pending', label: `${item}更新中`, detail: `等待 Cloud 发布或节点确认当前${item}`, tone: 'orange' };
  if (state === 'rejected') return { code: 'rejected', label: `${item}应用失败`, detail: `节点拒绝了当前${item}`, tone: 'red' };
  return { code: 'unknown', label: `${item}状态未知`, detail: '尚无当前配置回执', tone: 'gray' };
}

function aggregateApplyStatus(nodes: OperationalNode[]): OperationalNode['applyStatus'] {
  if (nodes.some((node) => node.applyStatus.code === 'rejected')) return { code: 'rejected', label: '配置应用失败', detail: '至少一个节点拒绝了当前配置；Peer 状态按实时遥测单独显示', tone: 'red' };
  if (nodes.some((node) => node.applyStatus.code === 'pending')) return { code: 'pending', label: '配置应用中', detail: '等待相关节点确认配置；Peer 状态按实时遥测单独显示', tone: 'orange' };
  if (nodes.length > 0 && nodes.every((node) => node.applyStatus.code === 'active')) return { code: 'active', label: '配置已应用', detail: '所有相关节点均已确认当前配置', tone: 'green' };
  return { code: 'unknown', label: '配置状态未知', detail: '部分节点尚无当前配置回执', tone: 'gray' };
}

function routeStatus(runtime: RuntimeTelemetry | null, fresh: boolean): OperationalNode['routeStatus'] {
  if (!runtime || !fresh) return { code: 'unknown', label: '路由状态待确认', detail: '尚无新鲜路由遥测', tone: 'gray' };
  const fault = routeDiagnosticsFault(runtime.route_diagnostics);
  if (fault || runtime.failed_route_prefixes?.length) return {
    code: 'failed', label: '路由转发异常', tone: 'red',
    detail: [runtime.failed_route_prefixes?.length ? `故障前缀：${runtime.failed_route_prefixes.join('、')}` : '', fault, runtime.last_error_detail].filter(Boolean).join('；'),
  };
  if (runtime.route_diagnostics?.integrity === 'reconciling') return { code: 'recovering', label: '路由恢复中', detail: '主机路由正在差量协调，Peer 状态独立判定', tone: 'orange' };
  if (runtime.required_route_owners > runtime.ready_route_owners) return {
    code: 'failed', label: '部分路由不可达', detail: `${runtime.ready_route_owners}/${runtime.required_route_owners} 个路由目标已就绪`, tone: 'red',
  };
  if (runtime.required_route_owners > 0 || runtime.route_diagnostics?.integrity === 'consistent') return { code: 'ready', label: '路由已就绪', detail: '当前路由遥测正常', tone: 'green' };
  return { code: 'unknown', label: '路由状态待确认', detail: 'Runtime 尚无路由目标或路由诊断', tone: 'gray' };
}

function siteOperationalStatus(nodes: OperationalNode[]): OperationalSite['status'] {
  if (nodes.length === 0) return { code: 'empty', label: '暂无节点', detail: '站点尚未配置节点', tone: 'gray' };

  // A site is gray when no node is currently online. Registration or a pending
  // configuration does not make an offline site operationally orange.
  const onlineNodes = nodes.filter((node) => node.registered && node.telemetryState === 'online');
  if (onlineNodes.length === 0) return { code: 'unregistered', label: '离线', detail: '站点当前没有在线节点', tone: 'gray' };
  const fault = onlineNodes.find((node) => node.status.tone === 'red');
  if (fault) return { code: 'fault', label: '节点故障', detail: fault.status.detail, tone: 'red' };

  const transition = nodes.find((node) => node.status.tone === 'orange');
  if (transition) return { code: 'warning', label: '状态变化', detail: transition.status.detail, tone: 'orange' };
  if (onlineNodes.length !== nodes.length) {
    return { code: 'warning', label: '部分在线', detail: `${onlineNodes.length}/${nodes.length} 个节点在线，其余节点当前离线`, tone: 'orange' };
  }
  return { code: 'healthy', label: '节点在线', detail: '站点内已认证节点均在线且 Runtime 稳定', tone: 'green' };
}

function pathIsReady(path: RuntimePathTelemetry, runtime: RuntimeTelemetry): boolean {
  const streamTelemetry = path.transport_mode === 'stream_primary'
    || runtime.transport_mode === 'stream_primary'
    || path.ready_streams != null || path.stream_count != null || (path.streams?.length ?? 0) > 0;
  if (streamTelemetry) {
    return (path.ready_streams ?? 0) > 0
      && (!path.streams?.length || pathHealth(path) !== 'fault');
  }
  // Legacy reports lack per-stream readiness; use the authenticated Peer count
  // to avoid making unrelated route-owner readiness control tunnel visibility.
  return runtime.active_peers > 0;
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
  // The API intentionally returns the full receipt history so it can also feed
  // the audit/log views.  A device can therefore have a newer *historical*
  // rejected receipt than its currently applied generation.  Never let that
  // historical row drive the live topology: prefer the current projection,
  // then fall back to the newest receipt only when no current row exists.
  const statusByIdentity = new Map<string, RuntimeConfigurationStatus>();
  for (const status of statuses) {
    const identity = `${status.device_id}:${status.device_key_id}`;
    const previous = statusByIdentity.get(identity);
    if (!previous || (status.current && !previous.current)
      || (status.current === previous.current
        && Date.parse(status.reported_at) > Date.parse(previous.reported_at))) {
      statusByIdentity.set(identity, status);
    }
  }
  const telemetryByIdentity = new Map(telemetry.map((item) => [`${item.device_id}:${item.device_key_id}`, item]));
  const nodes: OperationalNode[] = selectedNodes.map((item) => {
    const identity = `${value(item, 'device_id')}:${value(item, 'device_key_id')}`;
    const status = statusByIdentity.get(identity);
    const runtime = telemetryByIdentity.get(identity) ?? null;
    const reportedMs = runtime ? Date.parse(runtime.reported_at) : Number.NaN;
    const telemetryAgeMs = nowMs - reportedMs;
    const telemetryState = !runtime || !Number.isFinite(reportedMs) || telemetryAgeMs < 0
      ? 'unreported'
      : telemetryAgeMs <= staleAfterSeconds * 1000 ? 'online' : 'stale';
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
      operationalTransition: runtime?.dataplane_phase === 'recovering',
    });
    const dataPlaneActive = registered
      && telemetryState === 'online'
      && runtime !== null
      && runtimeDataPlaneReady(runtime);
    return {
      id: item.metadata.id,
      name: name(item),
      siteId: value(item, 'site_id'),
      registered,
      applyState,
      applyStatus: configurationApplyStatus(applyState, status?.activation_mode),
      routeStatus: routeStatus(runtime, telemetryState === 'online'),
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
        pendingApplyNodeCount: siteNodes.filter((node) => node.applyState === 'pending').length,
        rejectedApplyNodeCount: siteNodes.filter((node) => node.applyState === 'rejected').length,
        failedRouteNodeCount: siteNodes.filter((node) => node.routeStatus.code === 'failed').length,
        recoveringRouteNodeCount: siteNodes.filter((node) => node.routeStatus.code === 'recovering').length,
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
      const peerAttachments = selectedAttachments.filter((attachment) => value(attachment, 'segment_id') === value(peer, 'segment_id'));
      const peerNodeIds = new Set(peerAttachments.map((attachment) => value(attachment, 'node_id')));
      const peerNodes = nodes.filter((node) => peerNodeIds.has(node.id));
      const attachmentIdsBySite = new Map([
        [siteAId, new Set(peerAttachments.filter((attachment) => value(attachment, 'site_id') === siteAId).map((attachment) => attachment.metadata.id))],
        [siteBId, new Set(peerAttachments.filter((attachment) => value(attachment, 'site_id') === siteBId).map((attachment) => attachment.metadata.id))],
      ]);
      const activePaths: OperationalPathTelemetry[] = peerNodes.flatMap((node) => {
        if (!node.registered || node.telemetryState !== 'online' || !['active', 'degraded', 'fail_open'].includes(node.lifecycle ?? '') || !node.telemetry || (node.siteId !== siteAId && node.siteId !== siteBId)) return [];
        const destinationSiteId = node.siteId === siteAId ? siteBId : siteAId;
        const destinationAttachmentIds = attachmentIdsBySite.get(destinationSiteId) ?? new Set<string>();
        return (node.telemetry?.paths ?? [])
          .filter((path) => destinationAttachmentIds.has(path.peer_attachment_id) && pathIsReady(path, node.telemetry!))
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
      const degradedPathLabels = activePaths
        .filter((path) => pathHealth(path) === 'backpressured')
        .map((path) => `${path.sourceNodeName} -> ${siteNameById.get(path.destinationSiteId) ?? '对端'}`);
      const staleDirections = peerNodes.flatMap((node) => {
        if (node.telemetryState !== 'stale' || !node.telemetry || (node.siteId !== siteAId && node.siteId !== siteBId)) return [];
        const destinationSiteId = node.siteId === siteAId ? siteBId : siteAId;
        const destinationAttachmentIds = attachmentIdsBySite.get(destinationSiteId) ?? new Set<string>();
        return node.telemetry.paths
          .filter((path) => destinationAttachmentIds.has(path.peer_attachment_id))
          .map(() => `${node.siteId}:${destinationSiteId}`);
      });
      const staleDirectionKeys = new Set(staleDirections);
      const staleDirectionCount = staleDirectionKeys.size;
      const endpointNodes = [peerNodes.filter((node) => node.siteId === siteAId), peerNodes.filter((node) => node.siteId === siteBId)];
      const failedEndpointLabels = endpointNodes.flatMap((siteNodes, index) => {
        const siteId = index === 0 ? siteAId : siteBId;
        const hasActiveDirection = activeDirections.has(`${siteId}:${siteId === siteAId ? siteBId : siteAId}`);
        return !hasActiveDirection && siteNodes.length > 0 && siteNodes.every((node) => (
          !node.registered
          || (node.telemetryState === 'online' && (node.lifecycle === 'degraded' || node.lifecycle === 'stopped'))
        )) ? [index === 0 ? siteAName : siteBName] : [];
      });
      const endpointFailed = failedEndpointLabels.length > 0;
      const endpointOffline = endpointNodes.some((siteNodes) => (
        siteNodes.length === 0 || siteNodes.every((node) => node.status.tone === 'gray')
      ));
      const linkEndpointNodes = endpointNodes.flat();
      const expectedDirections = [
        { key: `${siteAId}:${siteBId}`, label: `${siteAName} -> ${siteBName}` },
        { key: `${siteBId}:${siteAId}`, label: `${siteBName} -> ${siteAName}` },
      ];
      const operationalStatus = linkOperationalStatus({
        configuredPathCount: paths.length,
        endpointOffline,
        activeDirectionCount,
        staleDirectionCount,
        endpointFailed,
        missingDirectionLabels: expectedDirections.filter((direction) => !activeDirections.has(direction.key)).map((direction) => direction.label),
        staleDirectionLabels: expectedDirections.filter((direction) => staleDirectionKeys.has(direction.key)).map((direction) => direction.label),
        failedEndpointLabels,
        degradedPathLabels,
      });
      const activeKinds = new Set(activePaths.map((path) => path.path_kind));
      const pathById = new Map(paths.map((path) => [path.metadata.id, path]));
      const allNodeNames = new Map(resources.nodes.map((item) => [item.metadata.id, name(item)]));
      const relayNodeNames = [...new Set(activePaths
        .filter((path) => path.path_kind === 'relay')
        .flatMap((path) => {
          const candidate = (path.candidate_id ? pathById.get(path.candidate_id) : undefined)
            ?? paths.find((item) => value(item, 'kind') === 'RELAY');
          const relayId = candidate && value(candidate, 'relay_id');
          const relay = relayId ? resources.relays.find((item) => item.metadata.id === relayId) : undefined;
          const serviceNodeId = relay ? value(relay, 'service_node_id') : '';
          const serviceNodeName = serviceNodeId ? allNodeNames.get(serviceNodeId) : undefined;
          if (serviceNodeName) return [serviceNodeName];
          if (relay) return [name(relay)];
          return ['中继节点'];
        }))];
      const kindLabel = activeKinds.size === 1
        ? (activeKinds.has('relay') ? '中继' : '直连')
        : activeKinds.size > 1
          ? '多路径'
          : kinds.size === 1
            ? `${kinds.has('RELAY') ? '中继' : '直连'}候选`
            : '线路候选';
      return {
        id: peer.metadata.id,
        siteAId,
        siteBId,
        siteAName,
        siteBName,
        directionCount: Math.min(2, paths.length),
        kindLabel,
        relayNodeNames,
        state: operationalStatus.code,
        status: operationalStatus,
        applyStatus: aggregateApplyStatus(linkEndpointNodes),
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
