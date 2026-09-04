import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Select, Space, Spin, Switch, Tag, Typography } from '@arco-design/web-react';
import {
  IconBranch,
  IconCheckCircle,
  IconCloud,
  IconDesktop,
  IconRefresh,
  IconRight,
  IconStorage,
  IconThunderbolt,
} from '@arco-design/web-react/icon';
import {
  fetchHealth,
  fetchRuntimeActivationReadiness,
  fetchRuntimeConfigurationStatuses,
  fetchRuntimeTelemetry,
  listAllResources,
} from '../api';
import {
  buildOperationalTopology,
  emptyOperationalResources,
  type OperationalResources,
  type OperationalResourceKey,
  type OperationalTopologySnapshot,
  type ResourceLoadErrors,
} from '../operational-topology';
import { LINK_STATUS_BOUNDARIES, SITE_STATUS_BOUNDARIES, type OperationalTone } from '../operational-status';
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import type { ControlResource, HealthState, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimeTelemetry, Session } from '../types';
import { QuickSetupWizard } from './QuickSetupWizard';

type Props = { session: Session; onOpenLogs?: () => void };

const initialHealth: HealthState = {
  live: { status: null, text: '', loading: true, checkedAt: null },
  ready: { status: null, text: '', loading: true, checkedAt: null },
  degraded: { status: null, text: '', loading: true, checkedAt: null },
};

const resourceRequests = [...resourceDefinitions, pathDefinition] as const;

function healthLabel(status: number | null): { label: string; tone: 'ok' | 'warn' | 'error' } {
  if (status !== null && status >= 200 && status < 300) return { label: '正常', tone: 'ok' };
  if (status === null) return { label: '不可达', tone: 'error' };
  return { label: '异常', tone: 'warn' };
}

function relativeTime(value: Date | null, now = Date.now()): string {
  if (!value) return '尚未更新';
  const seconds = Math.max(0, Math.floor((now - value.getTime()) / 1000));
  if (seconds < 5) return '刚刚更新';
  if (seconds < 60) return `${seconds} 秒前更新`;
  return `${Math.floor(seconds / 60)} 分钟前更新`;
}

function controlPlaneDetail(health: HealthState): string {
  if (health.ready.status === 200) return 'API、身份与存储已通过就绪检查';
  if (health.ready.status === null) return '无法连接控制面健康检查';
  return '至少一项控制面依赖尚未就绪';
}

export function Overview({ session, onOpenLogs }: Props) {
  const [resources, setResources] = useState<OperationalResources>(emptyOperationalResources);
  const [resourceErrors, setResourceErrors] = useState<ResourceLoadErrors>({});
  const [statuses, setStatuses] = useState<RuntimeConfigurationStatus[]>([]);
  const [telemetry, setTelemetry] = useState<RuntimeTelemetry[]>([]);
  const [telemetryStaleAfter, setTelemetryStaleAfter] = useState(60);
  const [telemetryAvailable, setTelemetryAvailable] = useState(true);
  const [readiness, setReadiness] = useState<Record<string, RuntimeActivationReadiness>>({});
  const [health, setHealth] = useState<HealthState>(initialHealth);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [clock, setClock] = useState(() => Date.now());
  const [selectedSegmentId, setSelectedSegmentId] = useState('');
  const [setupVisible, setSetupVisible] = useState(false);
  const tenantId = session.claims.tenant_id;

  const load = useCallback(async (background = false) => {
    if (background) setRefreshing(true); else setLoading(true);
    const healthPromise = Promise.all(['live', 'ready', 'degraded'].map((name) => fetchHealth(name as 'live' | 'ready' | 'degraded')))
      .then(([live, ready, degraded]) => setHealth({ live, ready, degraded }));
    if (!tenantId) {
      setResources(emptyOperationalResources);
      setResourceErrors({});
      setStatuses([]);
      setTelemetry([]);
      setReadiness({});
      await healthPromise;
      setLoading(false);
      setRefreshing(false);
      return;
    }
    const entries = await Promise.all(resourceRequests.map(async (definition) => {
      const key = definition.key as OperationalResourceKey;
      try {
        const response = await listAllResources(session.token, tenantId, definition.collection);
        return [key, response.filter((item) => item.metadata.state === 'ACTIVE'), null] as const;
      } catch (reason) {
        return [key, [] as ControlResource[], reason instanceof Error ? reason.message : '加载失败'] as const;
      }
    }));
    const nextResources = { ...emptyOperationalResources } as OperationalResources;
    const nextErrors: ResourceLoadErrors = {};
    for (const [key, items, error] of entries) {
      nextResources[key] = items;
      if (error) nextErrors[key] = error;
    }
    setResources(nextResources);
    setResourceErrors(nextErrors);
    const [statusResult, telemetryResult, readinessEntries] = await Promise.all([
      fetchRuntimeConfigurationStatuses(session.token, tenantId).catch(() => ({ schema_version: 1 as const, items: [] })),
      fetchRuntimeTelemetry(session.token, tenantId)
        .then((result) => ({ result, available: true }))
        .catch(() => ({ result: { schema_version: 1, stale_after_seconds: 60, items: [] as RuntimeTelemetry[] }, available: false })),
      Promise.all(nextResources.segments.map(async (segment) => {
        try {
          return [segment.metadata.id, await fetchRuntimeActivationReadiness(session.token, tenantId, segment.metadata.id)] as const;
        } catch {
          return [segment.metadata.id, null] as const;
        }
      })),
    ]);
    setStatuses(statusResult.items);
    setTelemetry(telemetryResult.result.items);
    setTelemetryStaleAfter(telemetryResult.result.stale_after_seconds);
    setTelemetryAvailable(telemetryResult.available);
    setReadiness(Object.fromEntries(readinessEntries.filter((entry): entry is readonly [string, RuntimeActivationReadiness] => entry[1] !== null)));
    await healthPromise;
    setLastUpdated(new Date());
    setLoading(false);
    setRefreshing(false);
  }, [session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => void load(true), 10_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);
  useEffect(() => {
    if (selectedSegmentId && !resources.segments.some((segment) => segment.metadata.id === selectedSegmentId)) setSelectedSegmentId('');
  }, [resources.segments, selectedSegmentId]);

  const topology = useMemo(
    () => buildOperationalTopology(resources, statuses, readiness, selectedSegmentId, telemetry, telemetryStaleAfter, clock),
    [clock, readiness, resources, selectedSegmentId, statuses, telemetry, telemetryStaleAfter],
  );
  const controlReady = health.ready.status === 200;
  const resourceErrorCount = Object.keys(resourceErrors).length;
  const incidents = useMemo(() => {
    const items: Array<{ tone: 'error' | 'warn'; title: string; detail: string }> = [];
    if (!controlReady) items.push({ tone: 'error', title: '控制面未就绪', detail: controlPlaneDetail(health) });
    if (controlReady && health.degraded.status !== null && health.degraded.status !== 200) items.push({ tone: 'warn', title: '控制面依赖降级', detail: health.degraded.text || '依赖探针返回异常状态，请在系统页查看具体服务' });
    if (resourceErrorCount > 0) items.push({ tone: 'error', title: '资源读取不完整', detail: `${resourceErrorCount} 类资源读取失败，拓扑仅显示已验证数据` });
    if (!telemetryAvailable) items.push({ tone: 'warn', title: '运行遥测不可用', detail: '无法读取 Runtime 最新状态，在线状态不会被推测' });
    for (const node of topology.nodes.filter((item) => item.status.tone === 'red')) {
      items.push({ tone: 'error', title: `${node.name} · ${node.status.label}`, detail: node.status.detail });
    }
    for (const link of topology.links.filter((item) => item.status.tone === 'red')) {
      items.push({ tone: 'error', title: `${link.siteAName} ↔ ${link.siteBName} · ${link.status.label}`, detail: link.status.detail });
    }
    if (topology.segment && topology.readiness && !topology.readiness.ready) {
      items.push({ tone: 'warn', title: `${topology.segment.name} 尚未完全激活`, detail: topology.readinessLabel });
    }
    for (const node of topology.nodes.filter((item) => item.status.tone === 'orange')) {
      items.push({ tone: 'warn', title: `${node.name} · ${node.status.label}`, detail: node.status.detail });
    }
    for (const link of topology.links.filter((item) => item.status.tone === 'orange')) {
      items.push({ tone: 'warn', title: `${link.siteAName} ↔ ${link.siteBName} · ${link.status.label}`, detail: link.status.detail });
    }
    return items.slice(0, 6);
  }, [controlReady, health, resourceErrorCount, telemetryAvailable, topology]);

  return (
    <section className="workspace-section operational-overview">
      <header className="page-header operational-header">
        <Space>
          <span className="live-refresh-control"><Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} /><span>实时更新</span></span>
          <Button icon={<IconRefresh />} loading={refreshing} onClick={() => void load(true)}>刷新</Button>
          <Button type="primary" icon={<IconRight />} onClick={() => setSetupVisible(true)}>{resources.nodes.length > 0 ? '调整网络' : '开始配置'}</Button>
        </Space>
      </header>
      {!tenantId && <Alert type="error" showIcon content="当前会话缺少租户范围，无法读取网络运行状态。" />}
      <Spin loading={loading} block>
        <div className="operational-status-strip">
          <StatusMetric icon={<IconCloud />} label="控制面" value={controlReady ? '正常' : '异常'} detail={controlPlaneDetail(health)} tone={controlReady ? 'ok' : 'error'} />
          <StatusMetric icon={<IconDesktop />} label="节点状态" value={`${topology.registeredNodeCount} 已认证`} detail={`${topology.onlineNodeCount} 在线 · ${topology.nodes.length - topology.registeredNodeCount} 待认证`} tone={topology.nodes.length === 0 ? 'neutral' : topology.registeredNodeCount === topology.nodes.length ? 'ok' : 'warn'} />
          <StatusMetric icon={<IconBranch />} label="互联线路" value={`${topology.activeLinkCount} / ${topology.links.length} 已认证`} detail={`${topology.warningLinkCount} 协商/更新 · ${topology.failedLinkCount} 故障`} tone={topology.failedLinkCount > 0 ? 'error' : topology.links.length === 0 ? 'neutral' : topology.warningLinkCount > 0 ? 'warn' : 'ok'} />
          <StatusMetric icon={<IconStorage />} label="路由与出口" value={`${topology.routeCount} 条路由`} detail={`${topology.egressCount} 个出口 · ${topology.policyRuleCount} 条策略规则`} tone="neutral" />
          <StatusMetric icon={<IconThunderbolt />} label="性能遥测" value={topology.nodes.length > 0 ? `${topology.telemetryCoverageCount} / ${topology.nodes.length}` : '未接入'} detail={!telemetryAvailable ? 'Cloud 遥测接口当前不可用' : topology.telemetryCoverageCount > 0 ? '仅统计新鲜且有来源的性能样本' : 'Runtime 在线状态已接入，等待 Core 性能指标'} tone="neutral" />
        </div>

        <div className="operational-layout">
          <div className="operational-main-column">
            <section className="topology-workspace">
            <header className="topology-toolbar">
              <div>
                <Typography.Title heading={5}>实时网络拓扑</Typography.Title>
                <div className="topology-toolbar-meta">
                  <span className="topology-update-state"><i className={autoRefresh ? 'active' : ''} />{relativeTime(lastUpdated, clock)}{refreshing ? ' · 同步中' : ''}</span>
                  <span className="topology-scope">{selectedSegmentId ? `${topology.segment?.name ?? '当前网络'} · ${topology.segment?.overlayCidr ?? ''}` : `全部网络 · ${topology.sites.length} 个站点`}</span>
                </div>
              </div>
              <Select
                value={selectedSegmentId || 'all'}
                options={[{ label: '全部网络', value: 'all' }, ...resources.segments.map((segment) => ({ label: String(segment.resource.spec.name ?? segment.metadata.id), value: segment.metadata.id }))]}
                onChange={(value) => setSelectedSegmentId(value === 'all' ? '' : value)}
                placeholder="筛选网络分段"
                className="segment-selector"
              />
            </header>
            {topology.segment ? <TopologyCanvas snapshot={topology} controlReady={controlReady} /> : (
              <div className="topology-empty"><Empty description="尚未建立可展示的网络分段" /><Button type="primary" onClick={() => setSetupVisible(true)}>开始配置</Button></div>
            )}
            </section>

            {topology.segment && <section className="resource-observability">
              <header><div><Typography.Title heading={5}>资源与路由状态</Typography.Title><Typography.Text type="secondary">{selectedSegmentId ? '当前网络分段的实际配置关系' : '所有网络分段的实际配置关系'}</Typography.Text></div><Tag color={topology.readiness?.ready ? 'green' : 'orange'}>{topology.readinessLabel}</Tag></header>
              <div className="resource-observability-grid">
                <ResourceSignal label="站点" value={topology.sites.length} detail={topology.sites.map((site) => site.name).join('、') || '未接入'} />
                <ResourceSignal label="节点" value={topology.nodes.length} detail={`${topology.registeredNodeCount} 个已认证 · ${topology.onlineNodeCount} 个在线`} />
                <ResourceSignal label="路由前缀" value={topology.routeCount} detail={topology.routeLabels.join('、') || '未发布'} mono />
                <ResourceSignal label="互联网出口" value={topology.egressCount} detail={topology.egressLabels.join('、') || '未配置'} />
                <ResourceSignal label="流量策略" value={topology.policyRuleCount} detail={`${topology.policyRuleCount > 0 ? topology.policyRuleCount : 0} 条规则`} />
                <ResourceSignal label="DNS" value={topology.dnsRecordCount} detail={`${topology.dnsZoneCount} 个内部区域`} />
              </div>
            </section>}
          </div>

          <aside className="telemetry-rail">
            <section>
              <header><strong>运行事件</strong><span className="incident-header-actions"><Tag color={incidents.length > 0 ? 'orange' : 'green'}>{incidents.length > 0 ? `${incidents.length} 项关注` : '无异常'}</Tag>{onOpenLogs && <Button type="text" size="mini" onClick={onOpenLogs}>查看日志</Button>}</span></header>
              {incidents.length === 0 ? <div className="quiet-state"><IconCheckCircle /><span>当前未发现控制面或配置应用异常</span></div> : (
                <div className="incident-list">{incidents.map((incident, index) => <div className={`incident-item ${incident.tone}`} key={`${incident.title}-${index}`}><i /><div><strong>{incident.title}</strong><span>{incident.detail}</span></div></div>)}</div>
              )}
            </section>
            <section>
              <header><strong>数据面遥测</strong><Tag color={topology.onlineNodeCount > 0 ? 'green' : 'gray'}>{topology.onlineNodeCount > 0 ? `${topology.onlineNodeCount} 个节点在线` : '无新鲜上报'}</Tag></header>
              {topology.nodes.filter((node) => node.telemetry?.dataplane_phase).length > 0 && <div className="dataplane-phase-list">
                {topology.nodes.filter((node) => node.telemetry?.dataplane_phase).map((node) => <div key={node.id}><span>{node.name}</span><strong>{dataplanePhaseLabel(node.telemetry?.dataplane_phase ?? null)}</strong></div>)}
              </div>}
              <div className="telemetry-grid">
                <div><span>往返时延</span><strong>{formatMetric(topology.averageRttMs, ' ms')}</strong></div>
                <div><span>丢包</span><strong>{topology.averagePacketLossPpm === null ? '—' : `${(topology.averagePacketLossPpm / 10_000).toFixed(2)}%`}</strong></div>
                <div><span>接收速率</span><strong>{formatRate(topology.rxBps)}</strong></div>
                <div><span>发送速率</span><strong>{formatRate(topology.txBps)}</strong></div>
              </div>
              <p className="telemetry-source-note">在线、自动降级、Peer 与路由状态来自 Runtime 心跳；时延、丢包和速率仅在 Core 提供真实采样时显示。</p>
            </section>
            <section>
              <header><strong>控制面探针</strong><span className="probe-time">{relativeTime(lastUpdated, clock)}</span></header>
              <div className="probe-list">{(['live', 'ready', 'degraded'] as const).map((key) => {
                const meta = healthLabel(health[key].status);
                return <div key={key}><span><i className={meta.tone} />{key}</span><strong>{meta.label}</strong></div>;
              })}</div>
            </section>
          </aside>
        </div>
      </Spin>
      <QuickSetupWizard visible={setupVisible} session={session} onClose={() => { setSetupVisible(false); void load(); }} onChanged={() => void load()} />
    </section>
  );
}

function dataplanePhaseLabel(phase: string | null): string {
  const labels: Record<string, string> = {
    control_received: '已接收控制配置', control_verified: '控制配置已校验', config_compiled: '配置已编译',
    netd_prepared: '主机网络已准备', core_policy_staged: 'Core 策略已暂存', peer_connecting: 'Peer 连接中',
    peer_authenticated: 'Peer 已认证', stream_opening: 'Stream 建立中', stream_ready: 'Stream 已就绪',
    route_owners_ready: '路由 owner 已就绪', steering_committed: '流量接管已提交', data_plane_active: '数据面运行中',
    degraded: '数据面已降级', recovering: '数据面恢复中', failed: '数据面故障', stopping: '停止中', stopped: '已停止',
  };
  return phase ? labels[phase] ?? phase : '未上报';
}

function StatusMetric({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: string; detail: string; tone: 'ok' | 'warn' | 'error' | 'neutral' }) {
  return <div className={`status-metric ${tone}`}><span className="status-metric-icon">{icon}</span><div><span>{label}</span><strong>{value}</strong><small title={detail}>{detail}</small></div></div>;
}

function ResourceSignal({ label, value, detail, mono = false }: { label: string; value: number; detail: string; mono?: boolean }) {
  return <div className="resource-signal"><span>{label}</span><strong>{value}</strong><small className={mono ? 'mono' : ''} title={detail}>{detail}</small></div>;
}

function TopologyCanvas({ snapshot, controlReady }: { snapshot: OperationalTopologySnapshot; controlReady: boolean }) {
  const siteCount = snapshot.sites.length;
  const width = Math.max(900, siteCount * 230 + 120);
  const center = width / 2;
  const aggregate = snapshot.segment?.aggregate ?? false;
  const siteY = aggregate ? 142 : 190;
  const maximumNodeRows = Math.min(3, Math.max(1, ...snapshot.sites.map((site) => site.nodes.length)));
  const hasOverflowNodes = snapshot.sites.some((site) => site.nodes.length > maximumNodeRows);
  const siteCardHeight = 126 + maximumNodeRows * 18 + (hasOverflowNodes ? 18 : 0);
  const siteBottom = siteY + siteCardHeight;
  const linkLaneGap = 62;
  const linkLaneCount = Math.min(snapshot.links.length, 8);
  const height = siteBottom + 42 + linkLaneCount * linkLaneGap + 32;
  const siteX = (index: number) => siteCount <= 1 ? center : 100 + index * ((width - 200) / (siteCount - 1));
  const siteById = Object.fromEntries(snapshot.sites.map((site, index) => [site.id, { ...site, x: siteX(index) }]));
  const allSitesOffline = snapshot.sites.length > 0 && snapshot.sites.every((site) => site.status.tone === 'gray');
  const controlLinkTone = !controlReady ? 'red' : allSitesOffline ? 'gray' : snapshot.readiness?.ready ? 'green' : 'orange';
  const segmentTone = !controlReady ? 'red' : allSitesOffline ? 'gray' : snapshot.readiness?.ready ? 'green' : 'orange';
  return <><div className="topology-canvas" aria-label="SD-WAN 运行拓扑">
    <svg viewBox={`0 0 ${width} ${height}`} role="img" style={{ minWidth: width, height }}>
      <g className={`topology-control-node ${controlReady ? 'ok' : 'error'}`} transform={`translate(${center - 98} 20)`}>
        <rect width="196" height="48" rx="6" /><circle cx="20" cy="24" r="5" /><text x="34" y="21">Candy Cloud</text><text className="sub" x="34" y="36">控制面 · {controlReady ? '正常' : '异常'}</text>
      </g>
      {!aggregate && <>
        <line className={`topology-control-link tone-${controlLinkTone}`} x1={center} y1="68" x2={center} y2="92" />
        <g className={`topology-segment-node tone-${segmentTone}`} transform={`translate(${center - 120} 92)`}>
          <rect width="240" height="58" rx="7" /><text x="120" y="24" textAnchor="middle">{ellipsis(snapshot.segment?.name ?? '网络分段', 24)}</text><text className="sub" x="120" y="42" textAnchor="middle">{snapshot.segment?.overlayCidr} · {snapshot.readinessLabel}</text>
        </g>
      </>}
      {snapshot.sites.map((site, index) => {
        const x = siteX(index);
        return <g key={site.id}>
          <path className={`topology-site-link tone-${site.status.tone}`} d={aggregate
            ? `M ${center} 68 C ${center} 105, ${x} 105, ${x} ${siteY}`
            : `M ${center} 150 C ${center} 174, ${x} 166, ${x} ${siteY}`} />
          <g className={`topology-site-node ${site.status.tone === 'green' ? 'ok' : site.status.tone === 'orange' ? 'pending' : site.status.tone === 'red' ? 'error' : 'neutral'}`} transform={`translate(${x - 90} ${siteY})`}>
            <rect width="180" height={siteCardHeight} rx="7" />
            <circle cx="18" cy="22" r="5" />
            <text className="site-name" x="31" y="26">{ellipsis(site.name, 19)}</text>
            <text className="sub" x="14" y="51">{site.kindLabel}</text>
            <line x1="14" y1="62" x2="166" y2="62" />
            <text x="14" y="83">节点 {site.nodes.length}</text><text className="value" x="166" y="83" textAnchor="end">已认证 {site.registeredNodeCount}</text>
            <text x="14" y="106">在线 {site.onlineNodeCount}</text><text className="value" x="166" y="106" textAnchor="end">路由 {site.routeCount} · 出口 {site.egressCount}</text>
            {site.nodes.length === 0 ? <text className="sub" x="14" y="132">等待节点接入</text> : site.nodes.slice(0, maximumNodeRows).map((node, nodeIndex) => <g className={`topology-node-state tone-${node.status.tone}`} key={node.id} transform={`translate(0 ${126 + nodeIndex * 18})`}>
              <circle cx="18" cy="6" r="3.5" /><text x="28" y="10">{ellipsis(node.name, 12)}</text><text className="state" x="166" y="10" textAnchor="end">{node.status.label}</text>
            </g>)}
            {site.nodes.length > maximumNodeRows && <text className="sub" x="14" y={126 + maximumNodeRows * 18 + 10}>另有 {site.nodes.length - maximumNodeRows} 个节点</text>}
          </g>
        </g>;
      })}
      {snapshot.links.map((link, linkIndex) => {
        const source = siteById[link.siteAId];
        const target = siteById[link.siteBId];
        if (!source || !target) return null;
        const left = source.x < target.x ? source : target;
        const right = source.x < target.x ? target : source;
        const lane = Math.min(linkIndex, 7);
        const y = siteBottom + 28 + lane * linkLaneGap;
        const tone = toneClass(link.status.tone);
        const telemetryRows = link.activePaths.slice(0, 2).map((path) => {
          const sourceName = siteById[path.sourceSiteId]?.name ?? path.sourceNodeName;
          const destinationName = siteById[path.destinationSiteId]?.name ?? '对端';
          const staleLabel = path.sampledAt ? formatStaleTelemetry(path.sampledAt) : '';
          return `${sourceName} -> ${destinationName}  RTT ${formatMetric(path.rtt_ms, ' ms')}  丢包 ${path.packet_loss_ppm == null ? '—' : `${(path.packet_loss_ppm / 10_000).toFixed(2)}%`}  ↑${formatRate(path.tx_bps)} ↓${formatRate(path.rx_bps)}${staleLabel ? `  ${staleLabel}` : ''}`;
        });
        const pathDetail = telemetryRows.length > 0 ? ` · ${telemetryRows.join(' · ')}` : '';
        const labelWidth = 310;
        const labelHeight = telemetryRows.length > 0 ? 42 : 24;
        return <g className={`topology-peer-link ${tone}`} key={link.id}>
          <title>{`${link.status.label}：${link.status.detail}${pathDetail}`}</title>
          <path aria-label="站点数据线路" d={`M ${left.x} ${siteBottom} C ${left.x} ${y}, ${right.x} ${y}, ${right.x} ${siteBottom}`} />
          <rect x={(left.x + right.x) / 2 - labelWidth / 2} y={y - labelHeight / 2} width={labelWidth} height={labelHeight} rx="7" />
          {telemetryRows.length > 0 ? <>
            <text x={(left.x + right.x) / 2} y={y - 11} textAnchor="middle">{link.status.label} · {link.kindLabel} · {link.activePathCount} 条路径</text>
            {telemetryRows.map((row, index) => <text className="telemetry" key={row} x={(left.x + right.x) / 2} y={y + 4 + index * 12} textAnchor="middle">{ellipsis(row, 72)}</text>)}
          </> : <text x={(left.x + right.x) / 2} y={y + 4} textAnchor="middle">{link.kindLabel} · {link.status.label}</text>}
        </g>;
      })}
      <g className="topology-legend" transform={`translate(${center - 225} ${height - 24})`}>
        <circle className="ok" cx="6" cy="6" r="5" /><text x="17" y="10">正常 / 已认证</text>
        <circle className="warn" cx="126" cy="6" r="5" /><text x="137" y="10">处理中 / 待确认</text>
        <circle className="error" cx="286" cy="6" r="5" /><text x="297" y="10">明确故障</text>
      </g>
    </svg>
  </div><StatusBoundaryLegend /></>;
}

function toneClass(tone: OperationalTone): 'ok' | 'warn' | 'error' | 'neutral' {
  if (tone === 'green') return 'ok';
  if (tone === 'orange') return 'warn';
  if (tone === 'red') return 'error';
  return 'neutral';
}

function StatusBoundaryLegend() {
  return <div className="status-boundary-legend" aria-label="站点与互联线路状态定义">
    {[{ label: '站点', items: SITE_STATUS_BOUNDARIES }, { label: '互联线路', items: LINK_STATUS_BOUNDARIES }].map((group) => <div key={group.label}>
      <strong>{group.label}</strong>
      {group.items.map((item) => <span key={item.tone} title={item.detail}><i className={`tone-${item.tone}`} />{item.label}<small>{item.detail}</small></span>)}
    </div>)}
  </div>;
}

function ellipsis(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

function formatMetric(value: number | null, suffix: string): string {
  return value === null ? '—' : `${value}${suffix}`;
}

function formatRate(value: number | null): string {
  if (value === null) return '—';
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} Gbps`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} Mbps`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} Kbps`;
  return `${value} bps`;
}

function formatStaleTelemetry(value: string): string {
  const reported = Date.parse(value);
  if (!Number.isFinite(reported)) return '';
  const seconds = Math.max(0, Math.round((Date.now() - reported) / 1000));
  return seconds <= 60 ? '' : `遥测 ${Math.floor(seconds / 60)} 分钟未更新`;
}
