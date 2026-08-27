import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Select, Space, Spin, Switch, Tag } from '@arco-design/web-react';
import {
  IconBranch,
  IconCheckCircle,
  IconCloud,
  IconDesktop,
  IconRefresh,
  IconRight,
  IconStorage,
  IconThunderbolt,
  IconWifi,
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
  type OperationalLink,
  type OperationalNode,
  type OperationalResourceKey,
  type OperationalTopologySnapshot,
  type ResourceLoadErrors,
} from '../operational-topology';
import { LINK_STATUS_BOUNDARIES, NODE_STATUS_BOUNDARIES, type OperationalTone } from '../operational-status';
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import type { ControlResource, HealthState, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimeTelemetry, Session } from '../types';
import {
  BarChart,
  Gauge,
  GradientStatusBar,
  NavigationTabs,
  NervPanel,
  PhaseStatusStack,
  type NervTone,
  type PhaseItem,
} from '../vendor/nerv-ui';
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
  const [activeView, setActiveView] = useState('network');
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

  const overallTone: NervTone = !controlReady || topology.errorNodeCount > 0 || topology.failedLinkCount > 0
    ? 'red'
    : topology.warningNodeCount > 0 || topology.warningLinkCount > 0 || incidents.length > 0 ? 'orange' : 'green';
  const overallLabel = topology.nodes.length === 0
    ? '等待接入'
    : overallTone === 'red' ? '存在故障' : overallTone === 'orange' ? '需要关注' : '全网正常';
  const healthyNodePercent = topology.nodes.length > 0 ? Math.round(topology.healthyNodeCount / topology.nodes.length * 100) : 0;
  const activeLinkPercent = topology.links.length > 0 ? Math.round(topology.activeLinkCount / topology.links.length * 100) : 0;
  const throughputBars = topology.nodes.flatMap((node) => {
    const rxBps = node.telemetry?.rx_bps ?? null;
    const txBps = node.telemetry?.tx_bps ?? null;
    if (rxBps === null && txBps === null) return [];
    return [{ label: node.name, value: ((rxBps ?? 0) + (txBps ?? 0)) / 1_000_000, color: node.status.tone === 'red' ? '#ff4d3d' : node.status.tone === 'orange' ? '#ff9f1a' : '#22d3ee', detail: `接收 ${formatRate(rxBps)} · 发送 ${formatRate(txBps)}` }];
  });
  const phaseItems: PhaseItem[] = [
    { label: '控制面', value: controlReady ? '就绪' : '异常', status: controlReady ? 'ok' : 'danger' },
    { label: '配置发布', value: topology.readinessLabel, status: topology.readiness?.ready ? 'ok' : topology.rejectedNodeCount > 0 ? 'danger' : 'warning' },
    { label: '节点数据面', value: `${topology.healthyNodeCount}/${topology.nodes.length}`, status: topology.errorNodeCount > 0 ? 'danger' : topology.warningNodeCount > 0 || topology.nodes.length === 0 ? 'warning' : 'ok' },
    { label: '互联认证', value: `${topology.activeLinkCount}/${topology.links.length}`, status: topology.failedLinkCount > 0 ? 'danger' : topology.warningLinkCount > 0 || topology.links.length === 0 ? 'warning' : 'ok' },
  ];

  return (
    <section className="workspace-section operational-overview">
      <header className="page-header operational-header">
        <div className="nerv-command-heading"><small>SD-WAN OPERATIONS</small><strong>运行状态监控</strong><span>{selectedSegmentId ? topology.segment?.name ?? '当前网络' : '全租户网络态势'}</span></div>
        <Space>
          <span className="live-refresh-control"><Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} /><span>实时更新</span></span>
          <Button icon={<IconRefresh />} loading={refreshing} onClick={() => void load(true)}>刷新</Button>
          <Button type="primary" icon={<IconRight />} onClick={() => setSetupVisible(true)}>{resources.nodes.length > 0 ? '调整网络' : '开始配置'}</Button>
        </Space>
      </header>
      {!tenantId && <Alert type="error" showIcon content="当前会话缺少租户范围，无法读取网络运行状态。" />}
      <Spin loading={loading} block>
        <div className="nerv-dashboard-shell">
          <section className={`nerv-command-strip tone-${overallTone}`}>
            <div className="nerv-primary-state"><small>NETWORK STATE</small><strong>{overallLabel}</strong><span>{incidents.length > 0 ? `${incidents.length} 项事件需要处理` : `${topology.onlineNodeCount} 个节点持续上报，未发现明确故障`}</span></div>
            <GradientStatusBar
              value={healthyNodePercent}
              zones={[{ start: 0, end: 60, color: '#ff4d3d', label: '故障' }, { start: 60, end: 90, color: '#ff9f1a', label: '恢复中' }, { start: 90, end: 100, color: '#1bd98a', label: '正常' }]}
              label="节点健康覆盖"
              detail={`${topology.healthyNodeCount} / ${topology.nodes.length} 个节点数据面正常`}
            />
            <div className="nerv-live-throughput"><small>LIVE THROUGHPUT</small><div><span>RX<strong>{formatRate(topology.rxBps)}</strong></span><span>TX<strong>{formatRate(topology.txBps)}</strong></span></div><footer><i className={autoRefresh ? 'active' : ''} />{relativeTime(lastUpdated, clock)}{refreshing ? ' · 同步中' : ''}</footer></div>
          </section>

          <div className="nerv-dashboard-nav">
            <NavigationTabs tabs={[{ id: 'network', label: '全网态势' }, { id: 'nodes', label: '节点与性能' }, { id: 'links', label: '链路与策略' }]} activeTab={activeView} onTabChange={setActiveView} />
            <Select
              value={selectedSegmentId || 'all'}
              options={[{ label: '全部网络', value: 'all' }, ...resources.segments.map((segment) => ({ label: String(segment.resource.spec.name ?? segment.metadata.id), value: segment.metadata.id }))]}
              onChange={(value) => setSelectedSegmentId(value === 'all' ? '' : value)}
              className="segment-selector"
            />
          </div>

          {activeView === 'network' && <NetworkDashboard
            topology={topology}
            controlReady={controlReady}
            health={health}
            telemetryAvailable={telemetryAvailable}
            incidents={incidents}
            phaseItems={phaseItems}
            throughputBars={throughputBars}
            activeLinkPercent={activeLinkPercent}
            onOpenLogs={onOpenLogs}
            onStartSetup={() => setSetupVisible(true)}
          />}
          {activeView === 'nodes' && <NodeDashboard topology={topology} telemetryAvailable={telemetryAvailable} clock={clock} />}
          {activeView === 'links' && <LinkDashboard topology={topology} />}
        </div>
      </Spin>
      <QuickSetupWizard visible={setupVisible} session={session} onClose={() => { setSetupVisible(false); void load(); }} onChanged={() => void load()} />
    </section>
  );
}

type Incident = { tone: 'error' | 'warn'; title: string; detail: string };

function NetworkDashboard({ topology, controlReady, health, telemetryAvailable, incidents, phaseItems, throughputBars, activeLinkPercent, onOpenLogs, onStartSetup }: {
  topology: OperationalTopologySnapshot;
  controlReady: boolean;
  health: HealthState;
  telemetryAvailable: boolean;
  incidents: Incident[];
  phaseItems: PhaseItem[];
  throughputBars: Array<{ label: string; value: number; color: string; detail: string }>;
  activeLinkPercent: number;
  onOpenLogs?: () => void;
  onStartSetup: () => void;
}) {
  return <div className="nerv-dashboard-view" role="tabpanel">
    <div className="nerv-signal-grid">
      <DashboardSignal icon={<IconCloud />} label="控制面" value={controlReady ? '服务就绪' : '服务异常'} detail={controlPlaneDetail(health)} tone={controlReady ? 'green' : 'red'} />
      <DashboardSignal icon={<IconDesktop />} label="节点" value={`${topology.healthyNodeCount} / ${topology.nodes.length} 正常`} detail={`${topology.warningNodeCount} 处理中 · ${topology.errorNodeCount} 故障`} tone={topology.errorNodeCount > 0 ? 'red' : topology.warningNodeCount > 0 ? 'orange' : topology.nodes.length > 0 ? 'green' : 'muted'} />
      <DashboardSignal icon={<IconBranch />} label="互联" value={`${topology.activeLinkCount} / ${topology.links.length} 已认证`} detail={`${topology.warningLinkCount} 协商中 · ${topology.failedLinkCount} 故障`} tone={topology.failedLinkCount > 0 ? 'red' : topology.warningLinkCount > 0 ? 'orange' : topology.links.length > 0 ? 'green' : 'muted'} />
      <DashboardSignal icon={<IconStorage />} label="策略与出口" value={`${topology.policyRuleCount} 条规则`} detail={`${topology.routeCount} 条路由 · ${topology.egressCount} 个出口`} tone="cyan" />
      <DashboardSignal icon={<IconThunderbolt />} label="性能样本" value={`${topology.telemetryCoverageCount} / ${topology.nodes.length}`} detail={telemetryAvailable ? '仅统计新鲜 Core 采样' : '遥测接口不可用'} tone={telemetryAvailable ? 'cyan' : 'red'} />
    </div>

    <div className="nerv-network-layout">
      <NervPanel label="NETWORK MAP" title="实时网络拓扑" className="nerv-topology-panel" action={<Tag color={topology.readiness?.ready ? 'green' : 'orange'}>{topology.readinessLabel}</Tag>}>
        {topology.segment ? <TopologyCanvas snapshot={topology} controlReady={controlReady} /> : <div className="topology-empty"><Empty description="尚未建立可展示的网络分段" /><Button type="primary" onClick={onStartSetup}>开始配置</Button></div>}
      </NervPanel>
      <aside className="nerv-operations-rail">
        <NervPanel label="INCIDENT QUEUE" title="运行事件" action={onOpenLogs && <Button type="text" size="mini" onClick={onOpenLogs}>查看日志</Button>}>
          {incidents.length === 0 ? <div className="nerv-quiet-state"><IconCheckCircle /><span><strong>未发现明确故障</strong><small>节点、链路与配置发布均在可接受边界内</small></span></div> : <div className="nerv-incident-list">{incidents.map((incident, index) => <div className={incident.tone} key={`${incident.title}-${index}`}><i /><span><strong>{incident.title}</strong><small>{incident.detail}</small></span></div>)}</div>}
        </NervPanel>
        <NervPanel label="SYSTEM PHASES" title="运行阶段">
          <PhaseStatusStack title="CONTROL TO DATA PLANE" phases={phaseItems} />
          <div className="nerv-probe-list">{(['live', 'ready', 'degraded'] as const).map((key) => { const meta = healthLabel(health[key].status); return <span key={key}><i className={meta.tone} />{key}<strong>{meta.label}</strong></span>; })}</div>
        </NervPanel>
      </aside>
    </div>

    <NervPanel label="DATA PLANE" title="实时性能">
      <div className="nerv-performance-layout">
        <div className="nerv-gauge-pair">
          <Gauge label="平均 RTT" value={topology.averageRttMs} max={300} unit="ms" tone="cyan" threshold={150} />
          <Gauge label="平均丢包" value={topology.averagePacketLossPpm === null ? null : Number((topology.averagePacketLossPpm / 10_000).toFixed(2))} max={5} unit="%" tone="green" threshold={1} />
        </div>
        <BarChart title="节点实时吞吐" bars={throughputBars} unit="Mbps" />
        <div className="nerv-link-integrity"><GradientStatusBar value={activeLinkPercent} label="链路双向认证覆盖" detail={`${topology.activeLinkCount} / ${topology.links.length} 条互联已完成双向认证`} zones={[{ start: 0, end: 60, color: '#ff4d3d', label: '不可用' }, { start: 60, end: 90, color: '#ff9f1a', label: '部分可用' }, { start: 90, end: 100, color: '#1bd98a', label: '已认证' }]} /><p>在线与自动降级来自 Runtime 心跳；RTT、丢包、RX/TX 只展示 Core 实际上报，不补零、不推测。</p></div>
      </div>
    </NervPanel>
  </div>;
}

function DashboardSignal({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: string; detail: string; tone: NervTone }) {
  return <div className={`nerv-dashboard-signal tone-${tone}`}><span>{icon}</span><div><small>{label}</small><strong>{value}</strong><p title={detail}>{detail}</p></div></div>;
}

function NodeDashboard({ topology, telemetryAvailable, clock }: { topology: OperationalTopologySnapshot; telemetryAvailable: boolean; clock: number }) {
  return <div className="nerv-dashboard-view" role="tabpanel">
    <div className="nerv-view-summary"><div><small>NODE INVENTORY</small><strong>{topology.nodes.length} 个节点</strong><span>{topology.onlineNodeCount} 个新鲜上报 · {topology.staleNodeCount} 个状态中断 · {topology.failOpenNodeCount} 个已降级</span></div><Tag color={telemetryAvailable ? 'green' : 'red'}>{telemetryAvailable ? '遥测接口正常' : '遥测接口异常'}</Tag></div>
    {topology.nodes.length === 0 ? <div className="nerv-view-empty"><Empty description="当前范围没有节点" /></div> : <div className="nerv-node-grid">{topology.nodes.map((node) => <NodeMonitorCard key={node.id} node={node} siteName={topology.sites.find((site) => site.id === node.siteId)?.name ?? '未关联站点'} clock={clock} />)}</div>}
  </div>;
}

function NodeMonitorCard({ node, siteName, clock }: { node: OperationalNode; siteName: string; clock: number }) {
  const telemetry = node.telemetry;
  const peerPercent = node.configuredPeers > 0 ? Math.round(node.activePeers / node.configuredPeers * 100) : node.activePeers > 0 ? 100 : 0;
  const routePercent = node.requiredRouteOwners > 0 ? Math.round(node.readyRouteOwners / node.requiredRouteOwners * 100) : node.readyRouteOwners > 0 ? 100 : 0;
  return <article className={`nerv-node-card tone-${node.status.tone}`}>
    <header><div><small>{siteName}</small><strong>{node.name}</strong></div><span><i />{node.status.label}</span></header>
    <p className="nerv-node-status-detail">{node.status.detail}</p>
    <div className="nerv-node-vitals">
      <Metric label="RX" value={formatRate(telemetry?.rx_bps ?? null)} />
      <Metric label="TX" value={formatRate(telemetry?.tx_bps ?? null)} />
      <Metric label="RTT" value={formatMetric(telemetry?.rtt_ms ?? null, ' ms')} />
      <Metric label="抖动" value={formatMetric(telemetry?.jitter_ms ?? null, ' ms')} />
      <Metric label="丢包" value={telemetry?.packet_loss_ppm == null ? '—' : `${(telemetry.packet_loss_ppm / 10_000).toFixed(2)}%`} />
      <Metric label="重连 / 切换" value={`${telemetry?.reconnects ?? '—'} / ${telemetry?.path_changes ?? '—'}`} />
    </div>
    <div className="nerv-readiness-bars"><ReadinessRow label="Peer 会话" value={peerPercent} detail={`${node.activePeers}/${node.configuredPeers}`} /><ReadinessRow label="路由就绪" value={routePercent} detail={`${node.readyRouteOwners}/${node.requiredRouteOwners}`} /></div>
    <footer><span>{node.telemetryState === 'stale' && telemetry ? formatStaleTelemetryAt(telemetry.reported_at, clock) : node.telemetryState === 'online' ? '遥测持续更新' : '尚未收到遥测'}</span><div>{telemetry?.local_networks.slice(0, 3).map((network) => <code key={network.network_id}>{network.cidr}</code>)}{(telemetry?.local_networks.length ?? 0) > 3 && <code>+{(telemetry?.local_networks.length ?? 0) - 3}</code>}</div></footer>
  </article>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function ReadinessRow({ label, value, detail }: { label: string; value: number; detail: string }) {
  return <div><span>{label}</span><div><i style={{ width: `${Math.max(0, Math.min(100, value))}%` }} /></div><strong>{detail}</strong></div>;
}

function LinkDashboard({ topology }: { topology: OperationalTopologySnapshot }) {
  return <div className="nerv-dashboard-view" role="tabpanel">
    <div className="nerv-resource-band">
      <ResourceDatum icon={<IconWifi />} label="站点" value={topology.sites.length} detail={topology.sites.map((site) => site.name).join('、') || '未接入'} />
      <ResourceDatum icon={<IconBranch />} label="互联" value={topology.links.length} detail={`${topology.activeLinkCount} 条已认证`} />
      <ResourceDatum icon={<IconStorage />} label="路由前缀" value={topology.routeCount} detail={topology.routeLabels.join('、') || '未发布'} mono />
      <ResourceDatum icon={<IconCloud />} label="互联网出口" value={topology.egressCount} detail={topology.egressLabels.join('、') || '未配置'} />
      <ResourceDatum icon={<IconThunderbolt />} label="策略 / DNS" value={topology.policyRuleCount} detail={`${topology.policyRuleCount} 条策略 · ${topology.dnsRecordCount} 条 DNS`} />
    </div>
    {topology.links.length === 0 ? <div className="nerv-view-empty"><Empty description="当前范围没有站点互联" /></div> : <div className="nerv-link-grid">{topology.links.map((link) => <LinkMonitorCard key={link.id} link={link} />)}</div>}
  </div>;
}

function ResourceDatum({ icon, label, value, detail, mono = false }: { icon: React.ReactNode; label: string; value: number; detail: string; mono?: boolean }) {
  return <div><span>{icon}</span><small>{label}</small><strong>{value}</strong><p className={mono ? 'mono' : ''} title={detail}>{detail}</p></div>;
}

function LinkMonitorCard({ link }: { link: OperationalLink }) {
  return <article className={`nerv-link-card tone-${link.status.tone}`}>
    <header><div><small>{link.kindLabel} · {link.activePathCount} 条活跃路径</small><strong>{link.siteAName}<i>↔</i>{link.siteBName}</strong></div><span>{link.status.label}</span></header>
    <p>{link.status.detail}</p>
    <div className="nerv-link-direction"><span><strong>{link.activeDirectionCount} / 2</strong> 双向认证</span><span><strong>{link.staleDirectionCount}</strong> 方向数据过期</span></div>
    {link.activePaths.length === 0 ? <div className="nerv-path-empty">没有新鲜路径遥测</div> : <div className="nerv-path-list">{link.activePaths.map((path) => <section key={`${path.sourceSiteId}-${path.destinationSiteId}-${path.candidate_id ?? path.connection_epoch}`}>
      <header><strong>{path.sourceNodeName} → {path.destinationSiteId === link.siteAId ? link.siteAName : link.siteBName}</strong><span>{path.path_kind === 'relay' ? '中继' : '直连'} · {path.transport}</span></header>
      <div><Metric label="RTT" value={formatMetric(path.rtt_ms, ' ms')} /><Metric label="抖动" value={formatMetric(path.jitter_ms, ' ms')} /><Metric label="丢包" value={path.packet_loss_ppm == null ? '—' : `${(path.packet_loss_ppm / 10_000).toFixed(2)}%`} /><Metric label="RX" value={formatRate(path.rx_bps)} /><Metric label="TX" value={formatRate(path.tx_bps)} /></div>
    </section>)}</div>}
  </article>;
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
  return <><div className="topology-canvas" aria-label="SD-WAN 运行拓扑">
    <svg viewBox={`0 0 ${width} ${height}`} role="img" style={{ minWidth: width, height }}>
      <g className={`topology-control-node ${controlReady ? 'ok' : 'error'}`} transform={`translate(${center - 98} 20)`}>
        <rect width="196" height="48" rx="6" /><circle cx="20" cy="24" r="5" /><text x="34" y="21">Candy Cloud</text><text className="sub" x="34" y="36">控制面 · {controlReady ? '正常' : '异常'}</text>
      </g>
      {!aggregate && <>
        <line className="topology-control-link" x1={center} y1="68" x2={center} y2="92" />
        <g className={`topology-segment-node ${snapshot.readiness?.ready ? 'ok' : 'warn'}`} transform={`translate(${center - 120} 92)`}>
          <rect width="240" height="58" rx="7" /><text x="120" y="24" textAnchor="middle">{ellipsis(snapshot.segment?.name ?? '网络分段', 24)}</text><text className="sub" x="120" y="42" textAnchor="middle">{snapshot.segment?.overlayCidr} · {snapshot.readinessLabel}</text>
        </g>
      </>}
      {snapshot.sites.map((site, index) => {
        const x = siteX(index);
        return <g key={site.id}>
          <path className="topology-site-link" d={aggregate
            ? `M ${center} 68 C ${center} 105, ${x} 105, ${x} ${siteY}`
            : `M ${center} 150 C ${center} 174, ${x} 166, ${x} ${siteY}`} />
          <g className={`topology-site-node ${site.nodes.some((node) => node.status.tone === 'red') ? 'error' : site.nodes.some((node) => node.status.tone === 'orange') ? 'pending' : site.nodes.length > 0 ? 'ok' : 'neutral'}`} transform={`translate(${x - 90} ${siteY})`}>
            <rect width="180" height={siteCardHeight} rx="7" />
            <circle cx="18" cy="22" r="5" />
            <text className="site-name" x="31" y="26">{ellipsis(site.name, 19)}</text>
            <text className="sub" x="14" y="51">{site.kindLabel}</text>
            <line x1="14" y1="62" x2="166" y2="62" />
            <text x="14" y="83">节点 {site.nodes.length}</text><text className="value" x="166" y="83" textAnchor="end">在线 {site.onlineNodeCount}</text>
            <text x="14" y="106">数据面 {site.dataPlaneActiveNodeCount}</text><text className="value" x="166" y="106" textAnchor="end">路由 {site.routeCount} · 出口 {site.egressCount}</text>
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
  return <div className="status-boundary-legend" aria-label="节点与链路状态定义">
    {[{ label: '节点', items: NODE_STATUS_BOUNDARIES }, { label: '互联链路', items: LINK_STATUS_BOUNDARIES }].map((group) => <div key={group.label}>
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
  return formatStaleTelemetryAt(value, Date.now());
}

function formatStaleTelemetryAt(value: string, now: number): string {
  const reported = Date.parse(value);
  if (!Number.isFinite(reported)) return '';
  const seconds = Math.max(0, Math.round((now - reported) / 1000));
  return seconds <= 60 ? '' : `遥测 ${Math.floor(seconds / 60)} 分钟未更新`;
}
