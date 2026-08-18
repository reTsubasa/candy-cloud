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
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import type { ControlResource, HealthState, RuntimeActivationReadiness, RuntimeConfigurationStatus, RuntimeTelemetry, Session } from '../types';
import { QuickSetupWizard } from './QuickSetupWizard';

type Props = { session: Session };

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

function relativeTime(value: Date | null): string {
  if (!value) return '尚未更新';
  const seconds = Math.max(0, Math.floor((Date.now() - value.getTime()) / 1000));
  if (seconds < 5) return '刚刚更新';
  if (seconds < 60) return `${seconds} 秒前更新`;
  return `${Math.floor(seconds / 60)} 分钟前更新`;
}

function controlPlaneDetail(health: HealthState): string {
  if (health.ready.status === 200) return 'API、身份与存储已通过就绪检查';
  if (health.ready.status === null) return '无法连接控制面健康检查';
  return '至少一项控制面依赖尚未就绪';
}

export function Overview({ session }: Props) {
  const [resources, setResources] = useState<OperationalResources>(emptyOperationalResources);
  const [resourceErrors, setResourceErrors] = useState<ResourceLoadErrors>({});
  const [statuses, setStatuses] = useState<RuntimeConfigurationStatus[]>([]);
  const [telemetry, setTelemetry] = useState<RuntimeTelemetry[]>([]);
  const [telemetryStaleAfter, setTelemetryStaleAfter] = useState(90);
  const [telemetryAvailable, setTelemetryAvailable] = useState(true);
  const [readiness, setReadiness] = useState<Record<string, RuntimeActivationReadiness>>({});
  const [health, setHealth] = useState<HealthState>(initialHealth);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
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
        .catch(() => ({ result: { schema_version: 1, stale_after_seconds: 90, items: [] as RuntimeTelemetry[] }, available: false })),
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
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => void load(true), 10_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);
  useEffect(() => {
    const available = resources.segments.some((segment) => segment.metadata.id === selectedSegmentId);
    if (!available) setSelectedSegmentId(resources.segments[0]?.metadata.id ?? '');
  }, [resources.segments, selectedSegmentId]);

  const topology = useMemo(
    () => buildOperationalTopology(resources, statuses, readiness, selectedSegmentId, telemetry, telemetryStaleAfter),
    [readiness, resources, selectedSegmentId, statuses, telemetry, telemetryStaleAfter],
  );
  const controlReady = health.ready.status === 200;
  const resourceErrorCount = Object.keys(resourceErrors).length;
  const incidents = useMemo(() => {
    const items: Array<{ tone: 'error' | 'warn'; title: string; detail: string }> = [];
    if (!controlReady) items.push({ tone: 'error', title: '控制面未就绪', detail: controlPlaneDetail(health) });
    if (health.degraded.status !== null && health.degraded.status !== 200) items.push({ tone: 'warn', title: '控制面依赖降级', detail: '依赖探针返回异常状态，请在系统页查看具体服务' });
    if (resourceErrorCount > 0) items.push({ tone: 'error', title: '资源读取不完整', detail: `${resourceErrorCount} 类资源读取失败，拓扑仅显示已验证数据` });
    if (!telemetryAvailable) items.push({ tone: 'warn', title: '运行遥测不可用', detail: '无法读取 Runtime 最新状态，在线状态不会被推测' });
    for (const node of topology.nodes.filter((item) => item.applyState === 'rejected')) {
      items.push({ tone: 'error', title: `${node.name} 配置被拒绝`, detail: node.errorCode || '节点未提供具体错误码' });
    }
    if (topology.segment && topology.readiness && !topology.readiness.ready) {
      items.push({ tone: 'warn', title: `${topology.segment.name} 尚未完全激活`, detail: topology.readinessLabel });
    }
    for (const node of topology.nodes.filter((item) => item.failOpenRequired)) {
      items.push({ tone: 'error', title: `${node.name} 已故障开放`, detail: node.telemetry?.last_error_code || 'Candy 数据面已退出，基础网络保持可用' });
    }
    for (const node of topology.nodes.filter((item) => item.telemetryState === 'online'
      && !item.failOpenRequired && ['degraded', 'stopped', 'unknown'].includes(item.lifecycle ?? ''))) {
      items.push({ tone: 'warn', title: `${node.name} 数据面未活跃`, detail: node.telemetry?.last_error_code || `Runtime 状态：${node.lifecycle ?? 'unknown'}` });
    }
    for (const node of topology.nodes.filter((item) => item.telemetryState === 'stale')) {
      items.push({ tone: 'warn', title: `${node.name} 遥测中断`, detail: `超过 ${telemetryStaleAfter} 秒没有收到运行状态` });
    }
    return items.slice(0, 6);
  }, [controlReady, health, resourceErrorCount, telemetryAvailable, telemetryStaleAfter, topology]);

  return (
    <section className="workspace-section operational-overview">
      <header className="page-header operational-header">
        <div>
          <Typography.Title heading={4}>网络运营中心</Typography.Title>
          <Typography.Text type="secondary">控制面与数据面运行拓扑</Typography.Text>
        </div>
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
          <StatusMetric icon={<IconDesktop />} label="在线节点" value={`${topology.onlineNodeCount} / ${topology.nodes.length}`} detail={`${topology.dataPlaneActiveNodeCount} 个数据面活跃 · ${topology.failOpenNodeCount} 个故障开放`} tone={topology.failOpenNodeCount > 0 ? 'error' : topology.nodes.length === 0 ? 'neutral' : topology.onlineNodeCount === topology.nodes.length ? 'ok' : 'warn'} />
          <StatusMetric icon={<IconBranch />} label="互联编排" value={`${topology.activeLinkCount} / ${topology.links.length}`} detail={`${topology.pathCount} 条线路已编排 · ${topology.nodes.reduce((sum, node) => sum + node.activePeers, 0)} 个活跃 Peer`} tone={topology.links.length === 0 ? 'neutral' : topology.activeLinkCount === topology.links.length ? 'ok' : 'warn'} />
          <StatusMetric icon={<IconStorage />} label="路由与出口" value={`${topology.routeCount} 条路由`} detail={`${topology.egressCount} 个出口 · ${topology.policyRuleCount} 条策略规则`} tone="neutral" />
          <StatusMetric icon={<IconThunderbolt />} label="性能遥测" value={topology.nodes.length > 0 ? `${topology.telemetryCoverageCount} / ${topology.nodes.length}` : '未接入'} detail={!telemetryAvailable ? 'Cloud 遥测接口当前不可用' : topology.telemetryCoverageCount > 0 ? '仅统计新鲜且有来源的性能样本' : 'Runtime 在线状态已接入，等待 Core 性能指标'} tone="neutral" />
        </div>

        <div className="operational-layout">
          <section className="topology-workspace">
            <header className="topology-toolbar">
              <div>
                <Typography.Title heading={5}>实时网络拓扑</Typography.Title>
                <span className="topology-update-state"><i className={autoRefresh ? 'active' : ''} />{relativeTime(lastUpdated)}{refreshing ? ' · 同步中' : ''}</span>
              </div>
              <Select
                value={selectedSegmentId || undefined}
                onChange={setSelectedSegmentId}
                options={resources.segments.map((segment) => ({ label: String(segment.resource.spec.name ?? segment.metadata.id), value: segment.metadata.id }))}
                placeholder="选择网络分段"
                className="segment-selector"
              />
            </header>
            {topology.segment ? <TopologyCanvas snapshot={topology} controlReady={controlReady} /> : (
              <div className="topology-empty"><Empty description="尚未建立可展示的网络分段" /><Button type="primary" onClick={() => setSetupVisible(true)}>开始配置</Button></div>
            )}
          </section>

          <aside className="telemetry-rail">
            <section>
              <header><strong>运行事件</strong><Tag color={incidents.length > 0 ? 'orange' : 'green'}>{incidents.length > 0 ? `${incidents.length} 项关注` : '无异常'}</Tag></header>
              {incidents.length === 0 ? <div className="quiet-state"><IconCheckCircle /><span>当前未发现控制面或配置应用异常</span></div> : (
                <div className="incident-list">{incidents.map((incident, index) => <div className={`incident-item ${incident.tone}`} key={`${incident.title}-${index}`}><i /><div><strong>{incident.title}</strong><span>{incident.detail}</span></div></div>)}</div>
              )}
            </section>
            <section>
              <header><strong>数据面遥测</strong><Tag color={topology.onlineNodeCount > 0 ? 'green' : 'gray'}>{topology.onlineNodeCount > 0 ? `${topology.onlineNodeCount} 个节点在线` : '无新鲜上报'}</Tag></header>
              <div className="telemetry-grid">
                <div><span>往返时延</span><strong>{formatMetric(topology.averageRttMs, ' ms')}</strong></div>
                <div><span>丢包</span><strong>{topology.averagePacketLossPpm === null ? '—' : `${(topology.averagePacketLossPpm / 10_000).toFixed(2)}%`}</strong></div>
                <div><span>接收速率</span><strong>{formatRate(topology.rxBps)}</strong></div>
                <div><span>发送速率</span><strong>{formatRate(topology.txBps)}</strong></div>
              </div>
              <p className="telemetry-source-note">在线、故障开放、Peer 与路由状态来自 Runtime 心跳；时延、丢包和速率仅在 Core 提供真实采样时显示。</p>
            </section>
            <section>
              <header><strong>控制面探针</strong><span className="probe-time">{relativeTime(lastUpdated)}</span></header>
              <div className="probe-list">{(['live', 'ready', 'degraded'] as const).map((key) => {
                const meta = healthLabel(health[key].status);
                return <div key={key}><span><i className={meta.tone} />{key}</span><strong>{meta.label}</strong></div>;
              })}</div>
            </section>
          </aside>
        </div>

        {topology.segment && <section className="resource-observability">
          <header><div><Typography.Title heading={5}>资源与路由状态</Typography.Title><Typography.Text type="secondary">当前分段的实际配置关系</Typography.Text></div><Tag color={topology.readiness?.ready ? 'green' : 'orange'}>{topology.readinessLabel}</Tag></header>
          <div className="resource-observability-grid">
            <ResourceSignal label="站点" value={topology.sites.length} detail={topology.sites.map((site) => site.name).join('、') || '未接入'} />
            <ResourceSignal label="节点" value={topology.nodes.length} detail={`${topology.onlineNodeCount} 个在线 · ${topology.activeNodeCount} 个配置已生效`} />
            <ResourceSignal label="路由前缀" value={topology.routeCount} detail={topology.routeLabels.join('、') || '未发布'} mono />
            <ResourceSignal label="互联网出口" value={topology.egressCount} detail={topology.egressLabels.join('、') || '未配置'} />
            <ResourceSignal label="流量策略" value={topology.policyRuleCount} detail={`${resources.policies.filter((item) => String(item.resource.spec.segment_id ?? '') === topology.segment?.id).length} 个策略版本`} />
            <ResourceSignal label="DNS" value={topology.dnsRecordCount} detail={`${topology.dnsZoneCount} 个内部区域`} />
          </div>
        </section>}
      </Spin>
      <QuickSetupWizard visible={setupVisible} session={session} onClose={() => { setSetupVisible(false); void load(); }} onChanged={() => void load()} />
    </section>
  );
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
  const height = 470;
  const center = width / 2;
  const siteX = (index: number) => siteCount <= 1 ? center : 100 + index * ((width - 200) / (siteCount - 1));
  const siteById = Object.fromEntries(snapshot.sites.map((site, index) => [site.id, { ...site, x: siteX(index) }]));
  return <div className="topology-canvas" aria-label="SD-WAN 运行拓扑">
    <svg viewBox={`0 0 ${width} ${height}`} role="img" style={{ minWidth: width }}>
      <defs>
        <marker id="topology-arrow-ok" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#00a870" /></marker>
        <marker id="topology-arrow-warn" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#d97706" /></marker>
      </defs>
      <line className="topology-control-link" x1={center} y1="67" x2={center} y2="112" />
      <g className={`topology-control-node ${controlReady ? 'ok' : 'error'}`} transform={`translate(${center - 98} 20)`}>
        <rect width="196" height="48" rx="6" /><circle cx="20" cy="24" r="5" /><text x="34" y="21">Candy Cloud</text><text className="sub" x="34" y="36">控制面 · {controlReady ? '正常' : '异常'}</text>
      </g>
      <g className={`topology-segment-node ${snapshot.readiness?.ready ? 'ok' : 'warn'}`} transform={`translate(${center - 120} 112)`}>
        <rect width="240" height="58" rx="7" /><text x="120" y="24" textAnchor="middle">{ellipsis(snapshot.segment?.name ?? '网络分段', 24)}</text><text className="sub" x="120" y="42" textAnchor="middle">{snapshot.segment?.overlayCidr} · {snapshot.readinessLabel}</text>
      </g>
      {snapshot.sites.map((site, index) => {
        const x = siteX(index);
        return <g key={site.id}>
          <path className="topology-site-link" d={`M ${center} 170 C ${center} 205, ${x} 190, ${x} 236`} />
          <g className={`topology-site-node ${site.failOpenNodeCount > 0 || site.hasRejectedNode ? 'error' : site.dataPlaneActiveNodeCount > 0 ? 'ok' : 'pending'}`} transform={`translate(${x - 90} 236)`}>
            <rect width="180" height="152" rx="7" />
            <circle cx="18" cy="22" r="5" />
            <text className="site-name" x="31" y="26">{ellipsis(site.name, 19)}</text>
            <text className="sub" x="14" y="51">{site.kindLabel}</text>
            <line x1="14" y1="62" x2="166" y2="62" />
            <text x="14" y="83">节点 {site.nodes.length}</text><text className="value" x="166" y="83" textAnchor="end">在线 {site.onlineNodeCount}</text>
            <text x="14" y="106">数据面 {site.dataPlaneActiveNodeCount}</text><text className="value" x="166" y="106" textAnchor="end">路由 {site.routeCount} · 出口 {site.egressCount}</text>
            <text className="sub" x="14" y="132">{ellipsis(site.nodeNames.join(' · ') || '等待节点接入', 26)}</text>
          </g>
        </g>;
      })}
      {snapshot.links.map((link) => {
        const source = siteById[link.siteAId];
        const target = siteById[link.siteBId];
        if (!source || !target) return null;
        const left = source.x < target.x ? source : target;
        const right = source.x < target.x ? target : source;
        const y = 220 - Math.min(36, Math.abs(right.x - left.x) / 12);
        const tone = link.state === 'active' ? 'ok' : 'warn';
        const activePath = link.activePaths[0];
        const pathDetail = activePath
          ? ` · RTT ${activePath.rtt_ms == null ? '--' : `${activePath.rtt_ms} ms`} · 丢包 ${activePath.packet_loss_ppm == null ? '--' : `${(activePath.packet_loss_ppm / 10_000).toFixed(2)}%`}`
          : '';
        return <g className={`topology-peer-link ${tone}`} key={link.id}>
          <title>{link.activePathCount > 0 ? `数据面活跃 · ${link.activePathCount} 条路径 · ${link.kindLabel}${pathDetail}` : '已编排，等待节点数据面遥测'}</title>
          <path d={`M ${left.x} 236 C ${left.x} ${y}, ${right.x} ${y}, ${right.x} 236`} markerEnd={`url(#topology-arrow-${tone})`} />
          <rect x={(left.x + right.x) / 2 - 52} y={y - 13} width="104" height="24" rx="12" />
          <text x={(left.x + right.x) / 2} y={y + 4} textAnchor="middle">{link.activePathCount > 0 ? `${link.activePathCount} 条活跃` : `${link.directionCount}/2 · ${link.kindLabel}`}</text>
        </g>;
      })}
      <g className="topology-legend" transform={`translate(${center - 225} 430)`}>
        <circle className="ok" cx="6" cy="6" r="5" /><text x="17" y="10">数据面活跃</text>
        <circle className="warn" cx="126" cy="6" r="5" /><text x="137" y="10">等待或遥测中断</text>
        <circle className="error" cx="286" cy="6" r="5" /><text x="297" y="10">故障开放或配置拒绝</text>
      </g>
    </svg>
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
