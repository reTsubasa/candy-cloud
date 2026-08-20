import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Descriptions, Drawer, Empty, Input, Select, Spin, Table, Tabs, Tag, Typography } from '@arco-design/web-react';
import { IconRefresh } from '@arco-design/web-react/icon';
import { fetchHealth, listAuditEvents } from '../api';
import type { AuditEvent, HealthState, Session } from '../types';

const healthMeta = {
  live: { label: '服务进程', endpoint: '/api/health/live' },
  ready: { label: '对外服务', endpoint: '/api/health/ready' },
  degraded: { label: '依赖状态', endpoint: '/api/health/degraded' },
};

const emptyHealth: HealthState = {
  live: { status: null, text: '', loading: true, checkedAt: null },
  ready: { status: null, text: '', loading: true, checkedAt: null },
  degraded: { status: null, text: '', loading: true, checkedAt: null },
};

type Props = { session: Session; initialTab?: 'status' | 'logs' };
type LogLevel = 'error' | 'warning' | 'info';

function eventLevel(action: string): LogLevel {
  const normalized = action.toUpperCase();
  if (/(FAILED|FAILURE|REJECTED|ERROR|DENIED)/.test(normalized)) return 'error';
  if (/(REVOKED|EXPIRED|DEGRADED|DISABLED)/.test(normalized)) return 'warning';
  return 'info';
}

const levelMeta = {
  error: { label: '错误', color: 'red' },
  warning: { label: '警告', color: 'orange' },
  info: { label: '信息', color: 'arcoblue' },
} as const;

const eventLabels: Record<string, { title: string; detail: string }> = {
  IDENTITY_LOGIN_SUCCEEDED: { title: '登录成功', detail: '账户完成了身份验证并建立管理会话。' },
  IDENTITY_REFRESH_SUCCEEDED: { title: '会话刷新成功', detail: '管理会话已续期。' },
  IDENTITY_LOGIN_FAILED: { title: '登录失败', detail: '账户身份验证未通过。' },
  IDENTITY_REFRESH_FAILED: { title: '会话刷新失败', detail: '会话续期未完成，可能需要重新登录。' },
  SDWAN_SEGMENT_ROUTES_PUBLISHED: { title: '网络路由已发布', detail: 'Cloud 已生成并发布该网络分段的签名路由配置。' },
  CONTROL_NODE_IDENTITY_REPLACED: { title: '节点身份已更新', detail: '节点重新加入后，Cloud 已替换其设备身份。' },
  CONTROL_NODE_ENROLLED: { title: '节点已加入', detail: '节点完成注册并加入当前租户。' },
  CONTROL_RESOURCE_CREATED: { title: '配置已创建', detail: '控制面创建了一项新的网络配置。' },
  CONTROL_RESOURCE_UPDATED: { title: '配置已更新', detail: '控制面更新了一项网络配置。' },
  CONTROL_RESOURCE_DELETED: { title: '配置已删除', detail: '控制面删除了一项网络配置。' },
  RUNTIME_CONFIGURATION_REJECTED: { title: '节点拒绝配置', detail: '节点收到配置后未能应用，需检查节点运行日志。' },
};

const objectLabels: Record<string, string> = {
  HUMAN_ACCOUNT: '用户账户', DEVICE: '节点', NODE: '节点', SEGMENT: '网络分段',
  SITE: '站点', PEER: '站点互联', PATH_CANDIDATE: '线路', EGRESS: '出口',
  SERVICE_POLICY: '策略', DNS_INTENT: 'DNS',
};

const actorLabels: Record<string, string> = {
  HUMAN_ACCOUNT: '用户', USER: '用户', WORKER: 'Cloud Worker', DEVICE: '节点', SYSTEM: '系统',
};

function eventLabel(action: string): string {
  if (eventLabels[action]) return eventLabels[action].title;
  return action.toLowerCase().split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

function eventDescription(action: string): string {
  return eventLabels[action]?.detail ?? '控制面记录了一项运行或配置事件。';
}

function objectLabel(value: string): string {
  return objectLabels[value] ?? value;
}

function actorLabel(value: string): string {
  return actorLabels[value] ?? value;
}

function formatEventTime(value: string, now = new Date()): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const time = date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  if (date.toDateString() === now.toDateString()) return '今天 ' + time;
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return '昨天 ' + time;
  return date.toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatMetadata(value: string): string {
  if (!value) return '暂无结构化详情';
  try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
}

export function SystemPage({ session, initialTab = 'status' }: Props) {
  const [health, setHealth] = useState(emptyHealth);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [levelFilter, setLevelFilter] = useState<'all' | LogLevel>('all');
  const [actionFilter, setActionFilter] = useState('');
  const [textFilter, setTextFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setAuditError(null);
    const [live, ready, degraded, audit] = await Promise.all([
      fetchHealth('live'), fetchHealth('ready'), fetchHealth('degraded'),
      session.claims.tenant_id ? listAuditEvents(session.token, session.claims.tenant_id).catch((error) => {
        setAuditError(error instanceof Error ? error.message : '统一日志暂不可用');
        return { schema_version: 1, items: [] };
      }) : Promise.resolve({ schema_version: 1, items: [] }),
    ]);
    setHealth({ live, ready, degraded });
    setEvents(audit.items);
    setLoading(false);
  }, [session.claims.tenant_id, session.token]);

  useEffect(() => { void load(); }, [load]);

  const actionOptions = useMemo(() => Array.from(new Set(events.map((event) => event.action))).sort(), [events]);
  const filtered = useMemo(() => events.filter((event) => {
    if (levelFilter !== 'all' && eventLevel(event.action) !== levelFilter) return false;
    if (actionFilter && event.action !== actionFilter) return false;
    if (textFilter) {
      const haystack = `${event.action} ${event.object_type} ${event.actor_type} ${event.metadata_json}`.toLowerCase();
      if (!haystack.includes(textFilter.toLowerCase())) return false;
    }
    return true;
  }), [actionFilter, events, levelFilter, textFilter]);

  return (
    <section className="workspace-section">
      <header className="page-header">
        <div><Typography.Title heading={4}>{initialTab === 'logs' ? '日志' : '系统'}</Typography.Title><Typography.Text type="secondary">{initialTab === 'logs' ? '控制面、配置与节点事件的统一记录' : '控制面状态与管理会话'}</Typography.Text></div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      <Tabs defaultActiveTab={initialTab} className="system-tabs single-tab">
        {initialTab !== 'logs' && <Tabs.TabPane key="status" title="运行状态"><Spin loading={loading} block>
          <div className="system-grid">
            <section className="detail-surface"><Typography.Title heading={5}>控制面健康</Typography.Title><Descriptions column={1} data={(['live', 'ready', 'degraded'] as const).map((key) => ({ label: healthMeta[key].label, value: <div className="health-detail"><span><Tag color={health[key].status === 200 ? 'green' : health[key].status === null ? 'red' : 'orange'}>{health[key].status === 200 ? '正常' : health[key].status === null ? '不可达' : '异常'}</Tag> {health[key].text || '—'}</span><code>{healthMeta[key].endpoint}</code></div> }))} /></section>
            <section className="detail-surface"><Typography.Title heading={5}>管理会话</Typography.Title><Descriptions column={1} data={[
              { label: '当前用户', value: session.user?.display_name ?? session.claims.sub ?? '未提供' },
              { label: '租户 ID', value: <span className="mono break-all">{session.claims.tenant_id ?? '未提供'}</span> },
              { label: '组织 ID', value: <span className="mono break-all">{session.claims.organization_id ?? '未提供'}</span> },
              { label: '访问角色', value: session.membership?.role ?? session.claims.role ?? '未提供' },
              { label: '会话到期', value: session.claims.exp ? new Date(session.claims.exp * 1000).toLocaleString() : '未提供' },
            ]} /></section>
          </div>
        </Spin></Tabs.TabPane>}
        {initialTab !== 'status' && <Tabs.TabPane key="logs" title="统一日志">
          <div className="log-toolbar"><div><Typography.Text bold>运行日志</Typography.Text><Typography.Text type="secondary">点击任意记录查看完整内容 · 最近 {events.length} 条</Typography.Text></div><Typography.Text type="secondary">{filtered.length} / {events.length} 条</Typography.Text></div>
          <div className="log-filters">
            <Select value={levelFilter} onChange={(value) => setLevelFilter(value as typeof levelFilter)} aria-label="日志级别" style={{ width: 140 }}><Select.Option value="all">全部级别</Select.Option><Select.Option value="error">错误</Select.Option><Select.Option value="warning">警告</Select.Option><Select.Option value="info">信息</Select.Option></Select>
            <Select value={actionFilter} onChange={setActionFilter} placeholder="全部事件" allowClear style={{ width: 240 }}>{actionOptions.map((action) => <Select.Option key={action} value={action}>{action}</Select.Option>)}</Select>
            <Input.Search value={textFilter} onChange={setTextFilter} allowClear placeholder="搜索事件、对象或详情" style={{ width: 280 }} />
          </div>
          {auditError && <div className="log-warning"><Tag color="orange">读取异常</Tag><Typography.Text type="secondary">{auditError}</Typography.Text></div>}
          <div className="table-surface operation-log-table">{filtered.length === 0 && !loading ? <Empty description={events.length ? '没有符合筛选条件的日志' : '暂无运行日志'} /> : <Table rowKey="id" loading={loading} data={filtered} pagination={filtered.length > 50 ? { pageSize: 50, sizeCanChange: true } : false} onRow={(item) => ({ onClick: () => setSelectedEvent(item), className: 'log-row-clickable' })} columns={[
            { title: '级别', width: 88, render: (_: unknown, item: AuditEvent) => { const meta = levelMeta[eventLevel(item.action)]; return <Tag color={meta.color}>{meta.label}</Tag>; } },
            { title: '事件', dataIndex: 'action', width: 330, render: (value: string, item: AuditEvent) => <div className="log-event-cell"><strong>{eventLabel(value)}</strong><small>{eventDescription(value)}</small><code>{value}</code></div> },
            { title: '对象', width: 150, render: (_: unknown, item: AuditEvent) => <div className="log-object-cell"><strong>{objectLabel(item.object_type)}</strong><small>{item.object_id ? `${item.object_id.slice(0, 8)}…` : '全局事件'}</small></div> },
            { title: '来源', width: 130, render: (_: unknown, item: AuditEvent) => actorLabel(item.actor_type) },
            { title: '发生时间', width: 180, render: (_: unknown, item: AuditEvent) => <Typography.Text>{formatEventTime(item.created_at)}</Typography.Text> },
          ]} />}</div>
        </Tabs.TabPane>}
      </Tabs>
      <Drawer width={520} title={selectedEvent ? eventLabel(selectedEvent.action) : '日志详情'} visible={selectedEvent !== null} onCancel={() => setSelectedEvent(null)} footer={null}>
        {selectedEvent && <div className="log-detail-drawer">
          <div className="log-detail-summary"><Tag color={levelMeta[eventLevel(selectedEvent.action)].color}>{levelMeta[eventLevel(selectedEvent.action)].label}</Tag><div><strong>{eventDescription(selectedEvent.action)}</strong><span>{formatEventTime(selectedEvent.created_at)} · {new Date(selectedEvent.created_at).toLocaleString('zh-CN')}</span></div></div>
          <Descriptions column={1} data={[
            { label: '事件', value: <span>{eventLabel(selectedEvent.action)} <code>{selectedEvent.action}</code></span> },
            { label: '对象', value: objectLabel(selectedEvent.object_type) + (selectedEvent.object_id ? ` · ${selectedEvent.object_id}` : '') },
            { label: '来源', value: actorLabel(selectedEvent.actor_type) },
            { label: '操作者', value: selectedEvent.actor_id ?? '系统生成' },
            { label: '发生时间', value: new Date(selectedEvent.created_at).toLocaleString('zh-CN') },
          ]} />
          <Typography.Title heading={6}>完整事件内容</Typography.Title>
          <pre className="log-details log-detail-full">{formatMetadata(selectedEvent.metadata_json)}</pre>
        </div>}
      </Drawer>
    </section>
  );
}
