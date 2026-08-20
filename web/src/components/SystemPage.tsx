import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Descriptions, Empty, Input, Select, Spin, Table, Tabs, Tag, Typography } from '@arco-design/web-react';
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

export function SystemPage({ session, initialTab = 'status' }: Props) {
  const [health, setHealth] = useState(emptyHealth);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [levelFilter, setLevelFilter] = useState<'all' | LogLevel>('all');
  const [actionFilter, setActionFilter] = useState('');
  const [textFilter, setTextFilter] = useState('');
  const [loading, setLoading] = useState(true);

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
      <Tabs defaultActiveTab={initialTab} className="system-tabs">
        <Tabs.TabPane key="status" title="运行状态"><Spin loading={loading} block>
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
        </Spin></Tabs.TabPane>
        <Tabs.TabPane key="logs" title="统一日志">
          <div className="log-toolbar"><div><Typography.Text bold>运行日志</Typography.Text><Typography.Text type="secondary">默认读取最近 200 条，可按级别、事件类型和内容过滤</Typography.Text></div><Typography.Text type="secondary">{filtered.length} / {events.length} 条</Typography.Text></div>
          <div className="log-filters">
            <Select value={levelFilter} onChange={(value) => setLevelFilter(value as typeof levelFilter)} aria-label="日志级别" style={{ width: 140 }}><Select.Option value="all">全部级别</Select.Option><Select.Option value="error">错误</Select.Option><Select.Option value="warning">警告</Select.Option><Select.Option value="info">信息</Select.Option></Select>
            <Select value={actionFilter} onChange={setActionFilter} placeholder="全部事件" allowClear style={{ width: 240 }}>{actionOptions.map((action) => <Select.Option key={action} value={action}>{action}</Select.Option>)}</Select>
            <Input.Search value={textFilter} onChange={setTextFilter} allowClear placeholder="搜索事件、对象或详情" style={{ width: 280 }} />
          </div>
          {auditError && <div className="log-warning"><Tag color="orange">读取异常</Tag><Typography.Text type="secondary">{auditError}</Typography.Text></div>}
          <div className="table-surface operation-log-table">{filtered.length === 0 && !loading ? <Empty description={events.length ? '没有符合筛选条件的日志' : '暂无运行日志'} /> : <Table rowKey="id" loading={loading} data={filtered} pagination={filtered.length > 50 ? { pageSize: 50, sizeCanChange: true } : false} expandedRowRender={(item: AuditEvent) => <pre className="log-details">{item.metadata_json || '{}'}</pre>} columns={[
            { title: '级别', width: 88, render: (_: unknown, item: AuditEvent) => { const meta = levelMeta[eventLevel(item.action)]; return <Tag color={meta.color}>{meta.label}</Tag>; } },
            { title: '事件', dataIndex: 'action', width: 280, render: (value: string, item: AuditEvent) => <div className="log-event-cell"><strong>{value}</strong><small>{item.object_type}{item.object_id ? ` · ${item.object_id.slice(0, 8)}…` : ''}</small></div> },
            { title: '来源', width: 130, render: (_: unknown, item: AuditEvent) => item.actor_type },
            { title: '发生时间', width: 200, render: (_: unknown, item: AuditEvent) => new Date(item.created_at).toLocaleString() },
          ]} />}</div>
        </Tabs.TabPane>
      </Tabs>
    </section>
  );
}
