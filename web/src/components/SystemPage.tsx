import { useCallback, useEffect, useState } from 'react';
import { Button, Descriptions, Empty, Spin, Table, Tabs, Tag, Typography } from '@arco-design/web-react';
import { IconRefresh } from '@arco-design/web-react/icon';
import { fetchHealth, listNodeJoinCodes } from '../api';
import type { EnrollmentActivation, HealthState, Session } from '../types';

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

export function SystemPage({ session }: { session: Session }) {
  const [health, setHealth] = useState(emptyHealth);
  const [enrollmentEvents, setEnrollmentEvents] = useState<EnrollmentActivation[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    const [live, ready, degraded, events] = await Promise.all([
      fetchHealth('live'), fetchHealth('ready'), fetchHealth('degraded'),
      session.claims.tenant_id ? listNodeJoinCodes(session.token, session.claims.tenant_id).catch(() => []) : Promise.resolve([]),
    ]);
    setHealth({ live, ready, degraded });
    setEnrollmentEvents(events);
    setLoading(false);
  }, [session.claims.tenant_id, session.token]);
  useEffect(() => { void load(); }, [load]);

  return (
    <section className="workspace-section">
      <header className="page-header">
        <div><Typography.Title heading={4}>系统</Typography.Title><Typography.Text type="secondary">控制面状态、管理会话与操作日志</Typography.Text></div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      <Tabs defaultActiveTab="status" className="system-tabs">
        <Tabs.TabPane key="status" title="运行状态"><Spin loading={loading} block>
          <div className="system-grid">
          <section className="detail-surface">
            <Typography.Title heading={5}>控制面健康</Typography.Title>
            <Descriptions
              column={1}
              data={(['live', 'ready', 'degraded'] as const).map((key) => ({
                label: healthMeta[key].label,
                value: <div className="health-detail"><span><Tag color={health[key].status === 200 ? 'green' : health[key].status === null ? 'red' : 'orange'}>{health[key].status === 200 ? '正常' : health[key].status === null ? '不可达' : '异常'}</Tag> {health[key].text || '—'}</span><code>{healthMeta[key].endpoint}</code></div>,
              }))}
            />
          </section>
          <section className="detail-surface">
            <Typography.Title heading={5}>管理会话</Typography.Title>
            <Descriptions column={1} data={[
              { label: '当前用户', value: session.user?.display_name ?? session.claims.sub ?? '未提供' },
              { label: '租户 ID', value: <span className="mono break-all">{session.claims.tenant_id ?? '未提供'}</span> },
              { label: '组织 ID', value: <span className="mono break-all">{session.claims.organization_id ?? '未提供'}</span> },
              { label: '访问角色', value: session.membership?.role ?? session.claims.role ?? '未提供' },
              { label: '会话到期', value: session.claims.exp ? new Date(session.claims.exp * 1000).toLocaleString() : '未提供' },
            ]} />
          </section>
          </div>
        </Spin></Tabs.TabPane>
        <Tabs.TabPane key="logs" title="日志">
          <div className="toolbar-row"><div><Typography.Text bold>节点加入</Typography.Text><Typography.Text type="secondary">节点注册、使用、撤销和过期记录</Typography.Text></div><Typography.Text type="secondary">{enrollmentEvents.length} 条</Typography.Text></div>
          <div className="table-surface operation-log-table">{enrollmentEvents.length === 0 && !loading ? <Empty description="暂无节点加入记录" /> : <Table rowKey="id" loading={loading} data={enrollmentEvents} pagination={enrollmentEvents.length > 20 ? { pageSize: 20, sizeCanChange: false } : false} columns={[
            { title: '类型', width: 120, render: () => <Tag color="arcoblue">节点加入</Tag> },
            { title: '设备', render: (_: unknown, item: EnrollmentActivation) => item.display_name ?? '未完成注册的设备' },
            { title: '结果', width: 120, render: (_: unknown, item: EnrollmentActivation) => <Tag color={item.status === 'CONSUMED' ? 'green' : item.status === 'ACTIVE' || item.status === 'RESERVED' ? 'orange' : 'gray'}>{({ ACTIVE: '等待设备', RESERVED: '注册中', CONSUMED: '已完成', REVOKED: '已撤销', EXPIRED: '已过期' } as const)[item.status]}</Tag> },
            { title: '发生时间', width: 200, render: (_: unknown, item: EnrollmentActivation) => new Date(item.consumed_at ?? item.reserved_at ?? item.created_at).toLocaleString() },
          ]} />}</div>
        </Tabs.TabPane>
      </Tabs>
    </section>
  );
}
