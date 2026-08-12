import { useCallback, useEffect, useState } from 'react';
import { Button, Descriptions, Spin, Tag, Typography } from '@arco-design/web-react';
import { IconRefresh } from '@arco-design/web-react/icon';
import { fetchHealth } from '../api';
import type { HealthState, Session } from '../types';

const emptyHealth: HealthState = {
  live: { status: null, text: '', loading: true, checkedAt: null },
  ready: { status: null, text: '', loading: true, checkedAt: null },
  degraded: { status: null, text: '', loading: true, checkedAt: null },
};

export function SystemPage({ session }: { session: Session }) {
  const [health, setHealth] = useState(emptyHealth);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    const [live, ready, degraded] = await Promise.all([fetchHealth('live'), fetchHealth('ready'), fetchHealth('degraded')]);
    setHealth({ live, ready, degraded });
    setLoading(false);
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <section className="workspace-section">
      <header className="page-header">
        <div><Typography.Title heading={4}>系统</Typography.Title><Typography.Text type="secondary">控制面依赖与当前会话</Typography.Text></div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      <Spin loading={loading} block>
        <div className="system-grid">
          <section className="detail-surface">
            <Typography.Title heading={5}>健康端点</Typography.Title>
            <Descriptions
              column={1}
              data={(['live', 'ready', 'degraded'] as const).map((key) => ({
                label: `/api/health/${key}`,
                value: <span><Tag color={health[key].status === 200 ? 'green' : health[key].status === null ? 'red' : 'orange'}>{health[key].status ?? 'OFFLINE'}</Tag> {health[key].text || '—'}</span>,
              }))}
            />
          </section>
          <section className="detail-surface">
            <Typography.Title heading={5}>管理会话</Typography.Title>
            <Descriptions column={1} data={[
              { label: 'Actor', value: session.claims.sub ?? '未提供' },
              { label: 'Tenant', value: <span className="mono break-all">{session.claims.tenant_id ?? '未提供'}</span> },
              { label: 'Organization', value: <span className="mono break-all">{session.claims.organization_id ?? '未提供'}</span> },
              { label: 'Role', value: session.claims.role ?? '未提供' },
              { label: 'Expires', value: session.claims.exp ? new Date(session.claims.exp * 1000).toLocaleString() : '未提供' },
            ]} />
          </section>
        </div>
      </Spin>
    </section>
  );
}
