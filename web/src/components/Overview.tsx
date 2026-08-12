import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Progress, Spin, Tag, Typography } from '@arco-design/web-react';
import { IconCheckCircle, IconExclamationCircle, IconRefresh } from '@arco-design/web-react/icon';
import { fetchHealth, listResources } from '../api';
import { resourceDefinitions } from '../resource-definitions';
import type { HealthState, Session } from '../types';

type Props = { session: Session };
type CountState = { value: number; capped: boolean; error?: string };

const initialHealth: HealthState = {
  live: { status: null, text: '', loading: true, checkedAt: null },
  ready: { status: null, text: '', loading: true, checkedAt: null },
  degraded: { status: null, text: '', loading: true, checkedAt: null },
};

function healthLabel(status: number | null): { label: string; color: string } {
  if (status !== null && status >= 200 && status < 300) return { label: '正常', color: 'green' };
  if (status === null) return { label: '不可达', color: 'red' };
  return { label: '异常', color: 'orange' };
}

export function Overview({ session }: Props) {
  const [counts, setCounts] = useState<Record<string, CountState>>({});
  const [health, setHealth] = useState<HealthState>(initialHealth);
  const [loading, setLoading] = useState(true);
  const tenantId = session.claims.tenant_id;

  const load = useCallback(async () => {
    setLoading(true);
    setHealth(initialHealth);
    const healthPromise = Promise.all(['live', 'ready', 'degraded'].map((name) => fetchHealth(name as 'live' | 'ready' | 'degraded')))
      .then(([live, ready, degraded]) => setHealth({ live, ready, degraded }));
    if (!tenantId) {
      setCounts({});
      await healthPromise;
      setLoading(false);
      return;
    }
    const countEntries = await Promise.all(resourceDefinitions.map(async (definition) => {
      try {
        const response = await listResources(session.token, tenantId, definition.collection);
        return [definition.key, { value: response.items.length, capped: Boolean(response.next_cursor) }] as const;
      } catch (reason) {
        return [definition.key, { value: 0, capped: false, error: reason instanceof Error ? reason.message : '加载失败' }] as const;
      }
    }));
    setCounts(Object.fromEntries(countEntries));
    await healthPromise;
    setLoading(false);
  }, [session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);

  const configured = useMemo(() => Object.values(counts).filter((item) => !item.error && item.value > 0).length, [counts]);
  const errors = useMemo(() => Object.values(counts).filter((item) => item.error).length, [counts]);
  const ready = health.ready.status === 200;

  return (
    <section className="workspace-section overview-page">
      <header className="page-header">
        <div>
          <Typography.Title heading={4}>运营概览</Typography.Title>
          <Typography.Text type="secondary">租户资源与控制面实时状态</Typography.Text>
        </div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      {!tenantId && <Alert type="error" showIcon content="JWT 中缺少 tenant_id，资源概览不可用。" />}
      <Spin loading={loading} block>
        <div className="overview-grid">
          <article className="summary-band primary-summary">
            <div>
              <span className="summary-label">控制面</span>
              <div className="summary-value-row">
                {ready ? <IconCheckCircle className="status-icon ok" /> : <IconExclamationCircle className="status-icon warn" />}
                <Typography.Title heading={3}>{ready ? '可投入运行' : '未就绪'}</Typography.Title>
              </div>
              <Typography.Text type="secondary">{health.ready.text || '正在检查就绪状态'}</Typography.Text>
            </div>
            <div className="summary-health-list">
              {(['live', 'ready', 'degraded'] as const).map((key) => {
                const state = health[key];
                const meta = healthLabel(state.status);
                return <div key={key}><span>{key}</span><Tag color={meta.color}>{meta.label}</Tag></div>;
              })}
            </div>
          </article>
          <article className="summary-band compact-summary">
            <span className="summary-label">已配置资源域</span>
            <Typography.Title heading={2}>{configured}<small> / {resourceDefinitions.length}</small></Typography.Title>
            <Progress percent={Math.round((configured / resourceDefinitions.length) * 100)} showText={false} color="#165dff" />
          </article>
          <article className="summary-band compact-summary">
            <span className="summary-label">读取异常</span>
            <Typography.Title heading={2}>{errors}</Typography.Title>
            <Typography.Text type="secondary">仅统计本次真实 API 请求结果</Typography.Text>
          </article>
        </div>
        <div className="section-heading-row">
          <div>
            <Typography.Title heading={5}>资源清单</Typography.Title>
            <Typography.Text type="secondary">单集合最多读取 200 项，存在后续页时显示 200+</Typography.Text>
          </div>
        </div>
        {Object.keys(counts).length === 0 && !loading ? <Empty description="没有可展示的租户资源" /> : (
          <div className="inventory-grid">
            {resourceDefinitions.map((definition) => {
              const count = counts[definition.key];
              return (
                <article className="inventory-row" key={definition.key}>
                  <div>
                    <Typography.Text bold>{definition.label}</Typography.Text>
                    <Typography.Text type="secondary">{definition.description}</Typography.Text>
                  </div>
                  {count?.error ? <Tag color="red">读取失败</Tag> : <strong>{count ? `${count.value}${count.capped ? '+' : ''}` : '—'}</strong>}
                </article>
              );
            })}
          </div>
        )}
      </Spin>
    </section>
  );
}
