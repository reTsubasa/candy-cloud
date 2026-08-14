import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Progress, Space, Spin, Tag, Typography } from '@arco-design/web-react';
import { IconCheckCircle, IconExclamationCircle, IconRefresh, IconRight } from '@arco-design/web-react/icon';
import { fetchHealth, listResources } from '../api';
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import type { HealthState, Session } from '../types';
import { QuickSetupWizard } from './QuickSetupWizard';

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

const setupSteps = [
  { key: 'sites', title: '建立站点', detail: '先定义办公室、门店、机房等业务位置。', required: true },
  { key: 'enrollment', title: '加入节点', detail: '让 OpenWrt 或 Linux 节点获得安全身份。', required: true },
  { key: 'segments', title: '创建网络分段', detail: '为站点间互通准备独立的覆盖网络。', required: true },
  { key: 'attachments', title: '接入网络', detail: '将已加入节点连接到网络分段并分配隧道地址。', required: true },
  { key: 'prefixes', title: '声明可达网段', detail: '登记每个站点需要被访问的局域网前缀。', required: true },
  { key: 'peers', title: '建立站点互联', detail: '建立互联关系，并为两个方向分别配置可用线路。', required: true },
  { key: 'egress', title: '配置出口', detail: '需要跨站点上网时，声明可被策略选择的 Candy 出口。', required: false },
  { key: 'policies', title: '发布流量策略', detail: '决定哪些业务走本地出口或远端出口。', required: false },
  { key: 'dns', title: '配置内部 DNS', detail: '为站点间服务提供统一且受控的内部解析。', required: false },
];

export function Overview({ session }: Props) {
  const [counts, setCounts] = useState<Record<string, CountState>>({});
  const [health, setHealth] = useState<HealthState>(initialHealth);
  const [loading, setLoading] = useState(true);
  const [setupVisible, setSetupVisible] = useState(false);
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
    const countEntries = await Promise.all([...resourceDefinitions, pathDefinition].map(async (definition) => {
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

  const configured = useMemo(() => resourceDefinitions.filter((definition) => {
    const item = counts[definition.key];
    return item && !item.error && item.value > 0;
  }).length, [counts]);
  const errors = useMemo(() => Object.values(counts).filter((item) => item.error).length, [counts]);
  const ready = health.ready.status === 200;
  const setupCompletion = setupSteps.map((step) => {
    if (step.key === 'enrollment') return (counts.nodes?.value ?? 0) > 0;
    if (step.key === 'peers') return (counts.peers?.value ?? 0) > 0 && (counts.paths?.value ?? 0) >= 2;
    return (counts[step.key]?.value ?? 0) > 0;
  });
  const requiredSteps = setupSteps.filter((step) => step.required);
  const requiredDone = setupSteps.filter((step, index) => step.required && setupCompletion[index]).length;

  return (
    <section className="workspace-section overview-page">
      <header className="page-header">
        <div>
          <Typography.Title heading={4}>运营概览</Typography.Title>
          <Typography.Text type="secondary">租户资源与控制面实时状态</Typography.Text>
        </div>
        <Space><Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button><Button type="primary" icon={<IconRight />} onClick={() => setSetupVisible(true)}>{requiredDone > 0 ? '继续配置' : '开始配置'}</Button></Space>
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
          <Typography.Text type="secondary">{requiredDone} / {requiredSteps.length} 个基础步骤已完成</Typography.Text>
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
      <QuickSetupWizard visible={setupVisible} session={session} onClose={() => { setSetupVisible(false); void load(); }} onChanged={() => void load()} />
    </section>
  );
}
