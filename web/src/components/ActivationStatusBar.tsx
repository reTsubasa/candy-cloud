import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Spin, Tag } from '@arco-design/web-react';
import { IconCheckCircle, IconRefresh } from '@arco-design/web-react/icon';
import { fetchRuntimeActivationReadiness, listAllResources } from '../api';
import { activationDisplay } from '../activation-status';
import type { ControlResource, RuntimeActivationReadiness, Session } from '../types';

type Props = {
  resources: ControlResource[];
  session: Session;
};

function resourceName(resource: ControlResource): string {
  return String(resource.resource.spec.name ?? resource.metadata.id);
}

export function ActivationStatusBar({ resources, session }: Props) {
  const tenantId = session.claims.tenant_id;
  const segmentIds = useMemo(() => [...new Set(resources
    .map((resource) => String(resource.resource.spec.segment_id ?? ''))
    .filter(Boolean))].sort(), [resources]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [readiness, setReadiness] = useState<Record<string, RuntimeActivationReadiness>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestVersion = useRef(0);

  const load = useCallback(async () => {
    const request = ++requestVersion.current;
    if (!tenantId || segmentIds.length === 0) {
      setReadiness({});
      setError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    const [segmentsResult, readinessResults] = await Promise.all([
      listAllResources(session.token, tenantId, 'segments'),
      Promise.allSettled(segmentIds.map((segmentId) => fetchRuntimeActivationReadiness(session.token, tenantId, segmentId))),
    ]).catch((reason) => [null, reason] as const);
    if (request !== requestVersion.current) return;
    if (!segmentsResult || !Array.isArray(readinessResults)) {
      setError(readinessResults instanceof Error ? readinessResults.message : 'Cloud 暂时无法读取激活状态');
      setLoading(false);
      return;
    }
    setNames(Object.fromEntries(segmentsResult.map((segment) => [segment.metadata.id, resourceName(segment)])));
    const next: Record<string, RuntimeActivationReadiness> = {};
    const failures: string[] = [];
    readinessResults.forEach((result, index) => {
      if (result.status === 'fulfilled') next[segmentIds[index]] = result.value;
      else failures.push(result.reason instanceof Error ? result.reason.message : '读取失败');
    });
    setReadiness(next);
    setError(failures.length > 0 ? `${failures.length} 个网络的激活状态读取失败` : null);
    setLoading(false);
  }, [segmentIds, session.token, tenantId]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      await load();
      if (!cancelled) timer = window.setTimeout(() => void poll(), 10_000);
    };
    void poll();
    return () => {
      cancelled = true;
      requestVersion.current += 1;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [load]);

  return <section className="activation-status-bar" aria-label="网络激活状态">
    <div className="activation-status-heading">
      <span className="activation-status-icon"><IconCheckCircle /></span>
      <div><strong>配置保存后自动发布</strong><span>节点同步并验证成功后会自动启用数据面，无需额外开关。</span></div>
      <Button type="text" size="small" icon={<IconRefresh />} loading={loading} onClick={() => void load()}>检查状态</Button>
    </div>
    {segmentIds.length === 0 ? <div className="activation-status-empty">建立站点互联和双向线路后，启用状态会显示在这里。</div> : <div className="activation-status-items">
      {segmentIds.map((segmentId) => {
        const display = activationDisplay(readiness[segmentId], null, loading);
        return <div className="activation-status-item" key={segmentId}>
          <span><strong>{names[segmentId] ?? '互联网络'}</strong><small>{display.detail}</small></span>
          {loading && !readiness[segmentId] ? <Spin dot /> : <Tag color={display.tone}>{display.label}</Tag>}
        </div>;
      })}
    </div>}
    {error && <Alert type="warning" showIcon content={error} action={<Button size="small" onClick={() => void load()}>重试</Button>} />}
  </section>;
}
