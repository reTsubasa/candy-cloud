import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Empty,
  Input,
  Message,
  Modal,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
} from '@arco-design/web-react';
import { IconBranch, IconDelete, IconEdit, IconLocation, IconLock, IconPlus, IconRefresh, IconSafe, IconSearch, IconSync } from '@arco-design/web-react/icon';
import { CloudApiError, deleteResource, fetchRuntimeConfigurationStatuses, getResource, listResourceReferences, listResources } from '../api';
import type { ControlResource, ResourceDefinition, ResourceReference, RuntimeConfigurationStatus, Session } from '../types';
import { attachmentTableValues } from '../resource-table';
import { ResourceEditor } from './ResourceEditor';

type Props = {
  definition: ResourceDefinition;
  session: Session;
  createRequest?: number;
  onEnrollNode?: () => void;
  onReenrollNode?: (node: ControlResource) => void;
  focusRequest?: { collection: string; id: string; nonce: number };
  onLocateResource?: (reference: ResourceReference) => void;
  onFocusHandled?: () => void;
};

function text(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

const valueLabels: Record<string, string> = {
  EDGE: '边缘站点', PRIVATE_CLOUD: '私有云', OPEN_WRT: 'OpenWrt', LINUX: 'Linux',
  DIRECT_ONLY: '仅直连', DIRECT_PREFERRED: '直连优先', RELAY_REQUIRED: '必须中继',
  DIRECT: '直接连接', RELAY: '中继路径', CONFIGURED: '手动配置', CONNECTED: '直连网络',
  APPROVED_LEARNED: '已批准学习', ACTIVE: '活跃', DISABLED: '已停用', DELETED: '已删除',
};

const createLabels: Record<string, string> = {
  SITE: '新建站点',
  SEGMENT: '创建分段',
  ATTACHMENT: '添加接入',
  PREFIX: '声明网段',
  PEER: '建立互联',
  PATH_CANDIDATE: '添加线路',
  EGRESS: '配置出口',
  SERVICE_POLICY: '新建策略',
  DNS_INTENT: '配置 DNS',
  RELAY: '添加中继',
};

const pageLabels: Record<string, string> = {
  PEER: '站点互联',
};

const kindLabels: Record<string, string> = {
  NODE: '节点', SITE: '站点', SEGMENT: '网络分段', ATTACHMENT: '网络接入', PREFIX: '网段',
  PEER: '站点互联', PATH_CANDIDATE: '线路配置', EGRESS: '出口', SERVICE_POLICY: '策略',
  DNS_INTENT: 'DNS', RELAY: '中继',
};

function SegmentGuide() {
  return (
    <section className="segment-guide" aria-label="网络分段配置说明">
      <div className="segment-guide-copy">
        <span className="segment-guide-icon"><IconBranch /></span>
        <div>
          <strong>一个分段，是一组共享路由与策略的站点网络</strong>
          <p>分段不是地理区域。杭州、香港、美国需要互通时，通常加入同一个分段；业务必须隔离、地址空间重叠或安全边界不同时，才创建不同分段。</p>
        </div>
      </div>
      <div className="segment-guide-example" aria-label="三个站点加入同一个办公网络分段的示例">
        <div className="segment-example-sites">
          <span><IconLocation />杭州</span>
          <span><IconLocation />香港</span>
          <span><IconLocation />美国</span>
        </div>
        <span className="segment-example-link" aria-hidden="true" />
        <div className="segment-example-network">
          <IconBranch />
          <span><strong>办公网络</strong><small>100.64.10.0/24</small></span>
        </div>
      </div>
      <div className="segment-guide-rules">
        <span><IconBranch /><span><strong>需要互通</strong><small>放在同一分段</small></span></span>
        <span><IconLock /><span><strong>需要隔离</strong><small>创建不同分段</small></span></span>
      </div>
    </section>
  );
}

function label(value: unknown): string {
  const raw = text(value);
  return valueLabels[raw] ?? raw;
}

function capacity(bits: unknown): string {
  const value = Number(bits);
  if (!Number.isFinite(value) || value <= 0) return '—';
  return value >= 1_000_000_000 ? `${value / 1_000_000_000} Gbps` : `${value / 1_000_000} Mbps`;
}

function resourceName(resource: ControlResource, relatedNames: Record<string, string> = {}): string {
  const spec = resource.resource.spec;
  const prefix = spec.prefix as Record<string, unknown> | undefined;
  if (prefix) return `${text(prefix.network)}/${text(prefix.prefix_len)}`;
  if (resource.resource.kind === 'ATTACHMENT') return attachmentTableValues(resource, relatedNames).nodeName;
  if (resource.resource.kind === 'PEER') return `${relatedNames[String(spec.site_a_id)] ?? '站点 A'} ↔ ${relatedNames[String(spec.site_b_id)] ?? '站点 B'}`;
  if (resource.resource.kind === 'SERVICE_POLICY') return '流量策略';
  return text(spec.display_name ?? spec.name ?? spec.zone ?? spec.endpoint ?? resource.metadata.id);
}

function resourceScope(resource: ControlResource): string {
  const spec = resource.resource.spec;
  const prefix = spec.prefix as Record<string, unknown> | undefined;
  const overlay = spec.overlay_prefix as Record<string, unknown> | undefined;
  if (prefix) return `${text(prefix.network)}/${text(prefix.prefix_len)}`;
  if (overlay) return `${text(overlay.network)}/${text(overlay.prefix_len)}`;
  if (Array.isArray(spec.rules)) return `${spec.rules.length} 条流量规则`;
  if (Array.isArray(spec.records)) return `${spec.records.length} 条 DNS 记录`;
  if (spec.max_bits_per_second) return `${capacity(spec.max_bits_per_second)} · ${text(spec.max_sessions)} 会话`;
  if (resource.resource.kind === 'ATTACHMENT') return attachmentTableValues(resource).tunnelIp;
  if (spec.overlay_router_ipv4) return `隧道地址 ${text(spec.overlay_router_ipv4)}`;
  return label(spec.region ?? spec.platform ?? spec.path_policy ?? spec.kind ?? spec.segment_id);
}

function stateColor(state: string): string {
  if (state === 'ACTIVE') return 'green';
  if (state === 'DISABLED') return 'orange';
  return 'gray';
}

export function ResourcePage({ definition, session, createRequest = 0, onEnrollNode, onReenrollNode, focusRequest, onLocateResource, onFocusHandled }: Props) {
  const [message, messageHolder] = Message.useMessage();
  const [items, setItems] = useState<ControlResource[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<{ visible: boolean; resource: ControlResource | null }>({ visible: false, resource: null });
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ControlResource | null>(null);
  const [referenceLoading, setReferenceLoading] = useState(false);
  const [deleteReferences, setDeleteReferences] = useState<ResourceReference[]>([]);
  const [relatedNames, setRelatedNames] = useState<Record<string, string>>({});
  const [runtimeStatuses, setRuntimeStatuses] = useState<Record<string, RuntimeConfigurationStatus>>({});
  const tenantId = session.claims.tenant_id;

  const load = useCallback(async () => {
    if (!tenantId) {
      setError('JWT 中没有 tenant_id，无法读取租户资源');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [response, statuses] = await Promise.all([
        listResources(session.token, tenantId, definition.collection),
        definition.kind === 'NODE'
          ? fetchRuntimeConfigurationStatuses(session.token, tenantId)
          : Promise.resolve({ schema_version: 1, items: [] }),
      ]);
      setItems(response.items);
      setNextCursor(response.next_cursor);
      setRuntimeStatuses(Object.fromEntries(
        statuses.items.map((status) => [`${status.device_id}:${status.device_key_id}`, status]),
      ));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '资源加载失败');
    } finally {
      setLoading(false);
    }
  }, [definition.collection, definition.kind, session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!tenantId) { setRelatedNames({}); return; }
    const relation = definition.kind === 'PEER'
      ? { collection: 'sites', nameField: 'name' }
      : definition.kind === 'ATTACHMENT'
        ? { collection: 'nodes', nameField: 'display_name' }
        : null;
    if (!relation) { setRelatedNames({}); return; }
    let cancelled = false;
    setRelatedNames({});
    void listResources(session.token, tenantId, relation.collection).then((response) => {
      if (!cancelled) setRelatedNames(Object.fromEntries(response.items.map((item) => [item.metadata.id, text(item.resource.spec[relation.nameField])])));
    }).catch(() => { if (!cancelled) setRelatedNames({}); });
    return () => { cancelled = true; };
  }, [definition.kind, session.token, tenantId]);
  useEffect(() => {
    if (createRequest > 0 && definition.kind !== 'NODE') setEditor({ visible: true, resource: null });
  }, [createRequest, definition.kind]);
  useEffect(() => {
    if (!focusRequest || focusRequest.collection !== definition.collection || loading || !tenantId) return;
    const target = items.find((item) => item.metadata.id === focusRequest.id);
    if (target) {
      setEditor({ visible: true, resource: target });
      onFocusHandled?.();
      return;
    }
    let cancelled = false;
    void getResource(session.token, tenantId, definition.collection, focusRequest.id)
      .then((resource) => { if (!cancelled) setEditor({ visible: true, resource }); })
      .catch((reason) => { if (!cancelled) message.error?.(reason instanceof Error ? reason.message : '无法打开引用配置'); })
      .finally(() => { if (!cancelled) onFocusHandled?.(); });
    return () => { cancelled = true; };
  }, [definition.collection, focusRequest, items, loading, message, onFocusHandled, session.token, tenantId]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => JSON.stringify(item).toLowerCase().includes(needle));
  }, [items, query]);

  const remove = async () => {
    if (!tenantId || !deleteTarget) return;
    setDeletingId(deleteTarget.metadata.id);
    try {
      await deleteResource(session.token, tenantId, definition.collection, deleteTarget.metadata.id, deleteTarget.metadata.revision);
      setDeleteTarget(null);
      message.success?.('资源已删除');
      await load();
    } catch (reason) {
      if (reason instanceof CloudApiError && reason.code === 'RESOURCE_REFERENCE_CONFLICT') {
        setDeleteReferences(reason.details?.references ?? []);
        if (!(reason.details?.references?.length)) {
          setDeleteTarget(null);
          message.error?.('资源删除被后端拒绝，但没有返回可定位的引用。请刷新资源列表并检查控制面状态。');
        }
      } else {
        message.error?.(reason instanceof Error ? reason.message : '删除失败，请稍后重试');
      }
    } finally {
      setDeletingId(null);
    }
  };

  const openDelete = async (record: ControlResource) => {
    if (!tenantId) return;
    setDeleteTarget(record);
    setDeleteReferences([]);
    setReferenceLoading(true);
    try {
      const response = await listResourceReferences(session.token, tenantId, definition.collection, record.metadata.id);
      setDeleteReferences(response.references);
    } catch (reason) {
      setDeleteTarget(null);
      message.error?.(reason instanceof Error ? reason.message : '无法检查资源引用关系');
    } finally {
      setReferenceLoading(false);
    }
  };

  const columns = [
    {
      title: definition.kind === 'ATTACHMENT' ? '节点名称' : definition.label,
      render: (_: unknown, record: ControlResource) => (
        <div className="resource-primary">
          <Typography.Text bold>{resourceName(record, relatedNames)}</Typography.Text>
        </div>
      ),
    },
    { title: definition.kind === 'ATTACHMENT' ? '节点隧道 IP' : '范围 / 类型', render: (_: unknown, record: ControlResource) => <Typography.Text>{resourceScope(record)}</Typography.Text> },
    { title: '状态', width: 104, render: (_: unknown, record: ControlResource) => <Tag color={stateColor(record.metadata.state)}>{label(record.metadata.state)}</Tag> },
    ...(definition.kind === 'NODE' ? [{
      title: 'SD-WAN',
      width: 136,
      render: (_: unknown, record: ControlResource) => {
        const deviceId = String(record.resource.spec.device_id ?? '');
        const deviceKeyId = String(record.resource.spec.device_key_id ?? '');
        const status = runtimeStatuses[`${deviceId}:${deviceKeyId}`];
        if (!status || !status.current) return <Tag color="gray">等待激活</Tag>;
        return (
          <Tooltip content={status.state === 'rejected' ? `激活失败：${status.error_code ?? 'unknown'}` : `配置已于 ${new Date(status.reported_at).toLocaleString()} 生效`}>
            <Tag color={status.state === 'active' ? 'green' : 'red'}>{status.state === 'active' ? '已启用' : '激活失败'}</Tag>
          </Tooltip>
        );
      },
    }] : []),
    {
      title: '',
      width: 92,
      align: 'right' as const,
      render: (_: unknown, record: ControlResource) => (
        <Space size={4}>
          {definition.kind === 'NODE' && <Tooltip content="重新生成加入文件"><Button type="text" size="small" icon={<IconSync />} aria-label="重新加入" onClick={() => onReenrollNode?.(record)} /></Tooltip>}
          <Tooltip content="编辑"><Button type="text" size="small" icon={<IconEdit />} aria-label="编辑" onClick={() => setEditor({ visible: true, resource: record })} /></Tooltip>
          <Tooltip content="删除"><Button type="text" size="small" status="danger" icon={<IconDelete />} aria-label="删除" loading={deletingId === record.metadata.id} disabled={deletingId !== null} onClick={() => void openDelete(record)} /></Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <section className="workspace-section">
      {messageHolder}
      <header className="page-header">
        <div>
          <Typography.Title heading={4}>{pageLabels[definition.kind] ?? definition.label}</Typography.Title>
          <Typography.Text type="secondary">{definition.description}</Typography.Text>
        </div>
        <Space>
          <Button icon={<IconRefresh />} onClick={() => void load()} loading={loading}>刷新</Button>
          {definition.kind === 'NODE' ? (
            <Button type="primary" icon={<IconSafe />} onClick={onEnrollNode}>添加节点</Button>
          ) : (
            <Button type="primary" icon={<IconPlus />} onClick={() => setEditor({ visible: true, resource: null })}>{createLabels[definition.kind] ?? '新建'}</Button>
          )}
        </Space>
      </header>
      {definition.kind === 'SEGMENT' && <SegmentGuide />}
      <div className="toolbar-row">
        <Input
          allowClear
          prefix={<IconSearch />}
          placeholder="搜索名称或配置内容"
          value={query}
          onChange={setQuery}
          className="resource-search"
        />
        <Typography.Text type="secondary">
          {nextCursor ? `${items.length}+ 项` : `${items.length} 项`}
        </Typography.Text>
      </div>
      {error && <Alert type="error" showIcon content={error} action={<Button size="small" onClick={() => void load()}>重试</Button>} />}
      <div className="table-surface">
        <Spin loading={loading} block>
          {!loading && !error && filtered.length === 0 ? (
            <Empty description={query ? '没有匹配的资源' : definition.emptyTitle} />
          ) : (
            <Table
              rowKey={(record) => record.metadata.id}
              columns={columns}
              data={filtered}
              pagination={filtered.length > 20 ? { pageSize: 20, sizeCanChange: true } : false}
              scroll={{ x: 780 }}
            />
          )}
        </Spin>
      </div>
      <ResourceEditor
        visible={editor.visible}
        definition={definition}
        session={session}
        resource={editor.resource}
        onClose={() => setEditor({ visible: false, resource: null })}
        onSaved={() => {
          setEditor({ visible: false, resource: null });
          message.success?.(editor.resource ? '资源已更新' : '资源已创建');
          void load();
        }}
      />
      <Modal
        visible={deleteTarget !== null}
        title={deleteTarget ? `删除“${resourceName(deleteTarget, relatedNames)}”？` : '删除资源'}
        okText="确认删除"
        cancelText="取消"
        okButtonProps={{ status: 'danger', disabled: referenceLoading || deleteReferences.length > 0 }}
        confirmLoading={deletingId !== null}
        onCancel={() => { if (!deletingId) setDeleteTarget(null); }}
        onOk={() => void remove()}
        unmountOnExit
      >
        {referenceLoading ? <div className="reference-checking"><Spin dot /><Typography.Text type="secondary">正在检查其他配置是否仍在使用此资源...</Typography.Text></div> : deleteReferences.length > 0 ? <>
          <Alert type="warning" showIcon title="暂时无法删除" content={`还有 ${deleteReferences.length} 项配置正在引用此资源。请先调整或删除这些配置。`} />
          <div className="reference-blocker-list">
            {deleteReferences.map((reference) => <div className="reference-blocker" key={`${reference.collection}:${reference.id}`}>
              <div><Tag>{kindLabels[reference.kind] ?? reference.kind}</Tag><span><strong>{resourceName(reference.resource)}</strong><small>仍在使用当前资源</small></span></div>
              <Button type="text" onClick={() => { setDeleteTarget(null); onLocateResource?.(reference); }}>查看</Button>
            </div>)}
          </div>
        </> : <Typography.Paragraph>删除后，该资源将不再参与控制面编排，且无法继续用于网络、线路或策略配置。</Typography.Paragraph>}
      </Modal>
    </section>
  );
}
