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
import { IconDelete, IconEdit, IconPlus, IconRefresh, IconSafe, IconSearch } from '@arco-design/web-react/icon';
import { deleteResource, listResources } from '../api';
import type { ControlResource, ResourceDefinition, Session } from '../types';
import { ResourceEditor } from './ResourceEditor';

type Props = {
  definition: ResourceDefinition;
  session: Session;
  createRequest?: number;
  onEnrollNode?: () => void;
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
  if (resource.resource.kind === 'ATTACHMENT') return `节点接入 · ${text(spec.overlay_router_ipv4)}`;
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
  if (spec.overlay_router_ipv4) return `隧道地址 ${text(spec.overlay_router_ipv4)}`;
  return label(spec.region ?? spec.platform ?? spec.path_policy ?? spec.kind ?? spec.segment_id);
}

function stateColor(state: string): string {
  if (state === 'ACTIVE') return 'green';
  if (state === 'DISABLED') return 'orange';
  return 'gray';
}

export function ResourcePage({ definition, session, createRequest = 0, onEnrollNode }: Props) {
  const [message, messageHolder] = Message.useMessage();
  const [items, setItems] = useState<ControlResource[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<{ visible: boolean; resource: ControlResource | null }>({ visible: false, resource: null });
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ControlResource | null>(null);
  const [relatedNames, setRelatedNames] = useState<Record<string, string>>({});
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
      const response = await listResources(session.token, tenantId, definition.collection);
      setItems(response.items);
      setNextCursor(response.next_cursor);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '资源加载失败');
    } finally {
      setLoading(false);
    }
  }, [definition.collection, session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (definition.kind !== 'PEER' || !tenantId) { setRelatedNames({}); return; }
    void listResources(session.token, tenantId, 'sites').then((response) => {
      setRelatedNames(Object.fromEntries(response.items.map((item) => [item.metadata.id, text(item.resource.spec.name)])));
    }).catch(() => setRelatedNames({}));
  }, [definition.kind, session.token, tenantId]);
  useEffect(() => {
    if (createRequest > 0 && definition.kind !== 'NODE') setEditor({ visible: true, resource: null });
  }, [createRequest, definition.kind]);

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
      message.error?.(reason instanceof Error ? reason.message : '删除失败，请稍后重试');
    } finally {
      setDeletingId(null);
    }
  };

  const columns = [
    {
      title: definition.label,
      render: (_: unknown, record: ControlResource) => (
        <div className="resource-primary">
          <Typography.Text bold>{resourceName(record, relatedNames)}</Typography.Text>
        </div>
      ),
    },
    { title: '范围 / 类型', render: (_: unknown, record: ControlResource) => <Typography.Text>{resourceScope(record)}</Typography.Text> },
    { title: '状态', width: 104, render: (_: unknown, record: ControlResource) => <Tag color={stateColor(record.metadata.state)}>{label(record.metadata.state)}</Tag> },
    {
      title: '',
      width: 92,
      align: 'right' as const,
      render: (_: unknown, record: ControlResource) => (
        <Space size={4}>
          <Tooltip content="编辑"><Button type="text" size="small" icon={<IconEdit />} aria-label="编辑" onClick={() => setEditor({ visible: true, resource: record })} /></Tooltip>
          <Tooltip content="删除"><Button type="text" size="small" status="danger" icon={<IconDelete />} aria-label="删除" loading={deletingId === record.metadata.id} disabled={deletingId !== null} onClick={() => setDeleteTarget(record)} /></Tooltip>
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
        okButtonProps={{ status: 'danger' }}
        confirmLoading={deletingId !== null}
        onCancel={() => { if (!deletingId) setDeleteTarget(null); }}
        onOk={() => void remove()}
        unmountOnExit
      >
        <Typography.Paragraph>删除后，该资源将不再参与控制面编排。后端会检查引用关系和修订版本；仍被使用的资源不会被删除。</Typography.Paragraph>
      </Modal>
    </section>
  );
}
