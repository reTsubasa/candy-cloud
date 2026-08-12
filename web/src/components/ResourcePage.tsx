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
  Typography,
} from '@arco-design/web-react';
import { IconDelete, IconEdit, IconPlus, IconRefresh, IconSearch } from '@arco-design/web-react/icon';
import { deleteResource, listResources } from '../api';
import type { ControlResource, ResourceDefinition, Session } from '../types';
import { ResourceEditor } from './ResourceEditor';

type Props = {
  definition: ResourceDefinition;
  session: Session;
};

function text(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function resourceName(resource: ControlResource): string {
  const spec = resource.resource.spec;
  return text(spec.display_name ?? spec.name ?? spec.zone ?? spec.endpoint ?? resource.metadata.id);
}

function resourceScope(resource: ControlResource): string {
  const spec = resource.resource.spec;
  const prefix = spec.prefix as Record<string, unknown> | undefined;
  const overlay = spec.overlay_prefix as Record<string, unknown> | undefined;
  if (prefix) return `${text(prefix.network)}/${text(prefix.prefix_len)}`;
  if (overlay) return `${text(overlay.network)}/${text(overlay.prefix_len)}`;
  return text(spec.region ?? spec.platform ?? spec.path_policy ?? spec.kind ?? spec.segment_id);
}

function stateColor(state: string): string {
  if (state === 'ACTIVE') return 'green';
  if (state === 'DISABLED') return 'orange';
  return 'gray';
}

export function ResourcePage({ definition, session }: Props) {
  const [items, setItems] = useState<ControlResource[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<{ visible: boolean; resource: ControlResource | null }>({ visible: false, resource: null });
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

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => JSON.stringify(item).toLowerCase().includes(needle));
  }, [items, query]);

  const remove = (resource: ControlResource) => {
    if (!tenantId) return;
    Modal.confirm({
      title: `删除${resourceName(resource)}？`,
      content: '后端会检查引用关系和 revision；仍被使用的资源不会被删除。',
      okButtonProps: { status: 'danger' },
      onOk: async () => {
        await deleteResource(session.token, tenantId, definition.collection, resource.metadata.id, resource.metadata.revision);
        Message.success('资源已删除');
        await load();
      },
    });
  };

  const columns = [
    {
      title: definition.label,
      render: (_: unknown, record: ControlResource) => (
        <div className="resource-primary">
          <Typography.Text bold>{resourceName(record)}</Typography.Text>
          <Typography.Text type="secondary" className="mono compact-id">{record.metadata.id}</Typography.Text>
        </div>
      ),
    },
    { title: '范围 / 类型', render: (_: unknown, record: ControlResource) => <Typography.Text>{resourceScope(record)}</Typography.Text> },
    { title: '状态', width: 104, render: (_: unknown, record: ControlResource) => <Tag color={stateColor(record.metadata.state)}>{record.metadata.state}</Tag> },
    { title: 'Revision', width: 96, render: (_: unknown, record: ControlResource) => <span className="mono">{record.metadata.revision}</span> },
    {
      title: '',
      width: 92,
      align: 'right' as const,
      render: (_: unknown, record: ControlResource) => (
        <Space size={4}>
          <Button type="text" size="small" icon={<IconEdit />} aria-label="编辑" onClick={() => setEditor({ visible: true, resource: record })} />
          <Button type="text" size="small" status="danger" icon={<IconDelete />} aria-label="删除" onClick={() => remove(record)} />
        </Space>
      ),
    },
  ];

  return (
    <section className="workspace-section">
      <header className="page-header">
        <div>
          <Typography.Title heading={4}>{definition.label}</Typography.Title>
          <Typography.Text type="secondary">{definition.description}</Typography.Text>
        </div>
        <Space>
          <Button icon={<IconRefresh />} onClick={() => void load()} loading={loading}>刷新</Button>
          <Button type="primary" icon={<IconPlus />} onClick={() => setEditor({ visible: true, resource: null })}>新建</Button>
        </Space>
      </header>
      <div className="toolbar-row">
        <Input
          allowClear
          prefix={<IconSearch />}
          placeholder="搜索名称、ID 或配置字段"
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
          Message.success(editor.resource ? '资源已更新' : '资源已创建');
          void load();
        }}
      />
    </section>
  );
}
