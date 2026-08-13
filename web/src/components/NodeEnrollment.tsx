import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Message, Modal, Space, Table, Tag, Typography } from '@arco-design/web-react';
import { IconCopy, IconDelete, IconPlus, IconRefresh } from '@arco-design/web-react/icon';
import {
  createNodeJoinCode,
  listNodeJoinCodes,
  revokeNodeJoinCode,
} from '../api';
import type { EnrollmentActivation, EnrollmentActivationSecret, Session } from '../types';

type Props = { session: Session };

const statusLabel: Record<EnrollmentActivation['status'], string> = {
  ACTIVE: '待使用', RESERVED: '正在加入', CONSUMED: '已使用', REVOKED: '已撤销', EXPIRED: '已过期',
};

function statusColor(status: EnrollmentActivation['status']): string {
  if (status === 'ACTIVE') return 'arcoblue';
  if (status === 'RESERVED') return 'orange';
  if (status === 'CONSUMED') return 'green';
  return 'gray';
}

export function NodeEnrollment({ session }: Props) {
  const tenantId = session.claims.tenant_id;
  const [items, setItems] = useState<EnrollmentActivation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<EnrollmentActivationSecret | null>(null);

  const load = useCallback(async () => {
    if (!tenantId) return;
    setLoading(true);
    setError(null);
    try { setItems(await listNodeJoinCodes(session.token, tenantId)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : '节点加入码加载失败'); }
    finally { setLoading(false); }
  }, [session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    if (!tenantId) return;
    try {
      setSecret(await createNodeJoinCode(session.token, tenantId));
      await load();
    } catch (reason) {
      Message.error(reason instanceof Error ? reason.message : '创建失败');
    }
  };

  const revoke = (item: EnrollmentActivation) => {
    if (!tenantId) return;
    Modal.confirm({
      title: '撤销这个节点加入码？',
      content: '尚未完成加入的设备将无法继续使用它。',
      okButtonProps: { status: 'danger' },
      onOk: async () => {
        await revokeNodeJoinCode(session.token, tenantId, item.id);
        Message.success('节点加入码已撤销');
        await load();
      },
    });
  };

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    Message.success('已复制');
  };

  const columns = [
    { title: '状态', width: 110, render: (_: unknown, item: EnrollmentActivation) => <Tag color={statusColor(item.status)}>{statusLabel[item.status]}</Tag> },
    { title: '创建时间', render: (_: unknown, item: EnrollmentActivation) => new Date(item.created_at).toLocaleString() },
    { title: '有效期至', render: (_: unknown, item: EnrollmentActivation) => new Date(item.expires_at).toLocaleString() },
    { title: '记录 ID', render: (_: unknown, item: EnrollmentActivation) => <Typography.Text className="mono compact-id">{item.id}</Typography.Text> },
    { title: '', width: 60, align: 'right' as const, render: (_: unknown, item: EnrollmentActivation) => ['ACTIVE', 'RESERVED'].includes(item.status) ? <Button type="text" status="danger" icon={<IconDelete />} aria-label="撤销" onClick={() => revoke(item)} /> : null },
  ];

  return (
    <section className="enrollment-section">
      <header className="section-heading-row">
        <div><Typography.Title heading={5}>节点加入</Typography.Title><Typography.Text type="secondary">生成一次性加入码，将 OpenWrt 或 Linux 节点安全加入当前网络</Typography.Text></div>
        <Space><Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button><Button type="primary" icon={<IconPlus />} onClick={() => void create()}>添加节点</Button></Space>
      </header>
      {error && <Alert type="error" showIcon content={error} />}
      <div className="table-surface enrollment-table"><Table rowKey="id" loading={loading} data={items} columns={columns} pagination={false} scroll={{ x: 720 }} /></div>
      <Modal title="节点加入码已生成" visible={secret !== null} footer={null} onCancel={() => setSecret(null)} className="activation-modal">
        {secret && <div className="activation-secret"><Alert type="warning" showIcon content="加入码仅可使用一次，并将在 10 分钟后失效。" /><Typography.Text type="secondary">有效期至 {new Date(secret.expires_at).toLocaleString()}</Typography.Text><div><code>{secret.credential}</code><Button icon={<IconCopy />} onClick={() => void copy(secret.credential)} aria-label="复制节点加入码" /></div><Typography.Text type="secondary">Linux：运行 <code>candy join --cloud https://cloud.example</code>，然后按提示输入加入码。</Typography.Text><Typography.Text type="secondary">OpenWrt：在 LuCI 的 SD-WAN 页面输入加入码。</Typography.Text></div>}
      </Modal>
    </section>
  );
}
