import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Empty, Form, Input, Modal, Popconfirm, Select, Space, Spin, Switch, Table, Tag, Typography } from '@arco-design/web-react';
import { IconPlus, IconRefresh, IconRight, IconUserGroup } from '@arco-design/web-react/icon';
import {
  inviteOrganizationMember,
  listOrganizationMembers,
  removeOrganizationMember,
  transferOrganizationOwnership,
  updateOrganizationMemberRole,
  updateOrganizationMemberStatus,
} from '../api';
import type { OrganizationMember, Session } from '../types';

type Props = { session: Session; onSessionInvalidated: () => void };

const roles = [
  { value: 'TENANT_ADMIN', label: '租户管理员' },
  { value: 'OPERATOR', label: '操作员' },
  { value: 'BILLING_VIEWER', label: '账务只读' },
  { value: 'AUDITOR', label: '审计员' },
];

function roleLabel(role: string): string {
  if (role === 'ORGANIZATION_OWNER') return '组织所有者';
  return roles.find((item) => item.value === role)?.label ?? role;
}

export function OrganizationAccess({ session, onSessionInvalidated }: Props) {
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('OPERATOR');
  const [busy, setBusy] = useState<string | null>(null);
  const currentRole = session.membership?.role ?? session.claims.role;
  const canRead = ['ORGANIZATION_OWNER', 'TENANT_ADMIN', 'AUDITOR'].includes(currentRole ?? '');
  const canManage = currentRole === 'ORGANIZATION_OWNER';

  const load = useCallback(async () => {
    if (!canRead) { setLoading(false); return; }
    setLoading(true);
    setError(null);
    try { setMembers(await listOrganizationMembers(session.token)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : '成员列表加载失败'); }
    finally { setLoading(false); }
  }, [canRead, session.token]);

  useEffect(() => { void load(); }, [load]);

  const run = async (id: string, operation: () => Promise<void>, invalidatesCurrent = false) => {
    setBusy(id); setError(null);
    try {
      await operation();
      if (invalidatesCurrent) { onSessionInvalidated(); return; }
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : '操作未完成'); }
    finally { setBusy(null); }
  };

  const invite = async () => {
    setBusy('invite'); setError(null);
    try {
      await inviteOrganizationMember(session.token, email.trim(), role);
      setInviteOpen(false); setEmail(''); setRole('OPERATOR');
    } catch (reason) { setError(reason instanceof Error ? reason.message : '邀请发送失败'); }
    finally { setBusy(null); }
  };

  if (!canRead) return <section className="workspace-section"><Alert type="info" showIcon content="当前角色不包含组织成员目录权限。你的网络配置权限保持不变。" /></section>;

  const columns = [
    { title: '成员', dataIndex: 'display_name', render: (_: unknown, item: OrganizationMember) => <div className="member-identity"><strong>{item.display_name}</strong><span>{item.email}</span></div> },
    { title: '角色', dataIndex: 'role', render: (value: string, item: OrganizationMember) => item.role === 'ORGANIZATION_OWNER' || !canManage ? <Tag color={item.role === 'ORGANIZATION_OWNER' ? 'arcoblue' : 'gray'}>{roleLabel(value)}</Tag> : <Select size="small" value={value} options={roles} onChange={(next) => void run(item.id, () => updateOrganizationMemberRole(session.token, item.id, next))} disabled={busy === item.id} /> },
    { title: '状态', dataIndex: 'active', render: (value: boolean, item: OrganizationMember) => item.role === 'ORGANIZATION_OWNER' || !canManage ? <Tag color={value ? 'green' : 'orange'}>{value ? '活跃' : '已停用'}</Tag> : <Switch checked={value} loading={busy === item.id} onChange={(next) => void run(item.id, () => updateOrganizationMemberStatus(session.token, item.id, next))} /> },
    { title: '管理', render: (_: unknown, item: OrganizationMember) => item.role === 'ORGANIZATION_OWNER' || !canManage ? null : <Space>
      <Popconfirm title="移除成员？" content="该成员的全部管理会话会立即撤销。" onOk={() => void run(item.id, () => removeOrganizationMember(session.token, item.id))}><Button size="small" status="danger" type="text">移除</Button></Popconfirm>
      <Popconfirm title="转移组织所有权？" content="你将变为租户管理员，双方现有会话都会立即失效。" onOk={() => void run(item.id, () => transferOrganizationOwnership(session.token, item.id), true)}><Button size="small" type="text" icon={<IconRight />}>转让</Button></Popconfirm>
    </Space> },
  ];

  const memberActions = (item: OrganizationMember) => item.role === 'ORGANIZATION_OWNER' || !canManage ? null : <Space size={4}>
    <Popconfirm title="移除成员？" content="该成员的全部管理会话会立即撤销。" onOk={() => void run(item.id, () => removeOrganizationMember(session.token, item.id))}><Button size="mini" status="danger" type="text">移除</Button></Popconfirm>
    <Popconfirm title="转移组织所有权？" content="你将变为租户管理员，双方现有会话都会立即失效。" onOk={() => void run(item.id, () => transferOrganizationOwnership(session.token, item.id), true)}><Button size="mini" type="text" icon={<IconRight />}>转让</Button></Popconfirm>
  </Space>;

  return <section className="workspace-section organization-access-page">
    <header className="page-header"><div><Typography.Title heading={4}>成员与权限</Typography.Title><Typography.Text type="secondary">邀请成员、分配最小权限，并即时撤销不再需要的访问。</Typography.Text></div><Space><Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>{canManage && <Button type="primary" icon={<IconPlus />} onClick={() => setInviteOpen(true)}>邀请成员</Button>}</Space></header>
    {error && <Alert className="editor-alert" type="error" content={error} showIcon />}
    <div className="access-summary"><IconUserGroup /><div><strong>{members.filter((item) => item.active).length}</strong><span>活跃成员</span></div><div><strong>{members.filter((item) => item.role === 'ORGANIZATION_OWNER').length}</strong><span>组织所有者</span></div><p>权限变更、停用和移除会在数据库事务内撤销受影响会话，Cloud API 每次请求重新校验权限。</p></div>
    {loading ? <div className="access-table-state"><Spin /></div> : members.length === 0 ? <Empty description="暂无组织成员" /> : <>
      <Table rowKey="id" columns={columns} data={members} pagination={false} className="access-table access-table-desktop" />
      <div className="member-list-mobile">
        {members.map((item) => <article className="member-card-mobile" key={item.id}>
          <header><div className="member-identity"><strong>{item.display_name}</strong><span>{item.email}</span></div>{memberActions(item)}</header>
          <div className="member-card-fields">
            <div><span>角色</span>{item.role === 'ORGANIZATION_OWNER' || !canManage ? <Tag color={item.role === 'ORGANIZATION_OWNER' ? 'arcoblue' : 'gray'}>{roleLabel(item.role)}</Tag> : <Select size="small" value={item.role} options={roles} onChange={(next) => void run(item.id, () => updateOrganizationMemberRole(session.token, item.id, next))} disabled={busy === item.id} />}</div>
            <div><span>状态</span>{item.role === 'ORGANIZATION_OWNER' || !canManage ? <Tag color={item.active ? 'green' : 'orange'}>{item.active ? '活跃' : '已停用'}</Tag> : <Switch checked={item.active} loading={busy === item.id} onChange={(next) => void run(item.id, () => updateOrganizationMemberStatus(session.token, item.id, next))} />}</div>
          </div>
        </article>)}
      </div>
    </>}
    <Modal className="invite-member-modal" title="邀请组织成员" visible={inviteOpen} onCancel={() => setInviteOpen(false)} onOk={() => void invite()} confirmLoading={busy === 'invite'} okButtonProps={{ disabled: !email.trim() }}>
      <Form layout="vertical"><Form.Item label="邮箱" required><Input value={email} onChange={setEmail} placeholder="member@example.com" /></Form.Item><Form.Item label="角色" required><Select value={role} onChange={setRole} options={roles} /></Form.Item></Form>
    </Modal>
  </section>;
}
