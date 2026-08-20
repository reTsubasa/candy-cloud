import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Descriptions, Empty, Popconfirm, Space, Spin, Tag, Typography } from '@arco-design/web-react';
import { IconCheckCircle, IconClockCircle, IconDelete, IconEmail, IconRefresh, IconSafe, IconUser } from '@arco-design/web-react/icon';
import { listAccountSessions, revokeAccountSession } from '../api';
import type { HumanSession, Session } from '../types';

type Props = { session: Session; onDisconnect: () => void };

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' });
}

function sessionLabel(item: HumanSession, currentId?: string): string {
  const device = item.device_label || '未命名设备';
  return item.id === currentId ? `${device}（当前）` : device;
}

export function AccountSecurity({ session, onDisconnect }: Props) {
  const [items, setItems] = useState<HumanSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems((await listAccountSessions(session.token)).filter((item) => !item.revoked_at));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '会话列表加载失败');
    } finally {
      setLoading(false);
    }
  }, [session.token]);

  useEffect(() => { void load(); }, [load]);

  const revoke = async (id: string) => {
    setBusyId(id);
    setError(null);
    try {
      await revokeAccountSession(session.token, id);
      if (id === session.claims.sid) {
        onDisconnect();
        return;
      }
      setItems((current) => current.filter((item) => item.id !== id));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '撤销会话失败');
    } finally {
      setBusyId(null);
    }
  };

  const user = session.user;
  const membership = session.membership;
  return (
    <section className="workspace-section account-page">
      <div className="page-header"><div><Typography.Title heading={4}>账户与安全</Typography.Title><Typography.Paragraph type="secondary">管理个人资料、邮箱验证状态和控制面登录会话。</Typography.Paragraph></div></div>
      {error && <Alert className="editor-alert" type="error" content={error} showIcon />}
      <div className="account-grid">
        <Card className="account-card" bordered>
          <div className="account-card-heading"><span className="account-icon blue"><IconUser /></span><div><Typography.Title heading={5}>账户资料</Typography.Title><Typography.Text type="secondary">当前管理身份</Typography.Text></div></div>
          <Descriptions
            column={1}
            colon="："
            className="account-descriptions"
            data={[
              { label: '姓名', value: user?.display_name ?? '未提供' },
              { label: '邮箱', value: <Space size={6}>{user?.email ?? '未提供'} {user?.email_verified ? <Tag color="green" icon={<IconCheckCircle />}>已验证</Tag> : <Tag color="orange" icon={<IconEmail />}>待验证</Tag>}</Space> },
              { label: '组织', value: membership?.organization_name ?? session.claims.organization_id ?? '未识别' },
              { label: '权限', value: membership?.role ?? session.claims.role ?? '未识别' },
            ]}
          />
        </Card>
        <Card className="account-card" bordered>
          <div className="account-card-heading"><span className="account-icon green"><IconSafe /></span><div><Typography.Title heading={5}>会话安全</Typography.Title><Typography.Text type="secondary">刷新令牌轮换，撤销即时生效</Typography.Text></div></div>
          <div className="security-summary"><strong>{items.length}</strong><span>个活跃会话</span></div>
          <Typography.Paragraph type="secondary">仅保留当前标签页的凭据。发现异常设备时可立即撤销其访问权限。</Typography.Paragraph>
          <Button icon={<IconRefresh />} onClick={() => void load()} loading={loading}>刷新列表</Button>
        </Card>
      </div>
      <div className="section-heading-row account-sessions-heading"><div><Typography.Title heading={5}>活跃会话</Typography.Title><Typography.Text type="secondary">访问令牌短期有效，刷新令牌为一次性轮换凭据。</Typography.Text></div></div>
      <div className="session-list">
        {loading ? <div className="session-list-state"><Spin /></div> : items.length === 0 ? <Empty description="暂无活跃会话" /> : items.map((item) => {
          const current = item.id === session.claims.sid;
          return <div className={`session-item ${current ? 'current' : ''}`} key={item.id}>
            <div className="session-item-status"><span className={`session-status-dot ${current ? 'active' : ''}`} /><div><strong>{sessionLabel(item, session.claims.sid)}</strong><Typography.Text type="secondary" className="session-id mono">{item.id}</Typography.Text></div></div>
            <div className="session-item-meta"><span><IconClockCircle /> 有效至 {formatDate(item.expires_at)}</span><span>角色 {item.role}</span></div>
            <Popconfirm title={current ? '撤销当前会话并退出？' : '撤销此会话？'} content="该设备将立即失去管理访问权限。" onOk={() => void revoke(item.id)}>
              <Button status="danger" type={current ? 'primary' : 'secondary'} icon={<IconDelete />} loading={busyId === item.id}>{current ? '退出此设备' : '撤销'}</Button>
            </Popconfirm>
          </div>;
        })}
      </div>
    </section>
  );
}
