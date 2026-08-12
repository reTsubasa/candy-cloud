import { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Space, Tag, Typography } from '@arco-design/web-react';
import { IconBranch, IconCloud, IconLock, IconRight, IconSafe, IconThunderbolt } from '@arco-design/web-react/icon';
import { loginAccount, registerAccount, verifyAccountEmail } from '../api';
import { isSessionExpired, saveIdentitySession } from '../session';
import type { Session } from '../types';

type Props = {
  onConnect: (session: Session) => void;
  loading?: boolean;
};

export function SessionGate({ onConnect, loading = false }: Props) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('verify_email');
    if (!token) return;
    let cancelled = false;
    setSubmitting(true);
    void verifyAccountEmail(token)
      .then((issued) => {
        if (cancelled) return;
        const session = saveIdentitySession(issued);
        window.history.replaceState({}, document.title, window.location.pathname);
        onConnect(session);
      })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : '邮箱验证失败，请重新发送验证邮件');
      })
      .finally(() => { if (!cancelled) setSubmitting(false); });
    return () => { cancelled = true; };
  }, [onConnect]);

  const connect = async () => {
    if (loading) return;
    try {
      setSubmitting(true);
      if (mode === 'register') {
        await registerAccount({
          email,
          password,
          display_name: displayName,
          organization_name: organizationName,
        });
        setMode('login');
        setPassword('');
        setNotice('验证邮件已发送。完成邮箱验证后即可登录。');
        setError(null);
        return;
      }
      const issued = await loginAccount(email, password);
      const session = saveIdentitySession(issued);
      if (isSessionExpired(session)) throw new Error('JWT 已过期，请获取新的管理会话');
      setError(null);
      onConnect(session);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '无法建立管理会话');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="session-shell">
      <section className="session-panel" aria-label="连接 Candy Cloud">
        <div className="session-brand">
          <div className="brand-mark">C</div>
          <div>
            <Typography.Title heading={3}>Candy Cloud</Typography.Title>
            <Typography.Text type="secondary">SD-WAN 管理控制台</Typography.Text>
          </div>
        </div>
        <div className="session-heading">
          <Tag color="arcoblue" icon={<IconLock />}>{mode === 'login' ? '安全登录' : '创建组织'}</Tag>
          <Typography.Title heading={4}>{mode === 'login' ? '登录控制面' : '开始管理你的网络'}</Typography.Title>
          <Typography.Paragraph type="secondary">
            {mode === 'login' ? '使用 Candy Cloud 账户安全登录。' : '创建管理员账户和首个网络组织。'} 会话仅保留在当前浏览器标签页中。
          </Typography.Paragraph>
        </div>
        {error && <Alert type="error" content={error} showIcon />}
        {notice && <Alert type="success" content={notice} showIcon />}
        <Form layout="vertical" className="session-form">
          {mode === 'register' && <>
            <Form.Item label="姓名" required>
              <Input value={displayName} onChange={setDisplayName} placeholder="你的姓名" autoComplete="name" />
            </Form.Item>
            <Form.Item label="组织名称" required>
              <Input value={organizationName} onChange={setOrganizationName} placeholder="例如：Acme Network" autoComplete="organization" />
            </Form.Item>
          </>}
          <Form.Item label="邮箱" required>
            <Input value={email} onChange={setEmail} placeholder="name@example.com" autoComplete="email" />
          </Form.Item>
          <Form.Item label="密码" required>
            <Input.Password value={password} onChange={setPassword} placeholder="至少 12 位" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} onPressEnter={() => void connect()} />
          </Form.Item>
          <Button type="primary" long size="large" icon={<IconRight />} loading={submitting || loading} onClick={() => void connect()} disabled={loading || !email.trim() || !password || (mode === 'register' && (!displayName.trim() || !organizationName.trim()))}>
            {mode === 'login' ? '登录' : '创建账户'}
          </Button>
        </Form>
        <Button type="text" className="session-switch" disabled={loading} onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null); setNotice(null); }}>
          {mode === 'login' ? '还没有账户？创建组织' : '已有账户？登录'}
        </Button>
        <Space className="session-footnote" size={6}>
          <span className="secure-dot" />
          <Typography.Text type="secondary">凭据仅保留在 sessionStorage</Typography.Text>
        </Space>
      </section>
      <aside className="session-context" aria-label="Candy Cloud 控制面能力">
        <div className="session-context-head">
          <Tag color="arcoblue">CLOUD 0.1</Tag>
          <Typography.Title heading={2}>站点、路径与出口，统一编排。</Typography.Title>
          <Typography.Paragraph>Cloud 只管理控制意图与签名投影，不进入客户数据面转发路径。</Typography.Paragraph>
        </div>
        <div className="session-capabilities">
          <div><IconBranch /><strong>多站点互联</strong><span>全双工 TUN 与站点网段管理</span></div>
          <div><IconThunderbolt /><strong>路径与出口</strong><span>直连、Relay 与远端 Candy 出口</span></div>
          <div><IconSafe /><strong>签名同步</strong><span>mTLS 身份、ETag 与原子应用</span></div>
        </div>
        <div className="session-core-line"><IconCloud /><span>Candy Core 0.3.10 · Wire 0.3</span></div>
      </aside>
    </main>
  );
}
