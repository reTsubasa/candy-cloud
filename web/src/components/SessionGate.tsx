import { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Space, Tag, Typography } from '@arco-design/web-react';
import { IconBranch, IconCloud, IconLock, IconRight, IconSafe, IconThunderbolt } from '@arco-design/web-react/icon';
import {
  loginAccount,
  registerAccount,
  registerFromOrganizationInvitation,
  requestEmailVerification,
  requestPasswordReset,
  resetAccountPassword,
  verifyAccountEmail,
} from '../api';
import { isSessionExpired, saveIdentitySession } from '../session';
import type { Session } from '../types';

type Props = {
  onConnect: (session: Session) => void;
  loading?: boolean;
};
type Mode = 'login' | 'register' | 'forgot' | 'reset' | 'resend' | 'invited';

function queryToken(name: string): string | null {
  return new URLSearchParams(window.location.search).get(name);
}

export function SessionGate({ onConnect, loading = false }: Props) {
  const [mode, setMode] = useState<Mode>(() => queryToken('reset_password') ? 'reset' : queryToken('accept_invitation') ? 'invited' : 'login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const token = queryToken('verify_email');
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

  const switchMode = (next: Mode) => {
    setMode(next);
    setError(null);
    setNotice(null);
    setPassword('');
    setConfirmation('');
  };

  const submit = async () => {
    if (loading || submitting) return;
    try {
      setSubmitting(true);
      setError(null);
      if (mode === 'register') {
        await registerAccount({ email, password, display_name: displayName, organization_name: organizationName });
        switchMode('login');
        setEmail(email.trim());
        setNotice('验证邮件已发送。完成邮箱验证后即可登录。');
        return;
      }
      if (mode === 'forgot') {
        await requestPasswordReset(email);
        setNotice('如果该邮箱已注册，密码重置邮件会很快送达。');
        return;
      }
      if (mode === 'resend') {
        await requestEmailVerification(email, password);
        setNotice('如果账户仍待验证，新的验证邮件会很快送达。');
        return;
      }
      if (mode === 'reset') {
        const token = queryToken('reset_password');
        if (!token) throw new Error('重置链接无效或已过期，请重新申请');
        if (password !== confirmation) throw new Error('两次输入的密码不一致');
        await resetAccountPassword(token, password);
        window.history.replaceState({}, document.title, window.location.pathname);
        switchMode('login');
        setNotice('密码已更新，所有旧会话都已退出。请使用新密码登录。');
        return;
      }
      if (mode === 'invited') {
        const token = queryToken('accept_invitation');
        if (!token) throw new Error('邀请链接无效或已过期');
        if (password !== confirmation) throw new Error('两次输入的密码不一致');
        const issued = await registerFromOrganizationInvitation(token, displayName, password);
        window.history.replaceState({}, document.title, window.location.pathname);
        onConnect(saveIdentitySession(issued));
        return;
      }
      const issued = await loginAccount(email, password);
      const session = saveIdentitySession(issued);
      if (isSessionExpired(session)) throw new Error('JWT 已过期，请获取新的管理会话');
      onConnect(session);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '请求未完成，请稍后重试');
    } finally {
      setSubmitting(false);
    }
  };

  const isPasswordMode = mode === 'login' || mode === 'register' || mode === 'resend' || mode === 'reset' || mode === 'invited';
  const title = mode === 'login' ? '登录控制面' : mode === 'register' ? '开始管理你的网络' : mode === 'forgot' ? '找回管理密码' : mode === 'reset' ? '设置新密码' : mode === 'invited' ? '加入组织' : '重发验证邮件';
  const tag = mode === 'register' ? '创建组织' : mode === 'forgot' || mode === 'reset' ? '账户恢复' : mode === 'resend' ? '邮箱验证' : mode === 'invited' ? '成员邀请' : '安全登录';
  const submitLabel = mode === 'login' ? '登录' : mode === 'register' ? '创建账户' : mode === 'forgot' ? '发送重置邮件' : mode === 'reset' ? '更新密码' : mode === 'invited' ? '创建账户并加入' : '重发验证邮件';

  return (
    <main className="session-shell">
      <section className="session-panel" aria-label="连接 Candy Cloud">
        <div className="session-brand"><div className="brand-mark">C</div><div><Typography.Title heading={3}>Candy Cloud</Typography.Title><Typography.Text type="secondary">SD-WAN 管理控制台</Typography.Text></div></div>
        <div className="session-heading"><Tag color="arcoblue" icon={<IconLock />}>{tag}</Tag><Typography.Title heading={4}>{title}</Typography.Title><Typography.Paragraph type="secondary">{mode === 'login' ? '使用 Candy Cloud 账户安全登录。' : mode === 'register' ? '创建管理员账户和首个网络组织。' : mode === 'forgot' ? '输入注册邮箱，我们会发送一次性重置链接。' : mode === 'reset' ? '新密码至少 12 位，更新后旧会话会全部失效。' : mode === 'invited' ? '设置姓名与密码，使用邀请邮箱创建账户并加入组织。' : '输入注册时使用的邮箱和密码，发送新的验证链接。'} 会话仅保留在当前浏览器标签页中。</Typography.Paragraph></div>
        {error && <Alert type="error" content={error} showIcon />}
        {notice && <Alert type="success" content={notice} showIcon />}
        <Form layout="vertical" className="session-form">
          {(mode === 'register' || mode === 'invited') && <Form.Item label="姓名" required><Input value={displayName} onChange={setDisplayName} placeholder="你的姓名" autoComplete="name" /></Form.Item>}
          {mode === 'register' && <Form.Item label="组织名称" required><Input value={organizationName} onChange={setOrganizationName} placeholder="例如：Acme Network" autoComplete="organization" /></Form.Item>}
          {mode !== 'reset' && mode !== 'invited' && <Form.Item label="邮箱" required><Input value={email} onChange={setEmail} placeholder="name@example.com" autoComplete="email" /></Form.Item>}
          {isPasswordMode && <Form.Item label={mode === 'resend' ? '当前密码' : '密码'} required><Input.Password value={password} onChange={setPassword} placeholder="至少 12 位" autoComplete={mode === 'login' || mode === 'resend' ? 'current-password' : 'new-password'} onPressEnter={() => void submit()} /></Form.Item>}
          {(mode === 'reset' || mode === 'invited') && <Form.Item label="确认新密码" required><Input.Password value={confirmation} onChange={setConfirmation} placeholder="再次输入新密码" autoComplete="new-password" /></Form.Item>}
          <Button type="primary" long size="large" icon={<IconRight />} loading={submitting || loading} onClick={() => void submit()} disabled={loading || submitting || (mode !== 'reset' && mode !== 'invited' && !email.trim()) || (isPasswordMode && !password) || (mode === 'register' && (!displayName.trim() || !organizationName.trim())) || (mode === 'invited' && (!displayName.trim() || !confirmation)) || (mode === 'reset' && !confirmation)}>{submitLabel}</Button>
        </Form>
        <Space direction="vertical" size={8} className="session-links">
          {mode === 'login' && <><Button type="text" onClick={() => switchMode('forgot')}>忘记密码？</Button><Button type="text" onClick={() => switchMode('resend')}>没有收到验证邮件？</Button><Button type="text" onClick={() => switchMode('register')}>还没有账户？创建组织</Button></>}
          {mode !== 'login' && <Button type="text" onClick={() => switchMode('login')}>返回登录</Button>}
        </Space>
        <Space className="session-footnote" size={6}><span className="secure-dot" /><Typography.Text type="secondary">凭据仅保留在 sessionStorage</Typography.Text></Space>
      </section>
      <aside className="session-context" aria-label="Candy Cloud 控制面能力"><div className="session-context-head"><Tag color="arcoblue">CLOUD 0.1</Tag><Typography.Title heading={2}>站点、路径与出口，统一编排。</Typography.Title><Typography.Paragraph>Cloud 只管理控制意图与签名投影，不进入客户数据面转发路径。</Typography.Paragraph></div><div className="session-capabilities"><div><IconBranch /><strong>多站点互联</strong><span>全双工 TUN 与站点网段管理</span></div><div><IconThunderbolt /><strong>路径与出口</strong><span>直连、Relay 与远端 Candy 出口</span></div><div><IconSafe /><strong>签名同步</strong><span>mTLS 身份、ETag 与原子应用</span></div></div><div className="session-core-line"><IconCloud /><span>Candy Core 0.3.10 · Wire 0.3</span></div></aside>
    </main>
  );
}
