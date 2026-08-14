import { useCallback, useEffect, useMemo, useState } from 'react';
import { Avatar, Button, Dropdown, Layout, Menu, Space, Tabs, Tag, Tooltip, Typography } from '@arco-design/web-react';
import {
  IconApps,
  IconBranch,
  IconCloud,
  IconDashboard,
  IconDesktop,
  IconDown,
  IconLocation,
  IconLink,
  IconMenuFold,
  IconMenuUnfold,
  IconPoweroff,
  IconSafe,
  IconSettings,
  IconStorage,
  IconUser,
  IconWifi,
} from '@arco-design/web-react/icon';
import { acceptOrganizationInvitation, listAccountMemberships, logoutAccount, refreshStoredSession, switchAccountContext } from './api';
import { clearSession, isSessionExpiringSoon, loadRefreshToken, loadSession, saveIdentitySession } from './session';
import type { IdentityMembership, ResourceDefinition, Session } from './types';
import { resourceDefinitions, pathDefinition } from './resource-definitions';
import { SessionGate } from './components/SessionGate';
import { Overview } from './components/Overview';
import { ResourcePage } from './components/ResourcePage';
import { SystemPage } from './components/SystemPage';
import { AccountSecurity } from './components/AccountSecurity';
import { OrganizationAccess } from './components/OrganizationAccess';
import { NodeEnrollment } from './components/NodeEnrollment';

const iconByKey: Record<string, React.ReactNode> = {
  sites: <IconLocation />,
  nodes: <IconDesktop />,
  segments: <IconBranch />,
  attachments: <IconLink />,
  prefixes: <IconStorage />,
  peers: <IconWifi />,
  egress: <IconCloud />,
  policies: <IconSafe />,
  dns: <IconApps />,
  relays: <IconBranch />,
};

function shortId(value?: string): string {
  return value ? `${value.slice(0, 8)}…${value.slice(-4)}` : '未识别租户';
}

function pageDefinition(key: string): ResourceDefinition | undefined {
  return resourceDefinitions.find((definition) => definition.key === key);
}

export default function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [restoring, setRestoring] = useState(true);
  const [selected, setSelected] = useState('overview');
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [createRequest, setCreateRequest] = useState<{ key: string; nonce: number }>({ key: '', nonce: 0 });
  const [memberships, setMemberships] = useState<IdentityMembership[]>([]);

  const selectedDefinition = useMemo(() => pageDefinition(selected), [selected]);
  const connect = useCallback((next: Session) => { setSession(next); }, []);

  useEffect(() => {
    let cancelled = false;
    const restore = async () => {
      const current = loadSession();
      const refresh = loadRefreshToken();
      if (current && !isSessionExpiringSoon(current)) {
        if (!cancelled) setSession(current);
        if (!cancelled) setRestoring(false);
        return;
      }
      if (!refresh) {
        if (!cancelled) setRestoring(false);
        return;
      }
      try {
        const token = await refreshStoredSession();
        const next = loadSession();
        if (!token || !next) throw new Error('session refresh failed');
        if (!cancelled) setSession(next);
      } catch {
        clearSession();
        if (!cancelled) setSession(null);
      } finally {
        if (!cancelled) setRestoring(false);
      }
    };
    void restore();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!session) { setMemberships([]); return; }
    void listAccountMemberships(session.token).then(setMemberships).catch(() => setMemberships(session.membership ? [session.membership] : []));
  }, [session]);

  useEffect(() => {
    if (!session) return;
    const token = new URLSearchParams(window.location.search).get('accept_invitation');
    if (!token) return;
    void acceptOrganizationInvitation(session.token, token).then(async () => {
      window.history.replaceState({}, document.title, window.location.pathname);
      setMemberships(await listAccountMemberships(session.token));
    }).catch(() => undefined);
  }, [session]);

  if (restoring || !session) {
    return <SessionGate loading={restoring} onConnect={connect} />;
  }

  const clearLocalSession = () => {
    clearSession();
    setSession(null);
    setSelected('overview');
  };

  const disconnect = () => {
    void logoutAccount(session.token).catch(() => undefined);
    clearLocalSession();
  };

  const accountMenu = (
    <Menu>
      <Menu.Item key="account" onClick={() => setSelected('account')}><IconSafe /> 账户与安全</Menu.Item>
      <Menu.Item key="disconnect" onClick={disconnect}><IconPoweroff /> 断开会话</Menu.Item>
    </Menu>
  );

  const switchContext = async (organizationId: string) => {
    if (organizationId === session.membership?.organization_id) return;
    const next = saveIdentitySession(await switchAccountContext(session.token, organizationId));
    setSession(next);
    setSelected('overview');
  };

  return (
    <Layout className="app-layout">
      <Layout.Sider className={`app-sider ${mobileNav ? 'mobile-open' : ''}`} width={232} collapsedWidth={64} collapsed={collapsed}>
        <div className="sidebar-brand">
          <div className="brand-mark small">C</div>
          {!collapsed && <div><strong>Candy Cloud</strong><span>CONTROL PLANE</span></div>}
        </div>
        <Menu
          theme="dark"
          selectedKeys={[selected]}
          onClickMenuItem={(key) => { setSelected(key); setCreateRequest({ key: '', nonce: 0 }); setMobileNav(false); }}
          collapse={collapsed}
          className="side-menu"
        >
          <Menu.Item key="overview"><IconDashboard />运营概览</Menu.Item>
          {resourceDefinitions.filter((item) => ['sites', 'nodes'].includes(item.key)).map((item) => <Menu.Item key={item.key} key-path={item.key}>{iconByKey[item.key]}{item.label}</Menu.Item>)}
          {resourceDefinitions.filter((item) => ['segments', 'attachments', 'prefixes'].includes(item.key)).map((item) => <Menu.Item key={item.key}>{iconByKey[item.key]}{item.label}</Menu.Item>)}
          <Menu.Item key="peers"><IconWifi />站点互联</Menu.Item>
          {resourceDefinitions.filter((item) => ['egress', 'policies', 'dns', 'relays'].includes(item.key)).map((item) => <Menu.Item key={item.key}>{iconByKey[item.key]}{item.label}</Menu.Item>)}
          <Menu.Item key="system"><IconSettings />系统</Menu.Item>
          {['ORGANIZATION_OWNER', 'TENANT_ADMIN', 'AUDITOR'].includes(session.membership?.role ?? session.claims.role ?? '') && <Menu.Item key="access"><IconSafe />成员与权限</Menu.Item>}
          <Menu.Item key="account"><IconUser />账户与安全</Menu.Item>
        </Menu>
        <div className="sidebar-foot">
          <Tooltip content={collapsed ? '展开导航' : '收起导航'} position="right">
            <Button type="text" icon={collapsed ? <IconMenuUnfold /> : <IconMenuFold />} onClick={() => setCollapsed((value) => !value)} />
          </Tooltip>
        </div>
      </Layout.Sider>
      {mobileNav && <button className="nav-backdrop" type="button" aria-label="关闭导航" onClick={() => setMobileNav(false)} />}
      <Layout className="main-layout">
        <header className="topbar">
          <div className="topbar-context">
            <Button type="text" className="mobile-nav-button" icon={<IconMenuUnfold />} aria-label="打开导航" onClick={() => setMobileNav(true)} />
            <Tag color="arcoblue">组织</Tag>
          {memberships.length > 1 ? <Dropdown trigger="click" droplist={<Menu selectedKeys={[session.membership?.organization_id ?? '']} onClickMenuItem={(key) => void switchContext(key)}>{memberships.map((item) => <Menu.Item key={item.organization_id}>{item.organization_name}<small className="context-role">{item.role}</small></Menu.Item>)}</Menu>} position="bl"><button type="button" className="context-switch">{session.membership?.organization_name ?? shortId(session.claims.organization_id)} <IconDown /></button></Dropdown> : <Tooltip content={session.claims.tenant_id ?? 'JWT 未包含 tenant_id'}><span>{session.membership?.organization_name ?? shortId(session.claims.organization_id)}</span></Tooltip>}
          </div>
          <Dropdown trigger="click" droplist={accountMenu} position="br">
            <button className="account-button" type="button" aria-label="打开账户菜单">
              <Avatar size={30}><IconUser /></Avatar>
              <span className="account-copy"><strong>{session.user?.display_name ?? session.claims.sub ?? 'Cloud Operator'}</strong><small>{session.membership?.role ?? session.claims.role ?? 'role unavailable'}</small></span>
              <IconDown />
            </button>
          </Dropdown>
        </header>
        <Layout.Content className="workspace">
          {selected === 'overview' && <Overview session={session} />}
          {selected === 'enrollment' && <NodeEnrollment session={session} onBack={() => setSelected('nodes')} onCreateSite={() => { setSelected('sites'); setCreateRequest({ key: 'sites', nonce: Date.now() }); }} onFinished={() => setSelected('nodes')} />}
          {selectedDefinition && selected !== 'peers' && <ResourcePage definition={selectedDefinition} session={session} createRequest={createRequest.key === selected ? createRequest.nonce : 0} onEnrollNode={() => { setSelected('enrollment'); setCreateRequest({ key: '', nonce: 0 }); }} />}
          {selected === 'peers' && (
            <Tabs className="peer-tabs" defaultActiveTab="relationships" destroyOnHide lazyload>
              <Tabs.TabPane key="relationships" title="互联关系"><ResourcePage definition={pageDefinition('peers')!} session={session} /></Tabs.TabPane>
              <Tabs.TabPane key="candidates" title="线路配置"><ResourcePage definition={pathDefinition} session={session} /></Tabs.TabPane>
            </Tabs>
          )}
          {selected === 'system' && <SystemPage session={session} />}
          {selected === 'account' && <AccountSecurity session={session} onDisconnect={clearLocalSession} />}
          {selected === 'access' && <OrganizationAccess session={session} onSessionInvalidated={clearLocalSession} />}
        </Layout.Content>
        <footer className="workspace-footer">
          <Space size={6}><span className="secure-dot" /><Typography.Text type="secondary">Cloud API · same-origin /api</Typography.Text></Space>
        </footer>
      </Layout>
    </Layout>
  );
}
