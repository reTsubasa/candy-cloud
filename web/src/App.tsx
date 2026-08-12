import { useCallback, useEffect, useMemo, useState } from 'react';
import { Avatar, Button, Dropdown, Layout, Menu, Space, Tag, Tooltip, Typography } from '@arco-design/web-react';
import {
  IconApps,
  IconBranch,
  IconCloud,
  IconDashboard,
  IconDesktop,
  IconDown,
  IconLocation,
  IconMenuFold,
  IconMenuUnfold,
  IconPoweroff,
  IconSafe,
  IconSettings,
  IconStorage,
  IconUser,
  IconWifi,
} from '@arco-design/web-react/icon';
import { logoutAccount, refreshStoredSession } from './api';
import { clearSession, isSessionExpiringSoon, loadRefreshToken, loadSession } from './session';
import type { ResourceDefinition, Session } from './types';
import { resourceDefinitions, pathDefinition } from './resource-definitions';
import { SessionGate } from './components/SessionGate';
import { Overview } from './components/Overview';
import { ResourcePage } from './components/ResourcePage';
import { SystemPage } from './components/SystemPage';
import { AccountSecurity } from './components/AccountSecurity';

const iconByKey: Record<string, React.ReactNode> = {
  sites: <IconLocation />,
  nodes: <IconDesktop />,
  segments: <IconBranch />,
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
          onClickMenuItem={(key) => { setSelected(key); setMobileNav(false); }}
          collapse={collapsed}
          className="side-menu"
        >
          <Menu.Item key="overview"><IconDashboard />运营概览</Menu.Item>
          {resourceDefinitions.slice(0, 4).map((item) => <Menu.Item key={item.key} key-path={item.key}>{iconByKey[item.key]}{item.label}</Menu.Item>)}
          <Menu.Item key="peers"><IconWifi />对等与路径</Menu.Item>
          {resourceDefinitions.slice(5).map((item) => <Menu.Item key={item.key}>{iconByKey[item.key]}{item.label}</Menu.Item>)}
          <Menu.Item key="system"><IconSettings />系统</Menu.Item>
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
            <Tag color="arcoblue">TENANT</Tag>
            <Tooltip content={session.claims.tenant_id ?? 'JWT 未包含 tenant_id'}><span className="mono">{shortId(session.claims.tenant_id)}</span></Tooltip>
          </div>
          <Dropdown droplist={accountMenu} position="br">
            <button className="account-button" type="button">
              <Avatar size={30}><IconUser /></Avatar>
              <span className="account-copy"><strong>{session.user?.display_name ?? session.claims.sub ?? 'Cloud Operator'}</strong><small>{session.membership?.role ?? session.claims.role ?? 'role unavailable'}</small></span>
              <IconDown />
            </button>
          </Dropdown>
        </header>
        <Layout.Content className="workspace">
          {selected === 'overview' && <Overview session={session} />}
          {selectedDefinition && selected !== 'peers' && <ResourcePage definition={selectedDefinition} session={session} />}
          {selected === 'peers' && (
            <div className="dual-page">
              <ResourcePage definition={pageDefinition('peers')!} session={session} />
              <ResourcePage definition={pathDefinition} session={session} />
            </div>
          )}
          {selected === 'system' && <SystemPage session={session} />}
          {selected === 'account' && <AccountSecurity session={session} onDisconnect={clearLocalSession} />}
        </Layout.Content>
        <footer className="workspace-footer">
          <Space size={6}><span className="secure-dot" /><Typography.Text type="secondary">Cloud API · same-origin /api</Typography.Text></Space>
        </footer>
      </Layout>
    </Layout>
  );
}
