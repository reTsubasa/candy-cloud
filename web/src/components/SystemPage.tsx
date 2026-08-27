import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Descriptions, Drawer, Empty, Input, Select, Spin, Table, Tabs, Tag, Typography } from '@arco-design/web-react';
import { IconRefresh } from '@arco-design/web-react/icon';
import { fetchHealth, listAuditEvents } from '../api';
import type { AuditEvent, HealthState, Session } from '../types';

const healthMeta = {
  live: { label: '服务进程', endpoint: '/api/health/live' },
  ready: { label: '对外服务', endpoint: '/api/health/ready' },
  degraded: { label: '依赖状态', endpoint: '/api/health/degraded' },
};

const emptyHealth: HealthState = {
  live: { status: null, text: '', loading: true, checkedAt: null },
  ready: { status: null, text: '', loading: true, checkedAt: null },
  degraded: { status: null, text: '', loading: true, checkedAt: null },
};

type Props = { session: Session; initialTab?: 'status' | 'logs' };
type LogLevel = 'error' | 'warning' | 'info';
type LogCategory = 'operations' | 'runtime' | 'security' | 'all';

function eventLevel(action: string): LogLevel {
  const normalized = action.toUpperCase();
  if (normalized === 'RUNTIME_FAIL_OPEN_ENTERED') return 'error';
  if (/(FAILED|FAILURE|REJECTED|ERROR|DENIED)/.test(normalized)) return 'error';
  if (/(REVOKED|EXPIRED|DEGRADED|DISABLED)/.test(normalized)) return 'warning';
  return 'info';
}

const levelMeta = {
  error: { label: '错误', color: 'red' },
  warning: { label: '警告', color: 'orange' },
  info: { label: '信息', color: 'arcoblue' },
} as const;

const eventLabels: Record<string, { title: string; detail: string }> = {
  IDENTITY_REGISTRATION_REQUESTED: { title: '申请创建账户', detail: '用户提交了账户和组织注册申请。' },
  IDENTITY_LOGIN_SUCCEEDED: { title: '登录成功', detail: '账户完成了身份验证并建立管理会话。' },
  IDENTITY_REFRESH_SUCCEEDED: { title: '会话刷新成功', detail: '管理会话已续期。' },
  IDENTITY_LOGIN_FAILED: { title: '登录失败', detail: '账户身份验证未通过。' },
  IDENTITY_LOGIN_REJECTED: { title: '登录被拒绝', detail: '账户身份验证未通过。' },
  IDENTITY_REFRESH_FAILED: { title: '会话刷新失败', detail: '会话续期未完成，可能需要重新登录。' },
  IDENTITY_REFRESH_REJECTED: { title: '会话刷新被拒绝', detail: '会话续期未通过安全校验，可能需要重新登录。' },
  IDENTITY_EMAIL_VERIFIED: { title: '验证账户邮箱', detail: '用户完成了邮箱验证并激活账户。' },
  IDENTITY_VERIFICATION_RESEND_REQUESTED: { title: '重发验证邮件', detail: '用户申请重新发送账户验证邮件。' },
  IDENTITY_PASSWORD_RESET_REQUESTED: { title: '申请重置密码', detail: '用户申请发送密码重置邮件。' },
  IDENTITY_PASSWORD_RESET_COMPLETED: { title: '完成密码重置', detail: '用户已修改账户密码，原有管理会话已撤销。' },
  IDENTITY_SESSION_LOGGED_OUT: { title: '退出管理会话', detail: '用户退出了当前管理会话。' },
  IDENTITY_SESSION_REVOKED: { title: '撤销管理会话', detail: '用户主动撤销了一个管理会话。' },
  IDENTITY_CONTEXT_SWITCHED: { title: '切换组织上下文', detail: '用户切换了当前管理的组织和租户。' },
  ENROLLMENT_ACTIVATION_CREATED: { title: '创建节点注册码', detail: '用户创建了新的节点注册凭据。' },
  ENROLLMENT_ACTIVATION_REVOKED: { title: '撤销节点注册码', detail: '用户撤销了尚未完成的节点注册凭据。' },
  DEVICE_ENROLLMENT_REQUESTED: { title: '节点申请接入', detail: '节点使用注册码发起了接入申请。' },
  ENROLLMENT_CHALLENGE_CREATED: { title: '生成节点认证挑战', detail: 'Cloud 为节点接入生成了一次认证挑战。' },
  ENROLLMENT_PROOF_VERIFIED: { title: '节点身份验证通过', detail: '节点完成了接入证明校验。' },
  DEVICE_IDENTITY_ISSUED: { title: '签发节点身份', detail: 'Cloud 已为通过验证的节点签发设备身份。' },
  ORGANIZATION_INVITATION_CREATED: { title: '邀请组织成员', detail: '用户发出了新的组织成员邀请。' },
  ORGANIZATION_INVITATION_ACCEPTED: { title: '接受成员邀请', detail: '用户接受邀请并加入了组织。' },
  ORGANIZATION_INVITATION_REVOKED: { title: '撤销成员邀请', detail: '尚未接受的组织成员邀请已撤销。' },
  ORGANIZATION_MEMBER_ROLE_CHANGED: { title: '修改成员角色', detail: '用户修改了组织成员的访问角色，并撤销了其旧会话。' },
  ORGANIZATION_MEMBER_REACTIVATED: { title: '恢复组织成员', detail: '用户恢复了组织成员的访问权限。' },
  ORGANIZATION_MEMBER_SUSPENDED: { title: '停用组织成员', detail: '用户停用了组织成员并撤销了其管理会话。' },
  ORGANIZATION_MEMBER_REMOVED: { title: '移除组织成员', detail: '用户从组织中移除了一名成员。' },
  ORGANIZATION_OWNERSHIP_TRANSFERRED: { title: '转移组织所有权', detail: '组织所有权已转移给另一名成员。' },
  SDWAN_SEGMENT_ROUTES_PUBLISHED: { title: '网络路由已发布', detail: 'Cloud 已生成并发布该网络分段的签名路由配置。' },
  CONTROL_NODE_IDENTITY_REPLACED: { title: '节点身份已更新', detail: '节点重新加入后，Cloud 已替换其设备身份。' },
  CONTROL_NODE_ENROLLED: { title: '节点已加入', detail: '节点完成注册并加入当前租户。' },
  CONTROL_RESOURCE_CREATED: { title: '配置已创建', detail: '控制面创建了一项新的网络配置。' },
  CONTROL_RESOURCE_UPDATED: { title: '配置已更新', detail: '控制面更新了一项网络配置。' },
  CONTROL_RESOURCE_DELETED: { title: '配置已删除', detail: '控制面删除了一项网络配置。' },
  RUNTIME_CONFIGURATION_REJECTED: { title: '节点拒绝配置', detail: '节点收到配置后未能应用，需检查节点运行日志。' },
  RUNTIME_CONFIGURATION_ACTIVATED: { title: '节点配置已激活', detail: '节点已平滑接管本批次配置，Cloud 将继续放行下一个节点。' },
  RUNTIME_FAIL_OPEN_ENTERED: { title: '节点进入故障开放', detail: 'Candy 数据面已退出，基础网络保持可用。' },
  RUNTIME_FAIL_OPEN_RECOVERED: { title: '节点已退出故障开放', detail: 'Candy 数据面已经恢复运行。' },
  RUNTIME_LIFECYCLE_DEGRADED: { title: '节点运行状态异常', detail: 'Runtime 上报了停止、启动中或降级状态。' },
  RUNTIME_LIFECYCLE_RECOVERED: { title: '节点运行状态恢复', detail: 'Runtime 已恢复为活跃状态。' },
};

const objectLabels: Record<string, string> = {
  HUMAN_ACCOUNT: '用户账户', DEVICE: '节点', NODE: '节点', SEGMENT: '网络分段',
  SITE: '站点', ATTACHMENT: '节点接入', PREFIX: '发布网段', PEER: '站点互联', RELAY: '中继',
  PATH_CANDIDATE: '线路', EGRESS: '出口', SERVICE_POLICY: '流量策略', DNS_INTENT: 'DNS 配置',
  ENROLLMENT_ACTIVATION: '节点注册码', ENROLLMENT_CHALLENGE: '节点认证挑战', ORGANIZATION_MEMBERSHIP: '组织成员', ORGANIZATION: '组织',
  ORGANIZATION_INVITATION: '成员邀请',
};

const actorLabels: Record<string, string> = {
  HUMAN_ACCOUNT: '用户', USER: '用户', IDENTITY: '身份服务', WORKER: 'Cloud Worker', DEVICE: '节点', SYSTEM: '系统',
};

function auditMetadata(event: AuditEvent): Record<string, unknown> {
  try {
    const value = JSON.parse(event.metadata_json) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function eventLabel(event: AuditEvent): string {
  if (eventLabels[event.action]) {
    if (/^CONTROL_RESOURCE_(CREATED|UPDATED|DELETED)$/.test(event.action)) {
      const verb = event.action.endsWith('CREATED') ? '创建' : event.action.endsWith('UPDATED') ? '更新' : '删除';
      return `${verb}${objectLabel(event.object_type)}`;
    }
    return eventLabels[event.action].title;
  }
  return `${objectLabel(event.object_type)}事件`;
}

const fieldLabels: Record<string, string> = {
  name: '名称', display_name: '显示名称', kind: '类型', site_id: '站点', node_id: '节点',
  segment_id: '网络分段', attachment_id: '接入点', overlay_prefix: 'Overlay 网段',
  overlay_router_ipv4: 'Overlay 地址', prefix: '发布网段', path_policy: '线路策略',
  priority: '优先级', transport_node_id: '传输节点', max_sessions: '最大会话数',
  max_bits_per_second: '带宽上限', generation: '策略版本', rules: '规则', zone: 'DNS 区域',
  records: 'DNS 记录', state: '状态',
};

function eventDescription(event: AuditEvent): string {
  if (/^CONTROL_RESOURCE_(CREATED|UPDATED|DELETED)$/.test(event.action)) {
    const metadata = auditMetadata(event);
    const name = typeof metadata.resource_name === 'string' && metadata.resource_name ? `“${metadata.resource_name}”` : '';
    const fields = Array.isArray(metadata.changed_fields)
      ? metadata.changed_fields.filter((value): value is string => typeof value === 'string').map((value) => fieldLabels[value] ?? value)
      : [];
    const verb = event.action.endsWith('CREATED') ? '创建了' : event.action.endsWith('UPDATED') ? '更新了' : '删除了';
    return `用户${verb}${objectLabel(event.object_type)}${name}${fields.length ? `，涉及：${fields.join('、')}` : ''}。`;
  }
  return eventLabels[event.action]?.detail ?? '控制面记录了一项运行或配置事件。';
}

function eventCategory(event: AuditEvent): Exclude<LogCategory, 'all'> {
  if (event.actor_type === 'USER' && !event.action.startsWith('IDENTITY_')) return 'operations';
  if (/^(CONTROL_RESOURCE_|ENROLLMENT_ACTIVATION_|ORGANIZATION_)/.test(event.action)) return 'operations';
  if (/^(IDENTITY_|PASSWORD_|SESSION_)/.test(event.action) || event.object_type === 'HUMAN_ACCOUNT') return 'security';
  return 'runtime';
}

function objectLabel(value: string): string {
  return objectLabels[value] ?? value;
}

function actorLabel(value: string): string {
  return actorLabels[value] ?? value;
}

function eventActorLabel(event: AuditEvent): string {
  return event.actor_display_name?.trim() || event.actor_email?.trim() || actorLabel(event.actor_type);
}

function formatEventTime(value: string, now = new Date()): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const time = date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  if (date.toDateString() === now.toDateString()) return '今天 ' + time;
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return '昨天 ' + time;
  return date.toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatMetadata(value: string): string {
  if (!value) return '暂无结构化详情';
  try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
}

function eventObjectName(event: AuditEvent): string | null {
  const metadata = auditMetadata(event);
  for (const value of [metadata.resource_name, metadata.device_name]) {
    if (typeof value === 'string' && value.trim()) return value;
  }
  return null;
}

export function SystemPage({ session, initialTab = 'status' }: Props) {
  const [health, setHealth] = useState(emptyHealth);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<LogCategory>('all');
  const [levelFilter, setLevelFilter] = useState<'all' | LogLevel>('all');
  const [actionFilter, setActionFilter] = useState('');
  const [textFilter, setTextFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setAuditError(null);
    const [live, ready, degraded, audit] = await Promise.all([
      fetchHealth('live'), fetchHealth('ready'), fetchHealth('degraded'),
      session.claims.tenant_id ? listAuditEvents(session.token, session.claims.tenant_id).catch((error) => {
        setAuditError(error instanceof Error ? error.message : '统一日志暂不可用');
        return { schema_version: 1, items: [] };
      }) : Promise.resolve({ schema_version: 1, items: [] }),
    ]);
    setHealth({ live, ready, degraded });
    setEvents(audit.items);
    setLoading(false);
  }, [session.claims.tenant_id, session.token]);

  useEffect(() => { void load(); }, [load]);

  const actionOptions = useMemo(() => Array.from(new Map(events.map((event) => [event.action, event])).values())
    .sort((left, right) => eventLabel(left).localeCompare(eventLabel(right), 'zh-CN')), [events]);
  const filtered = useMemo(() => events.filter((event) => {
    if (categoryFilter !== 'all' && eventCategory(event) !== categoryFilter) return false;
    if (levelFilter !== 'all' && eventLevel(event.action) !== levelFilter) return false;
    if (actionFilter && event.action !== actionFilter) return false;
    if (textFilter) {
      const haystack = `${event.action} ${event.object_type} ${event.actor_type} ${event.actor_display_name ?? ''} ${event.actor_email ?? ''} ${event.metadata_json}`.toLowerCase();
      if (!haystack.includes(textFilter.toLowerCase())) return false;
    }
    return true;
  }), [actionFilter, categoryFilter, events, levelFilter, textFilter]);

  return (
    <section className="workspace-section">
      <header className="page-header">
        <div><Typography.Title heading={4}>{initialTab === 'logs' ? '日志' : '系统'}</Typography.Title><Typography.Text type="secondary">{initialTab === 'logs' ? '控制面、配置与节点事件的统一记录' : '控制面状态与管理会话'}</Typography.Text></div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      <Tabs defaultActiveTab={initialTab} className="system-tabs single-tab">
        {initialTab !== 'logs' && <Tabs.TabPane key="status" title="运行状态"><Spin loading={loading} block>
          <div className="system-grid">
            <section className="detail-surface"><Typography.Title heading={5}>控制面健康</Typography.Title><Descriptions column={1} data={(['live', 'ready', 'degraded'] as const).map((key) => ({ label: healthMeta[key].label, value: <div className="health-detail"><span><Tag color={health[key].status === 200 ? 'green' : health[key].status === null ? 'red' : 'orange'}>{health[key].status === 200 ? '正常' : health[key].status === null ? '不可达' : '异常'}</Tag> {health[key].text || '—'}</span><code>{healthMeta[key].endpoint}</code></div> }))} /></section>
            <section className="detail-surface"><Typography.Title heading={5}>管理会话</Typography.Title><Descriptions column={1} data={[
              { label: '当前用户', value: session.user?.display_name ?? session.claims.sub ?? '未提供' },
              { label: '租户 ID', value: <span className="mono break-all">{session.claims.tenant_id ?? '未提供'}</span> },
              { label: '组织 ID', value: <span className="mono break-all">{session.claims.organization_id ?? '未提供'}</span> },
              { label: '访问角色', value: session.membership?.role ?? session.claims.role ?? '未提供' },
              { label: '会话到期', value: session.claims.exp ? new Date(session.claims.exp * 1000).toLocaleString() : '未提供' },
            ]} /></section>
          </div>
        </Spin></Tabs.TabPane>}
        {initialTab !== 'status' && <Tabs.TabPane key="logs" title="统一日志">
          <div className="log-toolbar"><div><Typography.Text bold>运行日志</Typography.Text><Typography.Text type="secondary">点击任意记录查看完整内容 · 最近 {events.length} 条</Typography.Text></div><Typography.Text type="secondary">{filtered.length} / {events.length} 条</Typography.Text></div>
          <div className="log-filters">
            <Select value={categoryFilter} onChange={(value) => setCategoryFilter(value as LogCategory)} aria-label="日志分类" style={{ width: 150 }}><Select.Option value="all">全部有效事件</Select.Option><Select.Option value="operations">产品操作</Select.Option><Select.Option value="runtime">运行事件</Select.Option><Select.Option value="security">身份安全</Select.Option></Select>
            <Select value={levelFilter} onChange={(value) => setLevelFilter(value as typeof levelFilter)} aria-label="日志级别" style={{ width: 140 }}><Select.Option value="all">全部级别</Select.Option><Select.Option value="error">错误</Select.Option><Select.Option value="warning">警告</Select.Option><Select.Option value="info">信息</Select.Option></Select>
            <Select value={actionFilter} onChange={setActionFilter} placeholder="全部事件" allowClear style={{ width: 240 }}>{actionOptions.map((event) => <Select.Option key={event.action} value={event.action}>{eventLabel(event)}</Select.Option>)}</Select>
            <Input.Search value={textFilter} onChange={setTextFilter} allowClear placeholder="搜索事件、对象或详情" style={{ width: 280 }} />
          </div>
          {auditError && <div className="log-warning"><Tag color="orange">读取异常</Tag><Typography.Text type="secondary">{auditError}</Typography.Text></div>}
          <div className="table-surface operation-log-table">{filtered.length === 0 && !loading ? <Empty description={events.length ? '没有符合筛选条件的日志' : '暂无运行日志'} /> : <Table rowKey="id" loading={loading} data={filtered} pagination={filtered.length > 50 ? { pageSize: 50, sizeCanChange: true } : false} onRow={(item) => ({ onClick: () => setSelectedEvent(item), className: 'log-row-clickable' })} columns={[
            { title: '级别', width: 88, render: (_: unknown, item: AuditEvent) => { const meta = levelMeta[eventLevel(item.action)]; return <Tag color={meta.color}>{meta.label}</Tag>; } },
            { title: '事件', dataIndex: 'action', width: 330, render: (_: string, item: AuditEvent) => <div className="log-event-cell"><strong>{eventLabel(item)}</strong><small>{eventDescription(item)}</small></div> },
            { title: '对象', width: 150, render: (_: unknown, item: AuditEvent) => <div className="log-object-cell"><strong>{eventObjectName(item) ?? objectLabel(item.object_type)}</strong><small>{eventObjectName(item) ? objectLabel(item.object_type) : item.object_id ? '配置对象' : '全局事件'}</small></div> },
            { title: '来源', width: 190, render: (_: unknown, item: AuditEvent) => <div className="log-object-cell"><strong>{eventActorLabel(item)}</strong><small>{item.actor_email && item.actor_email !== eventActorLabel(item) ? item.actor_email : actorLabel(item.actor_type)}</small></div> },
            { title: '发生时间', width: 180, render: (_: unknown, item: AuditEvent) => <Typography.Text>{formatEventTime(item.created_at)}</Typography.Text> },
          ]} />}</div>
        </Tabs.TabPane>}
      </Tabs>
      <Drawer width={520} title={selectedEvent ? eventLabel(selectedEvent) : '日志详情'} visible={selectedEvent !== null} onCancel={() => setSelectedEvent(null)} footer={null}>
        {selectedEvent && <div className="log-detail-drawer">
          <div className="log-detail-summary"><Tag color={levelMeta[eventLevel(selectedEvent.action)].color}>{levelMeta[eventLevel(selectedEvent.action)].label}</Tag><div><strong>{eventDescription(selectedEvent)}</strong><span>{formatEventTime(selectedEvent.created_at)} · {new Date(selectedEvent.created_at).toLocaleString('zh-CN')}</span></div></div>
          <Descriptions column={1} data={[
            { label: '事件', value: <span>{eventLabel(selectedEvent)} <code>{selectedEvent.action}</code></span> },
            { label: '对象', value: objectLabel(selectedEvent.object_type) + (selectedEvent.object_id ? ` · ${selectedEvent.object_id}` : '') },
            { label: '来源', value: actorLabel(selectedEvent.actor_type) },
            { label: '操作者', value: selectedEvent.actor_id ?? '系统生成' },
            { label: '发生时间', value: new Date(selectedEvent.created_at).toLocaleString('zh-CN') },
          ]} />
          <Typography.Title heading={6}>完整事件内容</Typography.Title>
          <pre className="log-details log-detail-full">{formatMetadata(selectedEvent.metadata_json)}</pre>
        </div>}
      </Drawer>
    </section>
  );
}
