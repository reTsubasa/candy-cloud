import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Collapse,
  Drawer,
  Form,
  Input,
  InputNumber,
  InputTag,
  Radio,
  Select,
  Space,
  Spin,
  Typography,
} from '@arco-design/web-react';
import { IconDelete, IconPlus, IconSave, IconSettings } from '@arco-design/web-react/icon';
import { createResource, listResources, replaceResource } from '../api';
import { defaultSpec } from '../resource-definitions';
import {
  buildResourceSpec,
  dnsRecordsForEditor,
  normalizeSpecForEditor,
  policyRulesForEditor,
  validateResourceEditor,
  type Spec,
} from '../resource-form';
import type { ControlResource, ResourceDefinition, ResourceOption, Session } from '../types';

type Props = {
  visible: boolean;
  definition: ResourceDefinition;
  session: Session;
  resource: ControlResource | null;
  onClose: () => void;
  onSaved: (resource: ControlResource) => void;
};

type ReferenceKey = 'sites' | 'nodes' | 'segments' | 'attachments' | 'peers' | 'egresses' | 'prefixes' | 'relays';
type References = Partial<Record<ReferenceKey, ResourceOption[]>>;

const referenceKeysByKind: Record<string, ReferenceKey[]> = {
  SITE: [],
  NODE: ['sites'],
  SEGMENT: [],
  PREFIX: ['sites', 'segments'],
  PEER: ['sites', 'segments'],
  PATH_CANDIDATE: ['segments', 'attachments', 'peers', 'relays'],
  EGRESS: ['sites', 'attachments'],
  RELAY: ['nodes'],
  SERVICE_POLICY: ['segments', 'sites', 'egresses'],
  DNS_INTENT: ['segments', 'sites', 'prefixes'],
};
const architectureOptions = ['aarch64', 'x86_64', 'arm_cortex-a7_neon-vfpv4', 'mipsel_24kc'].map((value) => ({ label: value, value }));
const trafficClassOptions = ['interactive', 'realtime', 'bulk', 'default'].map((value) => ({ label: value, value }));

function displayName(item: ControlResource): string {
  const spec = item.resource.spec;
  const prefix = spec.prefix as Spec | undefined;
  const overlay = spec.overlay_prefix as Spec | undefined;
  const primary = spec.display_name ?? spec.name ?? spec.zone ?? spec.endpoint;
  if (primary) return String(primary);
  if (prefix) return `${prefix.network}/${prefix.prefix_len}`;
  if (overlay) return `${overlay.network}/${overlay.prefix_len}`;
  return item.metadata.id;
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function optionFor(item: ControlResource): ResourceOption {
  const label = displayName(item);
  return { value: item.metadata.id, label, description: label === item.metadata.id ? undefined : shortId(item.metadata.id) };
}

function getValue(spec: Spec, key: string): string {
  return String(spec[key] ?? '');
}

function errorMessage(errors: string[]): string {
  const fieldLabels: Record<string, string> = {
    name: '名称', display_name: '节点名称', site_id: '站点', segment_id: '网络分段', device_id: '设备 ID',
    device_key_id: '设备密钥 ID', architecture: '架构', overlay_cidr: '覆盖网段', cidr: '网段',
    site_a_id: '站点 A', site_b_id: '站点 B', service_node_id: '服务节点', attachment_id: '接入关系',
    source_attachment_id: '源接入', destination_attachment_id: '目标接入', peer_id: '对等关系', relay_id: '中继',
    endpoint: '公网端点', priority: '优先级', max_sessions: '会话容量', capacity_mbps: '带宽容量',
    generation: '配置代次', zone: '内部域', value: '记录值', ttl_seconds: 'TTL', domains: '域名', destination_cidrs: '目标网段',
  };
  const reasonLabels: Record<string, string> = {
    required: '不能为空', uuid: '格式无效', cidr: '必须是规范 IPv4 CIDR', different: '不能选择同一站点',
    positive: '必须大于 0', range: '超出允许范围', endpoint: '必须是有效的 IP:端口', unique: '必须为非负且不能重复', domain: '域名格式无效',
    ipv4: '必须是有效 IPv4 地址', ipv6: '必须是有效 IPv6 地址',
  };
  return errors.slice(0, 4).map((value) => {
    const [path, reason] = value.split(':');
    const field = path.split('.').at(-1) ?? path;
    return `${fieldLabels[field] ?? field}${reasonLabels[reason] ?? '不正确'}`;
  }).join('；');
}

function FieldHelp({ children }: { children: React.ReactNode }) {
  return <Typography.Text className="field-help" type="secondary">{children}</Typography.Text>;
}

export function ResourceEditor({ visible, definition, session, resource, onClose, onSaved }: Props) {
  const [spec, setSpec] = useState<Spec>({});
  const [references, setReferences] = useState<References>({});
  const [loadingReferences, setLoadingReferences] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const tenantId = session.claims.tenant_id;

  useEffect(() => {
    const current = resource?.resource ?? defaultSpec(definition.kind);
    const normalized = normalizeSpecForEditor(current);
    if (definition.kind === 'SERVICE_POLICY') normalized.rules = policyRulesForEditor(normalized.rules);
    if (definition.kind === 'DNS_INTENT') normalized.records = dnsRecordsForEditor(normalized.records);
    setSpec(normalized);
    setError(null);
  }, [definition.kind, resource, visible]);

  useEffect(() => {
    if (!visible || !tenantId) return;
    let cancelled = false;
    const keys = referenceKeysByKind[definition.kind] ?? [];
    if (keys.length === 0) {
      setReferences({});
      setLoadingReferences(false);
      return;
    }
    setLoadingReferences(true);
    void Promise.all(keys.map(async (key) => {
      try {
        const response = await listResources(session.token, tenantId, key);
        return [key, response.items.filter((item) => item.metadata.state === 'ACTIVE').map(optionFor)] as const;
      } catch {
        return [key, []] as const;
      }
    })).then((entries) => {
      if (!cancelled) setReferences(Object.fromEntries(entries) as References);
    }).finally(() => { if (!cancelled) setLoadingReferences(false); });
    return () => { cancelled = true; };
  }, [definition.kind, session.token, tenantId, visible]);

  const update = (key: string, value: unknown) => setSpec((current) => ({ ...current, [key]: value }));
  const updateList = (key: 'rules' | 'records', index: number, field: string, value: unknown) => setSpec((current) => {
    const items = [...((current[key] as Spec[]) ?? [])];
    items[index] = { ...items[index], [field]: value };
    return { ...current, [key]: items };
  });
  const removeListItem = (key: 'rules' | 'records', index: number) => setSpec((current) => ({
    ...current,
    [key]: ((current[key] as Spec[]) ?? []).filter((_, itemIndex) => itemIndex !== index),
  }));

  const referenceSelect = (key: ReferenceKey, value: unknown, onChange: (next: string) => void, placeholder: string) => (
    <Select
      showSearch
      allowClear
      allowCreate={{ formatter: (input) => ({ label: input, value: input }) }}
      value={String(value ?? '') || undefined}
      onChange={(next) => onChange(String(next ?? ''))}
      options={references[key] ?? []}
      placeholder={loadingReferences ? '正在读取可用资源…' : placeholder}
      renderFormat={(option, selected) => option?.children ?? shortId(String(selected))}
      notFoundContent="没有可用资源，可粘贴资源 ID"
    />
  );

  const save = async () => {
    const errors = validateResourceEditor(definition.kind, spec);
    if (errors.length) {
      setError(errorMessage(errors));
      return;
    }
    if (!tenantId) {
      setError('当前会话没有租户范围，请重新登录');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const document = buildResourceSpec(definition.kind, spec);
      const response = resource
        ? await replaceResource(session.token, tenantId, definition.collection, resource.metadata.id, resource.metadata.revision, document)
        : await createResource(session.token, tenantId, definition.collection, document);
      onSaved(response.resource);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const basicFields = useMemo(() => {
    switch (definition.kind) {
      case 'SITE': return <>
        <Form.Item label="站点名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：上海办公室" maxLength={200} showWordLimit /></Form.Item>
        <Form.Item label="站点类型" required><Radio.Group type="button" value={spec.kind} onChange={(value) => update('kind', value)} options={[{ label: '边缘站点', value: 'EDGE' }, { label: '私有云', value: 'PRIVATE_CLOUD' }]} /></Form.Item>
      </>;
      case 'NODE': return <>
        <Alert type="info" showIcon content="节点通常通过“节点加入”自动注册。此处用于调整已注册节点的展示名称和站点归属。" />
        <div className="form-grid two"><Form.Item label="节点名称" required><Input value={getValue(spec, 'display_name')} onChange={(value) => update('display_name', value)} placeholder="例如：上海主网关" /></Form.Item><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), '选择站点')}</Form.Item></div>
        <div className="form-grid two"><Form.Item label="运行平台" required><Radio.Group type="button" value={spec.platform} onChange={(value) => update('platform', value)} options={[{ label: 'OpenWrt', value: 'OPEN_WRT' }, { label: 'Linux', value: 'LINUX' }]} /></Form.Item><Form.Item label="处理器架构" required><Select showSearch allowCreate value={getValue(spec, 'architecture') || undefined} onChange={(value) => update('architecture', value)} options={architectureOptions} placeholder="选择或输入架构" /></Form.Item></div>
        <Collapse className="advanced-collapse"><Collapse.Item name="identity" header="高级：节点身份"><FieldHelp>设备身份由安全加入流程签发。只有迁移或恢复节点时才应修改。</FieldHelp><div className="form-grid two identity-fields"><Form.Item label="设备 ID" required><Input className="mono-input" value={getValue(spec, 'device_id')} onChange={(value) => update('device_id', value)} /></Form.Item><Form.Item label="设备密钥 ID" required><Input className="mono-input" value={getValue(spec, 'device_key_id')} onChange={(value) => update('device_key_id', value)} /></Form.Item></div></Collapse.Item></Collapse>
      </>;
      case 'SEGMENT': return <><Form.Item label="分段名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：办公网络" /></Form.Item><Form.Item label="覆盖网络" required><Input className="mono-input" value={getValue(spec, 'overlay_cidr')} onChange={(value) => update('overlay_cidr', value)} placeholder="100.64.10.0/24" /><FieldHelp>用于站点间隧道地址，不应与任何站点局域网重叠。</FieldHelp></Form.Item></>;
      case 'PREFIX': return <><div className="form-grid two"><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), '选择站点')}</Form.Item><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => update('segment_id', value), '选择分段')}</Form.Item></div><div className="form-grid two"><Form.Item label="站点网段" required><Input className="mono-input" value={getValue(spec, 'cidr')} onChange={(value) => update('cidr', value)} placeholder="10.10.0.0/16" /></Form.Item><Form.Item label="来源" required><Select value={getValue(spec, 'source') || undefined} onChange={(value) => update('source', value)} options={[{ label: '手动配置', value: 'CONFIGURED' }, { label: '直连网络', value: 'CONNECTED' }, { label: '已批准学习', value: 'APPROVED_LEARNED' }]} /></Form.Item></div></>;
      case 'PEER': return <><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => update('segment_id', value), '选择分段')}</Form.Item><div className="form-grid two"><Form.Item label="站点 A" required>{referenceSelect('sites', spec.site_a_id, (value) => update('site_a_id', value), '选择第一个站点')}</Form.Item><Form.Item label="站点 B" required>{referenceSelect('sites', spec.site_b_id, (value) => update('site_b_id', value), '选择第二个站点')}</Form.Item></div><Form.Item label="路径策略" required><Radio.Group type="button" value={spec.path_policy} onChange={(value) => update('path_policy', value)} options={[{ label: '直连优先', value: 'DIRECT_PREFERRED' }, { label: '仅直连', value: 'DIRECT_ONLY' }, { label: '必须中继', value: 'RELAY_REQUIRED' }]} /><FieldHelp>直连优先会在公网条件允许时获得最低时延，并在不可达时使用中继。</FieldHelp></Form.Item></>;
      case 'PATH_CANDIDATE': return <><div className="form-grid two"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => update('segment_id', value), '选择分段')}</Form.Item><Form.Item label="对等关系" required>{referenceSelect('peers', spec.peer_id, (value) => update('peer_id', value), '选择对等关系')}</Form.Item></div><div className="form-grid two"><Form.Item label="源接入" required>{referenceSelect('attachments', spec.source_attachment_id, (value) => update('source_attachment_id', value), '选择源接入')}</Form.Item><Form.Item label="目标接入" required>{referenceSelect('attachments', spec.destination_attachment_id, (value) => update('destination_attachment_id', value), '选择目标接入')}</Form.Item></div><Form.Item label="路径类型" required><Radio.Group type="button" value={spec.kind} onChange={(value) => update('kind', value)} options={[{ label: '直接连接', value: 'DIRECT' }, { label: '中继路径', value: 'RELAY' }]} /></Form.Item>{spec.kind === 'RELAY' && <Form.Item label="中继节点" required>{referenceSelect('relays', spec.relay_id, (value) => update('relay_id', value), '选择中继')}</Form.Item>}<div className="form-grid endpoint-grid"><Form.Item label="公网端点" required><Input className="mono-input" value={getValue(spec, 'endpoint')} onChange={(value) => update('endpoint', value)} placeholder="203.0.113.10:8443" /></Form.Item><Form.Item label="优先级" required><InputNumber min={1} max={65535} value={Number(spec.priority)} onChange={(value) => update('priority', value)} /></Form.Item></div></>;
      case 'EGRESS': return <><Form.Item label="出口名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：上海互联网出口" /></Form.Item><div className="form-grid two"><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), '选择站点')}</Form.Item><Form.Item label="承载接入" required>{referenceSelect('attachments', spec.attachment_id, (value) => update('attachment_id', value), '选择接入关系')}</Form.Item></div><CapacityFields spec={spec} update={update} /></>;
      case 'RELAY': return <><div className="form-grid two"><Form.Item label="中继名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：东京中继 1" /></Form.Item><Form.Item label="区域标识" required><Input value={getValue(spec, 'region')} onChange={(value) => update('region', value)} placeholder="ap-northeast" /></Form.Item></div><Form.Item label="服务节点" required>{referenceSelect('nodes', spec.service_node_id, (value) => update('service_node_id', value), '选择提供中继能力的节点')}</Form.Item><CapacityFields spec={spec} update={update} /></>;
      case 'SERVICE_POLICY': return <PolicyFields spec={spec} update={update} updateList={updateList} removeListItem={removeListItem} references={references} referenceSelect={referenceSelect} />;
      case 'DNS_INTENT': return <DnsFields spec={spec} update={update} updateList={updateList} removeListItem={removeListItem} referenceSelect={referenceSelect} />;
      default: return null;
    }
  // Functions are stable for the lifetime of a render; spec and references intentionally drive this projection.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [definition.kind, loadingReferences, references, spec]);

  return (
    <Drawer
      width={720}
      visible={visible}
      onCancel={onClose}
      className="resource-drawer"
      title={<div className="drawer-title"><strong>{resource ? `编辑${definition.label}` : `新建${definition.label}`}</strong><span>{definition.description}</span></div>}
      footer={<Space><Button onClick={onClose}>取消</Button><Button type="primary" icon={<IconSave />} loading={saving} onClick={save}>保存配置</Button></Space>}
    >
      <Spin loading={loadingReferences} tip="正在读取关联资源" block>
        {resource && <div className="revision-strip"><IconSettings /><span>当前修订</span><strong>{resource.metadata.revision}</strong><small>保存时自动检查并发修改</small></div>}
        {error && <Alert type="error" title="无法保存配置" content={error} showIcon className="editor-alert" />}
        <Form layout="vertical" className="resource-form">{basicFields}</Form>
      </Spin>
    </Drawer>
  );
}

function CapacityFields({ spec, update }: { spec: Spec; update: (key: string, value: unknown) => void }) {
  return <><Typography.Title heading={6} className="form-section-title">容量预算</Typography.Title><div className="form-grid two"><Form.Item label="并发会话" required><InputNumber min={1} precision={0} value={Number(spec.max_sessions)} onChange={(value) => update('max_sessions', value)} suffix="条" /></Form.Item><Form.Item label="可用带宽" required><InputNumber min={1} precision={0} value={Number(spec.capacity_mbps)} onChange={(value) => update('capacity_mbps', value)} suffix="Mbps" /></Form.Item></div><FieldHelp>容量用于控制面调度和过载保护，不会主动限制低于该预算的正常流量。</FieldHelp></>;
}

type ListProps = {
  spec: Spec;
  update: (key: string, value: unknown) => void;
  updateList: (key: 'rules' | 'records', index: number, field: string, value: unknown) => void;
  removeListItem: (key: 'rules' | 'records', index: number) => void;
};

function PolicyFields({ spec, update, updateList, removeListItem, references, referenceSelect }: ListProps & { references: References; referenceSelect: (key: ReferenceKey, value: unknown, onChange: (next: string) => void, placeholder: string) => React.ReactNode }) {
  const rules = (spec.rules as Spec[]) ?? [];
  return <><div className="form-grid endpoint-grid"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => update('segment_id', value), '选择分段')}</Form.Item><Form.Item label="配置代次" required><InputNumber min={1} precision={0} value={Number(spec.generation)} onChange={(value) => update('generation', value)} /></Form.Item></div><div className="collection-heading"><div><Typography.Title heading={6}>流量规则</Typography.Title><Typography.Text type="secondary">按优先级从小到大匹配，未匹配流量保持本地出口。</Typography.Text></div><Button icon={<IconPlus />} onClick={() => update('rules', [...rules, { id: crypto.randomUUID(), priority: rules.length * 100 + 100, source_site_ids: [], destination_cidrs: [], domains: [], traffic_classes: [], action_type: 'LOCAL_EGRESS', egress_id: '' }])}>添加规则</Button></div>{rules.length === 0 ? <div className="inline-empty">当前没有覆盖规则，所有流量使用站点本地出口。</div> : <div className="structured-list">{rules.map((rule, index) => <section className="structured-item" key={String(rule.id ?? index)}><header><div><strong>规则 {index + 1}</strong><span>优先级 {String(rule.priority)}</span></div><Button type="text" status="danger" icon={<IconDelete />} aria-label={`删除规则 ${index + 1}`} onClick={() => removeListItem('rules', index)} /></header><div className="form-grid rule-grid"><Form.Item label="优先级"><InputNumber min={0} precision={0} value={Number(rule.priority)} onChange={(value) => updateList('rules', index, 'priority', value)} /></Form.Item><Form.Item label="来源站点"><Select mode="multiple" showSearch value={(rule.source_site_ids as string[]) ?? []} onChange={(value) => updateList('rules', index, 'source_site_ids', value)} options={references.sites ?? []} placeholder="全部站点" maxTagCount="responsive" /></Form.Item></div><Form.Item label="目标网段"><InputTag value={(rule.destination_cidrs as string[]) ?? []} onChange={(value) => updateList('rules', index, 'destination_cidrs', value)} tokenSeparators={[',', ' ']} saveOnBlur placeholder="输入 CIDR 后回车，例如 10.20.0.0/16" /></Form.Item><Form.Item label="目标域名"><InputTag value={(rule.domains as string[]) ?? []} onChange={(value) => updateList('rules', index, 'domains', value)} tokenSeparators={[',', ' ']} saveOnBlur placeholder="输入域名后回车" /></Form.Item><div className="form-grid two"><Form.Item label="流量类别"><Select mode="multiple" allowCreate showSearch value={(rule.traffic_classes as string[]) ?? []} onChange={(value) => updateList('rules', index, 'traffic_classes', value)} options={trafficClassOptions} placeholder="不限类别" maxTagCount="responsive" /></Form.Item><Form.Item label="出口动作"><Radio.Group type="button" value={rule.action_type} onChange={(value) => updateList('rules', index, 'action_type', value)} options={[{ label: '本地出口', value: 'LOCAL_EGRESS' }, { label: '远端出口', value: 'REMOTE_EGRESS' }]} /></Form.Item></div>{rule.action_type === 'REMOTE_EGRESS' && <Form.Item label="指定远端出口" required>{referenceSelect('egresses', rule.egress_id, (value) => updateList('rules', index, 'egress_id', value), '选择出口')}</Form.Item>}</section>)}</div>}</>;
}

function DnsFields({ spec, update, updateList, removeListItem, referenceSelect }: ListProps & { referenceSelect: (key: ReferenceKey, value: unknown, onChange: (next: string) => void, placeholder: string) => React.ReactNode }) {
  const records = (spec.records as Spec[]) ?? [];
  return <><div className="form-grid two"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => update('segment_id', value), '选择分段')}</Form.Item><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), '选择站点')}</Form.Item></div><Form.Item label="内部域" required><Input value={getValue(spec, 'zone')} onChange={(value) => update('zone', value)} placeholder="corp.example.internal" /><FieldHelp>仅向该网络分段内已授权站点发布。</FieldHelp></Form.Item><div className="collection-heading"><div><Typography.Title heading={6}>DNS 记录</Typography.Title><Typography.Text type="secondary">统一管理站点间服务发现，无需在节点维护 hosts。</Typography.Text></div><Button icon={<IconPlus />} onClick={() => update('records', [...records, { name: '', type: 'A', value: '', ttl_seconds: 60, required_prefix_id: '' }])}>添加记录</Button></div>{records.length === 0 ? <div className="inline-empty">尚未添加内部解析记录。</div> : <div className="structured-list dns-list">{records.map((record, index) => <section className="structured-item" key={index}><header><div><strong>记录 {index + 1}</strong><span>{String(record.type ?? 'A')}</span></div><Button type="text" status="danger" icon={<IconDelete />} aria-label={`删除记录 ${index + 1}`} onClick={() => removeListItem('records', index)} /></header><div className="form-grid dns-grid"><Form.Item label="名称"><Input value={getValue(record, 'name')} onChange={(value) => updateList('records', index, 'name', value)} placeholder="gateway.corp.example.internal" /></Form.Item><Form.Item label="类型"><Select value={getValue(record, 'type') || 'A'} onChange={(value) => updateList('records', index, 'type', value)} options={['A', 'AAAA', 'CNAME']} /></Form.Item><Form.Item label="记录值"><Input className="mono-input" value={getValue(record, 'value')} onChange={(value) => updateList('records', index, 'value', value)} placeholder={record.type === 'CNAME' ? 'target.example.internal' : record.type === 'AAAA' ? '2001:db8::10' : '10.0.0.10'} /></Form.Item><Form.Item label="TTL"><InputNumber min={5} max={86400} precision={0} value={Number(record.ttl_seconds)} onChange={(value) => updateList('records', index, 'ttl_seconds', value)} suffix="秒" /></Form.Item></div><Collapse className="advanced-collapse record-constraint"><Collapse.Item name={`constraint-${index}`} header="可选：仅在网段可达时发布"><Form.Item label="依赖网段">{referenceSelect('prefixes', record.required_prefix_id, (value) => updateList('records', index, 'required_prefix_id', value), '不限制')}</Form.Item></Collapse.Item></Collapse></section>)}</div>}</>;
}
