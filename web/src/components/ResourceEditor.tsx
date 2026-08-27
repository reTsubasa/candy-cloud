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
  Tag,
  Typography,
} from '@arco-design/web-react';
import { IconCloud, IconDelete, IconDesktop, IconPlus, IconSave, IconSettings, IconStorage, IconWifi } from '@arco-design/web-react/icon';
import { createResource, fetchRuntimeTelemetry, listResources, replaceResource } from '../api';
import { defaultSpec } from '../resource-definitions';
import {
  buildResourceSpec,
  dnsRecordsForEditor,
  normalizeSpecForEditor,
  policyRulesForEditor,
  validateResourceEditor,
  type Spec,
} from '../resource-form';
import type { ControlResource, ResourceDefinition, ResourceOption, RuntimeTelemetry, Session } from '../types';

type Props = {
  visible: boolean;
  definition: ResourceDefinition;
  session: Session;
  resource: ControlResource | null;
  onClose: () => void;
  onSaved: (resource: ControlResource) => void;
  embedded?: boolean;
  initialSpec?: Spec;
  saveLabel?: string;
};

type ReferenceKey = 'sites' | 'nodes' | 'segments' | 'attachments' | 'peers' | 'egresses' | 'prefixes' | 'relays';
type ReferenceOption = ResourceOption & { spec: Spec };
type References = Partial<Record<ReferenceKey, ReferenceOption[]>>;
type ReferenceSelect = (key: ReferenceKey, value: unknown, onChange: (next: string) => void, placeholder: string, options?: ResourceOption[]) => React.ReactNode;

const referenceKeysByKind: Record<string, ReferenceKey[]> = {
  SITE: [],
  NODE: ['sites'],
  SEGMENT: [],
  ATTACHMENT: ['segments', 'sites', 'nodes', 'attachments'],
  PREFIX: ['sites', 'segments', 'attachments', 'prefixes', 'nodes'],
  PEER: ['sites', 'segments', 'attachments'],
  PATH_CANDIDATE: ['segments', 'attachments', 'peers', 'relays'],
  EGRESS: ['sites', 'attachments'],
  RELAY: ['nodes'],
  SERVICE_POLICY: ['segments', 'sites', 'attachments', 'egresses'],
  DNS_INTENT: ['segments', 'sites', 'attachments', 'prefixes'],
};
const nodeArchitectureOptions = {
  OPEN_WRT: [
    { label: 'x86-64', value: 'x86_64' },
    { label: 'ARMv7 / IPQ40xx', value: 'armv7' },
  ],
  LINUX: [
    { label: 'x86-64', value: 'x86_64' },
    { label: 'ARM64 / aarch64', value: 'aarch64' },
  ],
};
const trafficClassOptions = [
  { label: '交互业务', value: 'interactive' },
  { label: '实时音视频', value: 'realtime' },
  { label: '批量传输', value: 'bulk' },
  { label: '默认流量', value: 'default' },
];
const entityLabels: Record<string, string> = {
  PEER: '站点互联',
  ATTACHMENT: '网络接入',
  SERVICE_POLICY: '策略',
  DNS_INTENT: 'DNS 配置',
};

function displayName(item: ControlResource): string {
  const spec = item.resource.spec;
  const prefix = spec.prefix as Spec | undefined;
  const overlay = spec.overlay_prefix as Spec | undefined;
  const primary = spec.display_name ?? spec.name ?? spec.zone ?? spec.endpoint;
  if (primary) return String(primary);
  if (prefix) return `${prefix.network}/${prefix.prefix_len}`;
  if (overlay) return `${overlay.network}/${overlay.prefix_len}`;
  if (item.resource.kind === 'ATTACHMENT') return `网络接入 · ${String(spec.overlay_router_ipv4 ?? '待分配')}`;
  if (item.resource.kind === 'PEER') return '站点互联';
  if (item.resource.kind === 'SERVICE_POLICY') return '流量策略';
  return item.metadata.id;
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function optionFor(item: ControlResource): ReferenceOption {
  const label = displayName(item);
  return { value: item.metadata.id, label, description: label === item.metadata.id ? undefined : shortId(item.metadata.id), spec: item.resource.spec };
}

function segmentAttachments(segmentId: unknown, references: References): ReferenceOption[] {
  if (!segmentId) return [];
  return (references.attachments ?? []).filter((item) => item.spec.segment_id === segmentId);
}

function segmentSites(segmentId: unknown, references: References): ReferenceOption[] {
  const siteIds = new Set(segmentAttachments(segmentId, references).map((item) => String(item.spec.site_id)));
  return (references.sites ?? []).filter((item) => siteIds.has(item.value));
}

function segmentEgresses(segmentId: unknown, references: References): ReferenceOption[] {
  const attachmentIds = new Set(segmentAttachments(segmentId, references).map((item) => item.value));
  return (references.egresses ?? []).filter((item) => attachmentIds.has(String(item.spec.attachment_id)));
}

function segmentPrefixes(segmentId: unknown, references: References): ReferenceOption[] {
  return (references.prefixes ?? []).filter((item) => item.spec.segment_id === segmentId);
}

function getValue(spec: Spec, key: string): string {
  return String(spec[key] ?? '');
}

function errorMessage(errors: string[]): string {
  const fieldLabels: Record<string, string> = {
    name: '名称', display_name: '节点名称', site_id: '站点', segment_id: '网络分段', device_id: '设备 ID',
    device_key_id: '设备密钥 ID', architecture: '架构', overlay_cidr: '覆盖网段', cidr: '网段',
    node_id: '接入节点', overlay_router_ipv4: '隧道地址', epoch_floor: '安全代次',
    site_a_id: '站点 A', site_b_id: '站点 B', service_node_id: '服务节点', attachment_id: '接入关系',
    source_attachment_id: '源接入', destination_attachment_id: '目标接入', peer_id: '对等关系', relay_id: '中继',
    endpoint: '公网端点', transport_node_id: '提供公网传输的节点', priority: '优先级', max_sessions: '会话容量', capacity_mbps: '带宽容量',
    generation: '配置代次', zone: '内部域', value: '记录值', ttl_seconds: 'TTL', domains: '域名', destination_cidrs: '目标网段',
  };
  const reasonLabels: Record<string, string> = {
    required: '不能为空', uuid: '格式无效', cidr: '必须是规范 IPv4 CIDR', different: '不能与前一项相同', mismatch: '与所选站点不匹配',
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

function FormIntro({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="form-intro"><strong>{title}</strong><span>{children}</span></div>;
}

function ipv4Number(value: string): number | null {
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return octets.reduce((result, part) => ((result << 8) | part) >>> 0, 0);
}

function ipv4Text(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
}

function suggestedOverlayAddress(segmentId: string, references: References): string {
  const segment = references.segments?.find((item) => item.value === segmentId)?.spec.overlay_prefix as Spec | undefined;
  const network = ipv4Number(String(segment?.network ?? ''));
  const prefix = Number(segment?.prefix_len);
  if (network === null || !Number.isInteger(prefix) || prefix < 1 || prefix > 30) return '';
  const size = 2 ** (32 - prefix);
  const used = new Set((references.attachments ?? []).filter((item) => item.spec.segment_id === segmentId).map((item) => String(item.spec.overlay_router_ipv4)));
  for (let offset = 2; offset < Math.min(size - 1, 65536); offset += 1) {
    const candidate = ipv4Text((network + offset) >>> 0);
    if (!used.has(candidate)) return candidate;
  }
  return '';
}

function addressInsideSegment(addressText: string, segmentId: string, references: References): boolean {
  const segment = references.segments?.find((item) => item.value === segmentId)?.spec.overlay_prefix as Spec | undefined;
  const address = ipv4Number(addressText);
  const network = ipv4Number(String(segment?.network ?? ''));
  const prefix = Number(segment?.prefix_len);
  if (address === null || network === null || !Number.isInteger(prefix) || prefix < 1 || prefix > 30) return false;
  const size = 2 ** (32 - prefix);
  return address > network && address < network + size - 1;
}

export function ResourceEditor({ visible, definition, session, resource, onClose, onSaved, embedded = false, initialSpec, saveLabel = '保存配置' }: Props) {
  const [spec, setSpec] = useState<Spec>({});
  const [references, setReferences] = useState<References>({});
  const [loadingReferences, setLoadingReferences] = useState(false);
  const [runtimeTelemetry, setRuntimeTelemetry] = useState<RuntimeTelemetry[]>([]);
  const [loadingNetworks, setLoadingNetworks] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const tenantId = session.claims.tenant_id;
  const entityLabel = entityLabels[definition.kind] ?? definition.label;

  useEffect(() => {
    const current = resource?.resource ?? defaultSpec(definition.kind);
    const normalized = normalizeSpecForEditor(current);
    if (!resource && initialSpec) Object.assign(normalized, initialSpec);
    if (definition.kind === 'SERVICE_POLICY') normalized.rules = policyRulesForEditor(normalized.rules);
    if (definition.kind === 'DNS_INTENT') normalized.records = dnsRecordsForEditor(normalized.records);
    setSpec(normalized);
    setError(null);
  }, [definition.kind, initialSpec, resource, visible]);

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

  useEffect(() => {
    if (!visible || definition.kind !== 'PREFIX' || !tenantId) {
      setRuntimeTelemetry([]);
      setLoadingNetworks(false);
      return;
    }
    let cancelled = false;
    setLoadingNetworks(true);
    void fetchRuntimeTelemetry(session.token, tenantId)
      .then((response) => { if (!cancelled) setRuntimeTelemetry(response.items); })
      .catch(() => { if (!cancelled) setRuntimeTelemetry([]); })
      .finally(() => { if (!cancelled) setLoadingNetworks(false); });
    return () => { cancelled = true; };
  }, [definition.kind, session.token, tenantId, visible]);

  const discoveredNetworks = useMemo(() => {
    const nodeByIdentity = new Map((references.nodes ?? []).map((node) => [
      `${String(node.spec.device_id)}:${String(node.spec.device_key_id)}`,
      node,
    ]));
    const published = new Set((references.prefixes ?? []).map((prefix) => {
      const value = prefix.spec.prefix as Spec | undefined;
      return `${String(prefix.spec.segment_id)}:${String(prefix.spec.site_id)}:${String(value?.network)}/${String(value?.prefix_len)}`;
    }));
    const attachedNodes = new Set(
      segmentAttachments(String(spec.segment_id ?? ''), references)
        .map((item) => String(item.spec.node_id)),
    );
    return runtimeTelemetry.flatMap((telemetry) => {
      const node = nodeByIdentity.get(`${telemetry.device_id}:${telemetry.device_key_id}`);
      if (!node || (spec.segment_id && !attachedNodes.has(node.value))) return [];
      return telemetry.local_networks.map((network) => ({
        ...network,
        nodeId: node.value,
        nodeName: node.label,
        siteId: String(node.spec.site_id),
        published: published.has(`${String(spec.segment_id)}:${String(node.spec.site_id)}:${network.cidr}`),
      }));
    }).sort((left, right) => left.nodeName.localeCompare(right.nodeName) || left.cidr.localeCompare(right.cidr));
  }, [references, runtimeTelemetry, spec.segment_id]);

  const update = (key: string, value: unknown) => setSpec((current) => ({ ...current, [key]: value }));
  const updateNodePlatform = (platform: 'OPEN_WRT' | 'LINUX') => setSpec((current) => {
    const available = nodeArchitectureOptions[platform];
    const architecture = available.some((option) => option.value === current.architecture)
      ? current.architecture
      : available[0].value;
    return { ...current, platform, architecture };
  });
  const updateList = (key: 'rules' | 'records', index: number, field: string, value: unknown) => setSpec((current) => {
    const items = [...((current[key] as Spec[]) ?? [])];
    items[index] = { ...items[index], [field]: value };
    return { ...current, [key]: items };
  });
  const removeListItem = (key: 'rules' | 'records', index: number) => setSpec((current) => ({
    ...current,
    [key]: ((current[key] as Spec[]) ?? []).filter((_, itemIndex) => itemIndex !== index),
  }));

  const referenceSelect: ReferenceSelect = (key, value, onChange, placeholder, options) => (
    <Select
      showSearch
      allowClear
      value={String(value ?? '') || undefined}
      onChange={(next) => onChange(String(next ?? ''))}
      options={options ?? references[key] ?? []}
      placeholder={loadingReferences ? '正在读取可用资源…' : placeholder}
      renderFormat={(option, selected) => option?.children ?? shortId(String(selected))}
      notFoundContent="暂无可用选项，请先完成前置配置"
    />
  );

  const save = async () => {
    const errors = validateResourceEditor(definition.kind, spec);
    if (definition.kind === 'ATTACHMENT') {
      if (spec.segment_id && spec.overlay_router_ipv4 && !addressInsideSegment(String(spec.overlay_router_ipv4), String(spec.segment_id), references)) errors.push('overlay_router_ipv4:range');
      const node = references.nodes?.find((item) => item.value === spec.node_id);
      if (node && node.spec.site_id !== spec.site_id) errors.push('node_id:mismatch');
    }
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
        <Form.Item label="站点类型" required>
          <Radio.Group className="site-type-options" value={spec.kind} onChange={(value) => update('kind', value)}>
            <Radio value="EDGE"><span className="site-type-card"><strong>边缘站点</strong><span>办公室、门店、家庭或 OpenWrt 节点。通常通过本地 Candy 出口访问互联网，并加入站点间网络。</span><small>适用：分支接入、移动办公、轻量节点</small></span></Radio>
            <Radio value="PRIVATE_CLOUD"><span className="site-type-card"><strong>私有云</strong><span>数据中心、云主机或自建机房。通常承载共享服务、内部网段或稳定的远端出口。</span><small>适用：服务中心、机房、集中出口</small></span></Radio>
          </Radio.Group>
          <FieldHelp>类型只描述站点在网络中的角色，不限制运行平台；后续可通过策略决定流量是否经由该站点。</FieldHelp>
          <div className="site-topology-heading"><Typography.Text bold>典型拓扑</Typography.Text><Typography.Text type="secondary">用于理解站点角色，不代表固定部署方式</Typography.Text></div>
          <div className="site-topologies">
            <figure className={spec.kind === 'EDGE' ? 'selected' : ''}>
              <figcaption><strong>边缘站点</strong><span>分支与终端接入</span></figcaption>
              <div className="topology-chain">
                <div className="topology-node"><IconDesktop /><span>局域网终端</span></div>
                <span className="topology-link" />
                <div className="topology-node primary"><IconWifi /><span>Candy 网关</span></div>
                <span className="topology-link" />
                <div className="topology-node"><IconCloud /><span>互联网 / SD-WAN</span></div>
              </div>
              <p>本地终端通过 OpenWrt 或 Linux 网关接入，默认保留本站出口，并按策略访问其他站点。</p>
            </figure>
            <figure className={spec.kind === 'PRIVATE_CLOUD' ? 'selected' : ''}>
              <figcaption><strong>私有云</strong><span>服务与集中出口</span></figcaption>
              <div className="topology-chain">
                <div className="topology-node"><IconStorage /><span>内部服务</span></div>
                <span className="topology-link" />
                <div className="topology-node primary"><IconDesktop /><span>Candy Server</span></div>
                <span className="topology-link" />
                <div className="topology-node"><IconCloud /><span>站点 / 远端出口</span></div>
              </div>
              <p>数据中心或云主机发布内部网段和服务，也可作为其他站点策略选择的稳定出口。</p>
            </figure>
          </div>
        </Form.Item>
      </>;
      case 'NODE': return <>
        <Alert type="info" showIcon content="节点通常通过“节点加入”自动注册。此处用于调整已注册节点的展示名称和站点归属。" />
        <div className="form-grid two"><Form.Item label="节点名称" required><Input value={getValue(spec, 'display_name')} onChange={(value) => update('display_name', value)} placeholder="例如：上海主网关" /></Form.Item><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), '选择站点')}</Form.Item></div>
        <div className="form-grid two"><Form.Item label="运行平台" required><Radio.Group type="button" value={spec.platform} onChange={updateNodePlatform} options={[{ label: 'OpenWrt', value: 'OPEN_WRT' }, { label: 'Linux', value: 'LINUX' }]} /></Form.Item><Form.Item label="处理器架构" required><Select value={getValue(spec, 'architecture') || undefined} onChange={(value) => update('architecture', value)} options={nodeArchitectureOptions[spec.platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX']} placeholder="选择已发布架构" /></Form.Item></div>
        <Collapse className="advanced-collapse"><Collapse.Item name="identity" header="高级：节点身份"><FieldHelp>设备身份由安全加入流程签发。只有迁移或恢复节点时才应修改。</FieldHelp><div className="form-grid two identity-fields"><Form.Item label="设备 ID" required><Input className="mono-input" value={getValue(spec, 'device_id')} onChange={(value) => update('device_id', value)} /></Form.Item><Form.Item label="设备密钥 ID" required><Input className="mono-input" value={getValue(spec, 'device_key_id')} onChange={(value) => update('device_key_id', value)} /></Form.Item></div></Collapse.Item></Collapse>
      </>;
      case 'SEGMENT': return <>
        <FormIntro title="按互通边界创建网络">需要共享路由和策略的站点放在同一分段，不要按地区拆分。只有业务隔离、地址重叠或安全边界不同时，才创建不同分段。</FormIntro>
        <Form.Item label="分段名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：办公网络" /></Form.Item>
        <Form.Item label="隧道地址池" required><Input className="mono-input" value={getValue(spec, 'overlay_cidr')} onChange={(value) => update('overlay_cidr', value)} placeholder="100.64.10.0/24" /><FieldHelp>只为该分段内的 Candy 节点分配 TUN 地址，不是站点局域网。应避开各站点 LAN 网段；需要互通的 LAN 网段请在“网段”菜单中单独发布。</FieldHelp></Form.Item>
      </>;
      case 'ATTACHMENT': {
        const nodeOptions = (references.nodes ?? []).filter((item) => !spec.site_id || item.spec.site_id === spec.site_id);
        return <>
          <FormIntro title="让节点参与站点互联">每个参与 SD-WAN 的节点都需要接入一个网络分段，并获得该分段内唯一的隧道地址。</FormIntro>
          <div className="form-grid two"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => setSpec((current) => ({ ...current, segment_id: value, overlay_router_ipv4: suggestedOverlayAddress(value, references) })), '选择分段')}</Form.Item><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => setSpec((current) => ({ ...current, site_id: value, node_id: '' })), '选择站点')}</Form.Item></div>
          <div className="form-grid two"><Form.Item label="接入节点" required>{referenceSelect('nodes', spec.node_id, (value) => update('node_id', value), spec.site_id ? '选择该站点的节点' : '请先选择站点', nodeOptions)}</Form.Item><Form.Item label="隧道地址" required><Input className="mono-input" value={getValue(spec, 'overlay_router_ipv4')} onChange={(value) => update('overlay_router_ipv4', value)} placeholder="选择分段后自动建议" /><FieldHelp>必须位于所选分段的地址池内且未被其他节点使用。</FieldHelp></Form.Item></div>
          <Collapse className="advanced-collapse"><Collapse.Item name="epoch" header="高级：安全代次"><Form.Item label="最低配置代次" required><InputNumber min={1} precision={0} value={Number(spec.epoch_floor)} onChange={(value) => update('epoch_floor', value)} /></Form.Item><FieldHelp>用于拒绝旧配置回放。正常新增时保持 1；仅在安全恢复或密钥轮换时调整。</FieldHelp></Collapse.Item></Collapse>
        </>;
      }
      case 'PREFIX': return <>
        <FormIntro title="发布站点内网">其他站点只会访问这里明确声明的网段，不会自动暴露整个局域网。</FormIntro>
        <div className="form-grid two"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => setSpec((current) => ({ ...current, segment_id: value, site_id: '' })), '选择分段')}</Form.Item><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => update('site_id', value), spec.segment_id ? '选择已接入该网络的站点' : '请先选择网络分段', segmentSites(spec.segment_id, references))}</Form.Item></div>
        <Form.Item label="节点发现的网段">
          {!spec.segment_id ? <div className="network-discovery-empty">先选择网络分段，即可查看参与节点上报的本地网段。</div> : loadingNetworks ? <div className="network-discovery-empty"><Spin dot /> 正在读取节点网段…</div> : discoveredNetworks.length === 0 ? <div className="network-discovery-empty">参与节点尚未上报可发布的直连网段，仍可在下方手动填写。</div> : <div className="network-discovery-list">
            {discoveredNetworks.map((network) => <button
              type="button"
              className={`network-discovery-item${spec.cidr === network.cidr && spec.site_id === network.siteId ? ' selected' : ''}`}
              key={`${network.nodeId}:${network.network_id}`}
              disabled={network.published}
              onClick={() => setSpec((current) => ({ ...current, site_id: network.siteId, cidr: network.cidr, source: 'CONNECTED' }))}
            >
              <span className="network-discovery-main"><strong>{network.cidr}</strong><small>{network.nodeName} · {network.interface_name} · 本机 {network.address}</small></span>
              <span className="network-discovery-meta"><code>{network.network_id.slice(0, 12)}</code>{network.published ? <Tag color="green">已发布</Tag> : <span>使用</span>}</span>
            </button>)}
          </div>}
          <FieldHelp>候选来自节点内核的直连路由；短标识用于区分接口变化。选择后仍需保存确认，Cloud 不会自动暴露本地网络。</FieldHelp>
        </Form.Item>
        <Form.Item label="可访问网段" required><Input className="mono-input" value={getValue(spec, 'cidr')} onChange={(value) => update('cidr', value)} placeholder="10.10.0.0/16" /><FieldHelp>填写本站希望向该网络分段发布的规范 IPv4 CIDR，不能与隧道地址池或其他已发布网段重叠。</FieldHelp></Form.Item>
        <Collapse className="advanced-collapse"><Collapse.Item name="source" header="高级：网段来源"><Form.Item label="来源" required><Select value={getValue(spec, 'source') || undefined} onChange={(value) => update('source', value)} options={[{ label: '手动配置', value: 'CONFIGURED' }, { label: '节点直连上报', value: 'CONNECTED' }, { label: '已批准学习', value: 'APPROVED_LEARNED' }]} /></Form.Item><FieldHelp>通过控制台创建时通常保持“手动配置”；另外两种来源用于节点上报和审批流程。</FieldHelp></Collapse.Item></Collapse>
      </>;
      case 'PEER': {
        const pathHelp: Record<string, string> = {
          DIRECT_PREFERRED: '优先建立低时延直连；公网条件不允许时自动选择可用中继。适合绝大多数站点。',
          DIRECT_ONLY: '只允许站点直接通信，不使用中继。适合具备稳定公网端点且有严格路径要求的场景。',
          RELAY_REQUIRED: '始终通过指定中继转发。适合需要固定路径或两端均无法直连的场景。',
        };
        return <>
          <FormIntro title="建立双向站点互联">选择同一网络分段中的两个站点，Candy 会为双向流量使用同一套路径策略。</FormIntro>
          <Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => setSpec((current) => ({ ...current, segment_id: value, site_a_id: '', site_b_id: '' })), '选择分段')}</Form.Item>
          <div className="form-grid two"><Form.Item label="第一个站点" required>{referenceSelect('sites', spec.site_a_id, (value) => update('site_a_id', value), spec.segment_id ? '选择已接入该网络的站点' : '请先选择网络分段', segmentSites(spec.segment_id, references))}</Form.Item><Form.Item label="第二个站点" required>{referenceSelect('sites', spec.site_b_id, (value) => update('site_b_id', value), spec.segment_id ? '选择另一个已接入站点' : '请先选择网络分段', segmentSites(spec.segment_id, references).filter((item) => item.value !== spec.site_a_id))}</Form.Item></div>
          <Form.Item label="路径策略" required><Radio.Group type="button" value={spec.path_policy} onChange={(value) => update('path_policy', value)} options={[{ label: '自动选择', value: 'DIRECT_PREFERRED' }, { label: '仅直连', value: 'DIRECT_ONLY' }, { label: '固定中继', value: 'RELAY_REQUIRED' }]} /><FieldHelp>{pathHelp[String(spec.path_policy)] ?? pathHelp.DIRECT_PREFERRED}</FieldHelp></Form.Item>
        </>;
      }
      case 'PATH_CANDIDATE': {
        const segmentAttachments = (references.attachments ?? []).filter((item) => !spec.segment_id || item.spec.segment_id === spec.segment_id);
        return <>
          <FormIntro title="配置一个方向的线路">选择从源节点到目标节点的连接方式。一次站点互联需要两个方向的线路；通常优先直连，网络条件不允许时再使用中继。</FormIntro>
          <div className="form-grid two"><Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => setSpec((current) => ({ ...current, segment_id: value, source_attachment_id: '', destination_attachment_id: '' })), '选择分段')}</Form.Item><Form.Item label="站点互联" required>{referenceSelect('peers', spec.peer_id, (value) => update('peer_id', value), '选择互联关系')}</Form.Item></div>
          <div className="form-grid two"><Form.Item label="起点节点" required>{referenceSelect('attachments', spec.source_attachment_id, (value) => update('source_attachment_id', value), '选择发送端节点', segmentAttachments)}</Form.Item><Form.Item label="目标节点" required>{referenceSelect('attachments', spec.destination_attachment_id, (value) => update('destination_attachment_id', value), '选择接收端节点', segmentAttachments)}</Form.Item></div>
          <Form.Item label="连接方式" required><Radio.Group type="button" value={spec.kind} onChange={(value) => update('kind', value)} options={[{ label: '直接连接', value: 'DIRECT' }, { label: '经中继转发', value: 'RELAY' }]} /></Form.Item>
          {spec.kind === 'RELAY' && <Form.Item label="中继" required>{referenceSelect('relays', spec.relay_id, (value) => update('relay_id', value), '选择中继')}</Form.Item>}
          <Form.Item label="提供公网传输的节点" required>{referenceSelect('nodes', spec.transport_node_id, (value) => update('transport_node_id', value), '选择已发布公网端点的节点')}<FieldHelp>双向线路可以共用同一台公网节点；Cloud 会自动核对其服务授权和证书身份。</FieldHelp></Form.Item>
          <Form.Item label="优先级" required><InputNumber min={1} max={65535} value={Number(spec.priority)} onChange={(value) => update('priority', value)} /><FieldHelp>数值越小越优先；同一节点的备用端点由 Cloud 自动展开。</FieldHelp></Form.Item>
        </>;
      }
      case 'EGRESS': {
        const siteAttachments = (references.attachments ?? []).filter((item) => !spec.site_id || item.spec.site_id === spec.site_id);
        return <>
          <FormIntro title="发布可选互联网出口">出口创建后不会自动接管流量；只有被策略明确选择时，其他站点才会使用它。</FormIntro>
          <Form.Item label="出口名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：上海互联网出口" /></Form.Item>
          <div className="form-grid two"><Form.Item label="所属站点" required>{referenceSelect('sites', spec.site_id, (value) => setSpec((current) => ({ ...current, site_id: value, attachment_id: '' })), '选择站点')}</Form.Item><Form.Item label="承载节点" required>{referenceSelect('attachments', spec.attachment_id, (value) => update('attachment_id', value), spec.site_id ? '选择该站点的网络接入' : '请先选择站点', siteAttachments)}</Form.Item></div>
          <CapacityFields spec={spec} update={update} />
        </>;
      }
      case 'RELAY': return <>
        <FormIntro title="提供可选的中继路径">中继只在路径策略需要时转发站点流量，不承担 Cloud 控制面职责，也不会成为默认出口。</FormIntro>
        <div className="form-grid two"><Form.Item label="中继名称" required><Input value={getValue(spec, 'name')} onChange={(value) => update('name', value)} placeholder="例如：东京中继 1" /></Form.Item><Form.Item label="部署区域" required><Input value={getValue(spec, 'region')} onChange={(value) => update('region', value)} placeholder="例如：东京" /></Form.Item></div>
        <Form.Item label="服务节点" required>{referenceSelect('nodes', spec.service_node_id, (value) => update('service_node_id', value), '选择提供中继能力的 Linux 节点')}<FieldHelp>该节点需要具备稳定公网可达性和足够的双向带宽。</FieldHelp></Form.Item>
        <CapacityFields spec={spec} update={update} />
      </>;
      case 'SERVICE_POLICY': return <PolicyFields spec={spec} update={update} updateList={updateList} removeListItem={removeListItem} references={references} referenceSelect={referenceSelect} />;
      case 'DNS_INTENT': return <DnsFields spec={spec} update={update} updateList={updateList} removeListItem={removeListItem} references={references} referenceSelect={referenceSelect} />;
      default: return null;
    }
  // Functions are stable for the lifetime of a render; spec and references intentionally drive this projection.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [definition.kind, discoveredNetworks, loadingNetworks, loadingReferences, references, spec]);

  const editorContent = (
    <>
      <Spin loading={loadingReferences} tip="正在读取关联资源" block>
        {resource && <div className="revision-strip"><IconSettings /><span>当前修订</span><strong>{resource.metadata.revision}</strong><small>保存时自动检查并发修改</small></div>}
        {error && <Alert type="error" title="无法保存配置" content={error} showIcon className="editor-alert" />}
        <Form layout="vertical" className="resource-form">{basicFields}</Form>
      </Spin>
    </>
  );

  if (embedded) {
    return <div className="embedded-resource-editor">
      {editorContent}
      <div className="embedded-editor-actions"><Button type="primary" icon={<IconSave />} loading={saving} onClick={save}>{saveLabel}</Button></div>
    </div>;
  }

  return (
    <Drawer
      width={720}
      visible={visible}
      onCancel={onClose}
      className="cloud-drawer resource-drawer"
      title={<div className="drawer-title"><strong>{resource ? `编辑${entityLabel}` : `新建${entityLabel}`}</strong><span>{definition.description}</span></div>}
      footer={<Space><Button onClick={onClose}>取消</Button><Button type="primary" icon={<IconSave />} loading={saving} onClick={save}>{saveLabel}</Button></Space>}
    >
      {editorContent}
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

function PolicyFields({ spec, update, updateList, removeListItem, references, referenceSelect }: ListProps & { references: References; referenceSelect: ReferenceSelect }) {
  const rules = (spec.rules as Spec[]) ?? [];
  const siteOptions = segmentSites(spec.segment_id, references);
  const egressOptions = segmentEgresses(spec.segment_id, references);
  return <>
    <FormIntro title="在一个网络分段内选择出口">策略只匹配所选分段内的站点与流量，不会跨分段生效。规则按优先级依次匹配；没有命中的流量继续使用来源站点的本地出口。</FormIntro>
    <Form.Item label="生效网络" required>{referenceSelect('segments', spec.segment_id, (value) => {
      update('segment_id', value);
      update('rules', rules.map((rule) => ({ ...rule, source_site_ids: [], egress_id: rule.action_type === 'REMOTE_EGRESS' ? '' : rule.egress_id })));
    }, '选择网络分段')}</Form.Item>
    <Collapse className="advanced-collapse"><Collapse.Item name="generation" header="高级：策略代次"><Form.Item label="配置代次" required><InputNumber min={1} precision={0} value={Number(spec.generation)} onChange={(value) => update('generation', value)} /></Form.Item><FieldHelp>用于控制策略发布顺序。普通修改保持当前值即可，系统仍会通过资源修订防止覆盖并发变更。</FieldHelp></Collapse.Item></Collapse>
    <div className="collection-heading"><div><Typography.Title heading={6}>流量规则</Typography.Title><Typography.Text type="secondary">优先级数字越小越先匹配；条件留空表示不限制。</Typography.Text></div><Button icon={<IconPlus />} onClick={() => update('rules', [...rules, { id: crypto.randomUUID(), priority: rules.length * 100 + 100, source_site_ids: [], destination_cidrs: [], domains: [], traffic_classes: [], action_type: 'LOCAL_EGRESS', egress_id: '' }])}>添加规则</Button></div>
    {rules.length === 0 ? <div className="inline-empty">尚未添加覆盖规则，所有流量保持本站出口。</div> : <div className="structured-list">{rules.map((rule, index) => <section className="structured-item" key={String(rule.id ?? index)}>
      <header><div><strong>规则 {index + 1}</strong><span>优先级 {String(rule.priority)}</span></div><Button type="text" status="danger" icon={<IconDelete />} aria-label={`删除规则 ${index + 1}`} onClick={() => removeListItem('rules', index)} /></header>
      <div className="form-grid rule-grid"><Form.Item label="优先级"><InputNumber min={0} precision={0} value={Number(rule.priority)} onChange={(value) => updateList('rules', index, 'priority', value)} /></Form.Item><Form.Item label="来源站点"><Select mode="multiple" showSearch value={(rule.source_site_ids as string[]) ?? []} onChange={(value) => updateList('rules', index, 'source_site_ids', value)} options={siteOptions} placeholder={spec.segment_id ? '全部已接入站点' : '请先选择生效网络'} maxTagCount="responsive" /></Form.Item></div>
      <Form.Item label="目标网段"><InputTag value={(rule.destination_cidrs as string[]) ?? []} onChange={(value) => updateList('rules', index, 'destination_cidrs', value)} tokenSeparators={[',', ' ']} saveOnBlur placeholder={rule.action_type === 'REMOTE_EGRESS' ? '输入 0.0.0.0/0 表示全部互联网流量' : '输入 CIDR 后回车，例如 10.20.0.0/16'} /></Form.Item>
      <Form.Item label="目标域名"><InputTag value={(rule.domains as string[]) ?? []} onChange={(value) => updateList('rules', index, 'domains', value)} tokenSeparators={[',', ' ']} saveOnBlur placeholder="输入域名后回车，例如 video.example.com" /></Form.Item>
      <div className="form-grid two"><Form.Item label="业务类型"><Select mode="multiple" allowCreate showSearch value={(rule.traffic_classes as string[]) ?? []} onChange={(value) => updateList('rules', index, 'traffic_classes', value)} options={trafficClassOptions} placeholder="全部业务" maxTagCount="responsive" /></Form.Item><Form.Item label="使用出口"><Radio.Group type="button" value={rule.action_type} onChange={(value) => updateList('rules', index, 'action_type', value)} options={[{ label: '本站出口', value: 'LOCAL_EGRESS' }, { label: '远端出口', value: 'REMOTE_EGRESS' }]} /></Form.Item></div>
      {rule.action_type === 'REMOTE_EGRESS' && <Form.Item label="指定远端出口" required>{referenceSelect('egresses', rule.egress_id, (value) => updateList('rules', index, 'egress_id', value), spec.segment_id ? '选择该网络内已发布的出口' : '请先选择生效网络', egressOptions)}</Form.Item>}
    </section>)}</div>}
  </>;
}

function DnsFields({ spec, update, updateList, removeListItem, references, referenceSelect }: ListProps & { references: References; referenceSelect: ReferenceSelect }) {
  const records = (spec.records as Spec[]) ?? [];
  const selectedSiteIds = (spec.site_ids as string[]) ?? [];
  const publishScope = String(spec.publish_scope ?? (selectedSiteIds.length > 0 ? 'SELECTED' : 'ALL'));
  const siteOptions = segmentSites(spec.segment_id, references);
  const prefixOptions = segmentPrefixes(spec.segment_id, references);
  return <>
    <FormIntro title="为内部服务提供统一名称">DNS 记录只发布到所选网络分段；你可以发布到该分段的全部站点，也可以限制到指定站点。</FormIntro>
    <Form.Item label="网络分段" required>{referenceSelect('segments', spec.segment_id, (value) => {
      update('segment_id', value);
      update('site_ids', []);
      update('records', records.map((record) => ({ ...record, required_prefix_id: '' })));
    }, '选择分段')}</Form.Item>
    <Form.Item label="发布范围" required><Radio.Group type="button" value={publishScope} onChange={(value) => { update('publish_scope', value); if (value === 'ALL') update('site_ids', []); }} options={[{ label: '全部站点', value: 'ALL' }, { label: '指定站点', value: 'SELECTED' }]} /></Form.Item>
    {publishScope === 'SELECTED' && <Form.Item label="指定站点" required><Select mode="multiple" showSearch allowClear value={selectedSiteIds} onChange={(value) => update('site_ids', value)} options={siteOptions} placeholder={spec.segment_id ? '选择已接入该网络的站点' : '请先选择网络分段'} maxTagCount="responsive" notFoundContent="该网络暂无已接入站点" /></Form.Item>}
    <Form.Item label="内部域" required><Input value={getValue(spec, 'zone')} onChange={(value) => update('zone', value)} placeholder="corp.example.internal" /><FieldHelp>建议使用组织自有域名的内部子域，避免与公网域名或本地域名冲突。</FieldHelp></Form.Item>
    <div className="collection-heading"><div><Typography.Title heading={6}>解析记录</Typography.Title><Typography.Text type="secondary">统一发布站点间服务地址，无需逐台维护 hosts。</Typography.Text></div><Button icon={<IconPlus />} onClick={() => update('records', [...records, { name: '', type: 'A', value: '', ttl_seconds: 60, required_prefix_id: '' }])}>添加记录</Button></div>
    {records.length === 0 ? <div className="inline-empty">尚未添加解析记录。保存空配置不会改变现有公网 DNS。</div> : <div className="structured-list dns-list">{records.map((record, index) => <section className="structured-item" key={index}>
      <header><div><strong>记录 {index + 1}</strong><span>{String(record.type ?? 'A')}</span></div><Button type="text" status="danger" icon={<IconDelete />} aria-label={`删除记录 ${index + 1}`} onClick={() => removeListItem('records', index)} /></header>
      <div className="form-grid dns-grid"><Form.Item label="服务名称"><Input value={getValue(record, 'name')} onChange={(value) => updateList('records', index, 'name', value)} placeholder="gateway.corp.example.internal" /></Form.Item><Form.Item label="类型"><Select value={getValue(record, 'type') || 'A'} onChange={(value) => updateList('records', index, 'type', value)} options={['A', 'AAAA', 'CNAME']} /></Form.Item><Form.Item label="指向地址"><Input className="mono-input" value={getValue(record, 'value')} onChange={(value) => updateList('records', index, 'value', value)} placeholder={record.type === 'CNAME' ? 'target.example.internal' : record.type === 'AAAA' ? '2001:db8::10' : '10.0.0.10'} /></Form.Item><Form.Item label="缓存时间"><InputNumber min={5} max={86400} precision={0} value={Number(record.ttl_seconds)} onChange={(value) => updateList('records', index, 'ttl_seconds', value)} suffix="秒" /></Form.Item></div>
      <Collapse className="advanced-collapse record-constraint"><Collapse.Item name={`constraint-${index}`} header="高级：仅在网段可达时发布"><Form.Item label="依赖网段">{referenceSelect('prefixes', record.required_prefix_id, (value) => updateList('records', index, 'required_prefix_id', value), '不限制', prefixOptions)}</Form.Item><FieldHelp>选择后，只有同一网络分段内的对应网段可达时才向节点发布这条记录，可避免把不可访问的地址交给客户端。</FieldHelp></Collapse.Item></Collapse>
    </section>)}</div>}
  </>;
}
