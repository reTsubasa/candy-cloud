import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Drawer,
  Form,
  Input,
  Message,
  Progress,
  Radio,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
} from '@arco-design/web-react';
import {
  IconCheck,
  IconCheckCircle,
  IconDownload,
  IconLeft,
  IconRefresh,
  IconRight,
} from '@arco-design/web-react/icon';
import {
  createNodeJoinCode,
  createResource,
  fetchRuntimeActivationReadiness,
  listNodeJoinCodes,
  listResources,
} from '../api';
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import type {
  ControlResource,
  EnrollmentActivation,
  EnrollmentActivationSecret,
  ResourceDefinition,
  Session,
  RuntimeActivationReadiness,
} from '../types';
import type { Spec } from '../resource-form';
import { ResourceEditor } from './ResourceEditor';
import { downloadEnrollmentBootstrap, enrollmentExpired, validCloudAddress } from '../enrollment-bootstrap';
import { compatibleEnrollmentArchitecture, defaultEnrollmentArchitecture, enrollmentArchitectureOptions, type EnrollmentPlatform } from '../enrollment-platform';

type Props = {
  visible: boolean;
  session: Session;
  onClose: () => void;
  onChanged: () => void;
};

type ResourceKey = 'sites' | 'nodes' | 'segments' | 'attachments' | 'prefixes' | 'peers' | 'paths' | 'egress' | 'policies' | 'dns';
type ResourceMap = Record<ResourceKey, ControlResource[]>;
type Selection = {
  siteA: string;
  siteB: string;
  nodeA: string;
  nodeB: string;
  segment: string;
  attachmentA: string;
  attachmentB: string;
  peer: string;
};

const emptyResources: ResourceMap = {
  sites: [], nodes: [], segments: [], attachments: [], prefixes: [], peers: [], paths: [], egress: [], policies: [], dns: [],
};

const emptySelection: Selection = {
  siteA: '', siteB: '', nodeA: '', nodeB: '', segment: '', attachmentA: '', attachmentB: '', peer: '',
};

const steps = [
  { key: 'sites', title: '创建两个站点', detail: '添加需要互通的两个地点，例如办公室和云服务器。', required: true },
  { key: 'nodes', title: '为站点添加节点', detail: '每个站点选择或加入一台运行 Candy 的设备。', required: true },
  { key: 'segments', title: '创建互联网络', detail: '建立一个供两端节点安全通信的专用网络。', required: true },
  { key: 'attachments', title: '将节点加入网络', detail: '为两台节点分配专用地址并接入同一网络。', required: true },
  { key: 'prefixes', title: '填写两端局域网', detail: '填写两个站点需要互相访问的本地网段。', required: true },
  { key: 'peers', title: '连接两个站点', detail: '确认两个站点在这个网络中建立互通关系。', required: true },
  { key: 'paths', title: '配置双向线路', detail: '分别填写去程和返程实际可达的 UDP 地址。', required: true },
  { key: 'egress', title: '共享互联网出口', detail: '需要让另一站点借用本站出口时再配置。', required: false },
  { key: 'policies', title: '设置流量规则', detail: '需要指定本地或远端出口时再配置。', required: false },
  { key: 'dns', title: '添加内部域名', detail: '需要通过域名访问站点间服务时再配置。', required: false },
] as const;

const definitionByKey = Object.fromEntries([...resourceDefinitions, pathDefinition].map((definition) => [definition.key, definition])) as Record<ResourceKey, ResourceDefinition>;

function specText(item: ControlResource | undefined, key: string): string {
  return String(item?.resource.spec[key] ?? '');
}

function resourceName(item: ControlResource | undefined): string {
  if (!item) return '未选择站点';
  const spec = item.resource.spec;
  const prefix = spec.prefix as { network?: string; prefix_len?: number } | undefined;
  return String(spec.name ?? spec.display_name ?? (prefix?.network ? `${prefix.network}/${prefix.prefix_len}` : item.metadata.id));
}

function options(items: ControlResource[]) {
  return items.map((item) => ({ label: resourceName(item), value: item.metadata.id }));
}

function byId(items: ControlResource[], id: string) {
  return items.find((item) => item.metadata.id === id);
}

function samePair(peer: ControlResource, selection: Selection): boolean {
  const a = specText(peer, 'site_a_id');
  const b = specText(peer, 'site_b_id');
  return specText(peer, 'segment_id') === selection.segment
    && ((a === selection.siteA && b === selection.siteB) || (a === selection.siteB && b === selection.siteA));
}

function pathDirection(path: ControlResource, source: string, destination: string, selection: Selection): boolean {
  return specText(path, 'segment_id') === selection.segment
    && specText(path, 'peer_id') === selection.peer
    && specText(path, 'source_attachment_id') === source
    && specText(path, 'destination_attachment_id') === destination;
}

function nextOverlayAddress(segment: ControlResource | undefined, attachments: ControlResource[], preferredOffset: number): string {
  const prefix = segment?.resource.spec.overlay_prefix as { network?: string; prefix_len?: number } | undefined;
  const octets = String(prefix?.network ?? '').split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return '';
  const base = octets.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
  const used = new Set(attachments.map((item) => specText(item, 'overlay_router_ipv4')));
  for (let offset = preferredOffset; offset < preferredOffset + 64; offset += 1) {
    const value = (base + offset) >>> 0;
    const candidate = [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
    if (!used.has(candidate)) return candidate;
  }
  return '';
}

function completion(resources: ResourceMap, selection: Selection, activationReady: boolean): boolean[] {
  const nodeA = byId(resources.nodes, selection.nodeA);
  const nodeB = byId(resources.nodes, selection.nodeB);
  const attachmentA = byId(resources.attachments, selection.attachmentA);
  const attachmentB = byId(resources.attachments, selection.attachmentB);
  const prefixA = resources.prefixes.some((item) => specText(item, 'site_id') === selection.siteA && specText(item, 'segment_id') === selection.segment);
  const prefixB = resources.prefixes.some((item) => specText(item, 'site_id') === selection.siteB && specText(item, 'segment_id') === selection.segment);
  const forward = resources.paths.some((item) => pathDirection(item, selection.attachmentA, selection.attachmentB, selection));
  const reverse = resources.paths.some((item) => pathDirection(item, selection.attachmentB, selection.attachmentA, selection));
  return [
    Boolean(selection.siteA && selection.siteB && selection.siteA !== selection.siteB),
    Boolean(nodeA && nodeB && specText(nodeA, 'site_id') === selection.siteA && specText(nodeB, 'site_id') === selection.siteB),
    Boolean(selection.segment && byId(resources.segments, selection.segment)),
    Boolean(attachmentA && attachmentB),
    prefixA && prefixB,
    Boolean(selection.peer && byId(resources.peers, selection.peer)),
    forward && reverse && activationReady,
    resources.egress.some((item) => specText(item, 'site_id') === selection.siteA || specText(item, 'site_id') === selection.siteB),
    resources.policies.some((item) => specText(item, 'segment_id') === selection.segment),
    resources.dns.some((item) => specText(item, 'segment_id') === selection.segment),
  ];
}

export function QuickSetupWizard({ visible, session, onClose, onChanged }: Props) {
  const [message, messageHolder] = Message.useMessage();
  const [resources, setResources] = useState<ResourceMap>(emptyResources);
  const [selection, setSelection] = useState<Selection>(emptySelection);
  const [current, setCurrent] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [advanceWhenReady, setAdvanceWhenReady] = useState(false);
  const [activationReadiness, setActivationReadiness] = useState<RuntimeActivationReadiness | null>(null);
  const tenantId = session.claims.tenant_id;

  const load = useCallback(async () => {
    if (!tenantId) return emptyResources;
    setLoading(true);
    setError(null);
    try {
      const entries = await Promise.all((Object.keys(emptyResources) as ResourceKey[]).map(async (key) => {
        const response = await listResources(session.token, tenantId, definitionByKey[key].collection);
        return [key, response.items.filter((item) => item.metadata.state === 'ACTIVE')] as const;
      }));
      const loaded = Object.fromEntries(entries) as ResourceMap;
      setResources(loaded);
      return loaded;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '快速配置资源加载失败');
      return null;
    } finally {
      setLoading(false);
    }
  }, [session.token, tenantId]);

  useEffect(() => {
    if (visible) void load();
  }, [load, visible]);

  useEffect(() => {
    if (!visible) return;
    setSelection((previous) => {
      const siteA = byId(resources.sites, previous.siteA)?.metadata.id ?? resources.sites[0]?.metadata.id ?? '';
      const siteB = byId(resources.sites, previous.siteB)?.metadata.id
        ?? resources.sites.find((item) => item.metadata.id !== siteA)?.metadata.id
        ?? '';
      const nodeA = resources.nodes.find((item) => item.metadata.id === previous.nodeA && specText(item, 'site_id') === siteA)?.metadata.id
        ?? resources.nodes.find((item) => specText(item, 'site_id') === siteA)?.metadata.id
        ?? '';
      const nodeB = resources.nodes.find((item) => item.metadata.id === previous.nodeB && specText(item, 'site_id') === siteB)?.metadata.id
        ?? resources.nodes.find((item) => specText(item, 'site_id') === siteB)?.metadata.id
        ?? '';
      const segment = byId(resources.segments, previous.segment)?.metadata.id ?? resources.segments[0]?.metadata.id ?? '';
      const attachmentA = resources.attachments.find((item) => item.metadata.id === previous.attachmentA && specText(item, 'site_id') === siteA && specText(item, 'segment_id') === segment)?.metadata.id
        ?? resources.attachments.find((item) => specText(item, 'site_id') === siteA && specText(item, 'segment_id') === segment)?.metadata.id
        ?? '';
      const attachmentB = resources.attachments.find((item) => item.metadata.id === previous.attachmentB && specText(item, 'site_id') === siteB && specText(item, 'segment_id') === segment)?.metadata.id
        ?? resources.attachments.find((item) => specText(item, 'site_id') === siteB && specText(item, 'segment_id') === segment)?.metadata.id
        ?? '';
      const draft = { ...previous, siteA, siteB, nodeA, nodeB, segment, attachmentA, attachmentB };
      const peer = resources.peers.find((item) => item.metadata.id === previous.peer && samePair(item, draft))?.metadata.id
        ?? resources.peers.find((item) => samePair(item, draft))?.metadata.id
        ?? '';
      return { ...draft, peer };
    });
  }, [resources, visible]);

  useEffect(() => {
    if (!visible || !tenantId || !selection.segment) {
      setActivationReadiness(null);
      return;
    }
    let cancelled = false;
    void fetchRuntimeActivationReadiness(session.token, tenantId, selection.segment)
      .then((result) => { if (!cancelled) setActivationReadiness(result); })
      .catch(() => { if (!cancelled) setActivationReadiness(null); });
    return () => { cancelled = true; };
  }, [resources.paths, selection.segment, session.token, tenantId, visible]);

  const completed = useMemo(
    () => completion(resources, selection, activationReadiness?.ready === true),
    [activationReadiness, resources, selection],
  );
  const requiredDone = completed.slice(0, 7).filter(Boolean).length;

  useEffect(() => {
    if (!advanceWhenReady || !completed[current]) return;
    setAdvanceWhenReady(false);
    setCurrent((value) => Math.min(value + 1, steps.length - 1));
  }, [advanceWhenReady, completed, current]);

  const saved = async () => {
    setAdvanceWhenReady(true);
    const loaded = await load();
    if (loaded) {
      onChanged();
      message.success?.('配置已保存，正在检查下一项');
    }
  };

  const updateSelection = (key: keyof Selection, value: string) => setSelection((currentSelection) => ({ ...currentSelection, [key]: value }));
  const stageLocked = (index: number) => index > 0 && index <= 6 && !completed[index - 1];
  const optionalLocked = current >= 7 && requiredDone < 7;

  const editorConfig = useMemo((): { definition: ResourceDefinition; initialSpec: Spec; label: string } | null => {
    const missingSite = !selection.siteA ? '第一个站点' : '第二个站点';
    if (current === 0) return { definition: definitionByKey.sites, initialSpec: { name: '', kind: 'EDGE' }, label: `创建${missingSite}` };
    if (current === 2) return { definition: definitionByKey.segments, initialSpec: { name: '', overlay_cidr: '100.64.0.0/24' }, label: '创建并使用此网络' };
    if (current === 3) {
      const useA = !selection.attachmentA;
      const segment = byId(resources.segments, selection.segment);
      return { definition: definitionByKey.attachments, initialSpec: {
        segment_id: selection.segment,
        site_id: useA ? selection.siteA : selection.siteB,
        node_id: useA ? selection.nodeA : selection.nodeB,
        overlay_router_ipv4: nextOverlayAddress(segment, resources.attachments, useA ? 2 : 3),
        epoch_floor: 1,
      }, label: `接入${useA ? resourceName(byId(resources.sites, selection.siteA)) : resourceName(byId(resources.sites, selection.siteB))}节点` };
    }
    if (current === 4) {
      const hasA = resources.prefixes.some((item) => specText(item, 'site_id') === selection.siteA && specText(item, 'segment_id') === selection.segment);
      return { definition: definitionByKey.prefixes, initialSpec: { site_id: hasA ? selection.siteB : selection.siteA, segment_id: selection.segment, cidr: '', source: 'CONFIGURED' }, label: '声明此可达网段' };
    }
    if (current === 5) return { definition: definitionByKey.peers, initialSpec: { segment_id: selection.segment, site_a_id: selection.siteA, site_b_id: selection.siteB, path_policy: 'DIRECT_PREFERRED' }, label: '建立站点互联' };
    if (current === 6) {
      const forwardExists = resources.paths.some((item) => pathDirection(item, selection.attachmentA, selection.attachmentB, selection));
      return { definition: definitionByKey.paths, initialSpec: {
        segment_id: selection.segment,
        peer_id: selection.peer,
        source_attachment_id: forwardExists ? selection.attachmentB : selection.attachmentA,
        destination_attachment_id: forwardExists ? selection.attachmentA : selection.attachmentB,
        kind: 'DIRECT', relay_id: null, transport_node_id: selection.nodeB, priority: 100,
      }, label: `保存${forwardExists ? '返程' : '去程'}线路` };
    }
    if (current === 7) return { definition: definitionByKey.egress, initialSpec: { name: '', site_id: selection.siteB, attachment_id: selection.attachmentB, max_sessions: 10000, capacity_mbps: 1000 }, label: '发布出口' };
    if (current === 8) return { definition: definitionByKey.policies, initialSpec: { segment_id: selection.segment, generation: 1, rules: [] }, label: '发布策略' };
    if (current === 9) return { definition: definitionByKey.dns, initialSpec: { segment_id: selection.segment, site_id: selection.siteB, zone: '', records: [] }, label: '保存 DNS 配置' };
    return null;
  }, [current, resources, selection]);

  const renderSelections = () => {
    if (current === 0) return <SelectionGrid>
      <Form.Item label="第一个站点" required><Select value={selection.siteA || undefined} onChange={(value) => updateSelection('siteA', value)} options={options(resources.sites)} placeholder="选择已有站点" /></Form.Item>
      <Form.Item label="第二个站点" required><Select value={selection.siteB || undefined} onChange={(value) => updateSelection('siteB', value)} options={options(resources.sites.filter((item) => item.metadata.id !== selection.siteA))} placeholder="选择另一个站点" /></Form.Item>
    </SelectionGrid>;
    if (current === 1) return <SelectionGrid>
      <Form.Item label={`${resourceName(byId(resources.sites, selection.siteA))}节点`} required><Select value={selection.nodeA || undefined} onChange={(value) => updateSelection('nodeA', value)} options={options(resources.nodes.filter((item) => specText(item, 'site_id') === selection.siteA))} placeholder="选择已加入节点" /></Form.Item>
      <Form.Item label={`${resourceName(byId(resources.sites, selection.siteB))}节点`} required><Select value={selection.nodeB || undefined} onChange={(value) => updateSelection('nodeB', value)} options={options(resources.nodes.filter((item) => specText(item, 'site_id') === selection.siteB))} placeholder="选择已加入节点" /></Form.Item>
    </SelectionGrid>;
    if (current === 2) return <Form layout="vertical"><Form.Item label="用于此次互联的网络" required><Select value={selection.segment || undefined} onChange={(value) => updateSelection('segment', value)} options={options(resources.segments)} placeholder="选择已有网络" /></Form.Item></Form>;
    if (current === 3) return <SelectionGrid>
      <Form.Item label="第一个站点的接入" required><Select value={selection.attachmentA || undefined} onChange={(value) => updateSelection('attachmentA', value)} options={options(resources.attachments.filter((item) => specText(item, 'site_id') === selection.siteA && specText(item, 'segment_id') === selection.segment))} placeholder="选择已有接入" /></Form.Item>
      <Form.Item label="第二个站点的接入" required><Select value={selection.attachmentB || undefined} onChange={(value) => updateSelection('attachmentB', value)} options={options(resources.attachments.filter((item) => specText(item, 'site_id') === selection.siteB && specText(item, 'segment_id') === selection.segment))} placeholder="选择已有接入" /></Form.Item>
    </SelectionGrid>;
    if (current === 5) return <Form layout="vertical"><Form.Item label="用于此次配置的互联关系" required><Select value={selection.peer || undefined} onChange={(value) => updateSelection('peer', value)} options={options(resources.peers.filter((item) => samePair(item, selection)))} placeholder="选择已有互联关系" /></Form.Item></Form>;
    return null;
  };

  const currentStep = steps[current];
  const canMoveNext = completed[current] || !currentStep.required;
  const missingNodeSite = !selection.nodeA ? selection.siteA : selection.siteB;

  return <Drawer
    width={1180}
    visible={visible}
    onCancel={onClose}
    className="cloud-drawer setup-drawer"
    footer={null}
    title={<div className="drawer-title"><strong>快速配置</strong><span>在一个流程内完成可运行的双站点网络</span></div>}
  >
    {messageHolder}
    <Spin loading={loading && resources.sites.length === 0} block>
      {error && <Alert type="error" showIcon content={error} action={<Button size="small" icon={<IconRefresh />} onClick={() => void load()}>重试</Button>} />}
      <div className="quick-setup-shell">
        <aside className="quick-setup-nav">
          <div className="quick-setup-progress"><div><strong>{requiredDone} / 7</strong><span>基础配置</span></div><Progress percent={Math.round(requiredDone / 7 * 100)} showText={false} /></div>
          <div className="quick-step-list">
            {steps.map((step, index) => {
              const locked = stageLocked(index) || (index >= 7 && requiredDone < 7);
              return <button key={step.key} type="button" className={`quick-step ${index === current ? 'active' : ''} ${completed[index] ? 'done' : ''}`} disabled={locked} onClick={() => setCurrent(index)}>
                <span className="quick-step-index">{completed[index] ? <IconCheck /> : index + 1}</span>
                <span><strong>{step.title}{!step.required && <Tag>按需</Tag>}</strong></span>
              </button>;
            })}
          </div>
        </aside>
        <main className="quick-setup-workspace">
          <header className="quick-workspace-heading"><div><span>步骤 {current + 1}</span><Typography.Title heading={4}>{currentStep.title}</Typography.Title><Typography.Text type="secondary">{currentStep.detail}</Typography.Text></div>{completed[current] && <Tag color="green" icon={<IconCheckCircle />}>已完成</Tag>}</header>
          <div className="quick-workspace-body">
            {renderSelections()}
            {current === 1 && !completed[1] && <QuickNodeEnrollment session={session} siteId={missingNodeSite} siteName={resourceName(byId(resources.sites, missingNodeSite))} onSaved={() => void saved()} />}
            {current === 4 && completed[4] && <StageComplete text="两个站点都已声明至少一个可达网段。" />}
            {current === 6 && <PathStatus resources={resources} selection={selection} readiness={activationReadiness} />}
            {completed[current] && current !== 1 && current !== 4 && current !== 6 && <StageComplete text="已选择并验证可用于此次编排的配置。" />}
            {!completed[current] && current !== 1 && editorConfig && <ResourceEditor
              key={`${current}-${editorConfig.definition.kind}-${selection.siteA}-${selection.siteB}-${selection.segment}-${selection.peer}-${resources[steps[current].key as ResourceKey].length}`}
              visible
              embedded
              initialSpec={editorConfig.initialSpec}
              saveLabel={editorConfig.label}
              definition={editorConfig.definition}
              session={session}
              resource={null}
              onClose={() => undefined}
              onSaved={() => void saved()}
            />}
            {optionalLocked && <Alert type="warning" showIcon content="请先完成前七项基础配置，再添加出口、策略或内部 DNS。" />}
          </div>
          <footer className="quick-workspace-footer">
            <Button icon={<IconLeft />} disabled={current === 0} onClick={() => setCurrent((value) => Math.max(0, value - 1))}>上一步</Button>
            <Space>
              {!currentStep.required && <Button onClick={() => setCurrent((value) => Math.min(steps.length - 1, value + 1))}>暂不配置</Button>}
              <Button type="primary" icon={<IconRight />} disabled={!canMoveNext || current === steps.length - 1} onClick={() => setCurrent((value) => Math.min(steps.length - 1, value + 1))}>{current === 6 ? '进入按需配置' : '下一步'}</Button>
              {current === steps.length - 1 && <Button type="primary" onClick={onClose}>完成</Button>}
            </Space>
          </footer>
        </main>
      </div>
    </Spin>
  </Drawer>;
}

function SelectionGrid({ children }: { children: React.ReactNode }) {
  return <Form layout="vertical" className="quick-selection"><div className="form-grid two">{children}</div></Form>;
}

function StageComplete({ text }: { text: string }) {
  return <div className="quick-stage-complete"><IconCheckCircle /><div><strong>当前步骤已就绪</strong><span>{text}</span></div></div>;
}

function PathStatus({ resources, selection, readiness }: { resources: ResourceMap; selection: Selection; readiness: RuntimeActivationReadiness | null }) {
  const forward = resources.paths.some((item) => pathDirection(item, selection.attachmentA, selection.attachmentB, selection));
  const reverse = resources.paths.some((item) => pathDirection(item, selection.attachmentB, selection.attachmentA, selection));
  return <>
    <div className="path-direction-status"><div className={forward ? 'done' : ''}><span>{forward ? <IconCheck /> : '1'}</span><strong>去程线路</strong><small>第一个站点 → 第二个站点</small></div><IconRight /><div className={reverse ? 'done' : ''}><span>{reverse ? <IconCheck /> : '2'}</span><strong>返程线路</strong><small>第二个站点 → 第一个站点</small></div></div>
    {forward && reverse && readiness && !readiness.ready && <Alert type="warning" showIcon content={`线路已保存，但还有 ${readiness.missing_transport_count} 个节点未发布安全传输身份。节点上线并完成 Cloud 同步后会自动就绪。`} />}
    {forward && reverse && readiness?.ready && <StageComplete text="双向线路、服务授权和节点安全身份均已验证，可生成运行配置。" />}
  </>;
}

function QuickNodeEnrollment({ session, siteId, siteName, onSaved }: { session: Session; siteId: string; siteName: string; onSaved: () => void }) {
  const [message, messageHolder] = Message.useMessage();
  const [phase, setPhase] = useState<'details' | 'waiting' | 'finish' | 'expired'>('details');
  const [platform, setPlatform] = useState<EnrollmentPlatform>('LINUX_SERVER');
  const [name, setName] = useState('');
  const [architecture, setArchitecture] = useState(defaultEnrollmentArchitecture('LINUX_SERVER'));
  const cloudAddress = window.location.origin;
  const [secret, setSecret] = useState<EnrollmentActivationSecret | null>(null);
  const [activation, setActivation] = useState<EnrollmentActivation | null>(null);
  const [busy, setBusy] = useState(false);
  const tenantId = session.claims.tenant_id;

  useEffect(() => { setArchitecture((value) => compatibleEnrollmentArchitecture(platform, value)); }, [platform]);

  useEffect(() => {
    if (phase !== 'waiting' || !secret || !tenantId) return undefined;
    const syncExpiry = () => {
      if (!enrollmentExpired(secret.expires_at)) return false;
      setPhase('expired');
      return true;
    };
    const poll = async () => {
      if (syncExpiry()) return;
      try {
        const items = await listNodeJoinCodes(session.token, tenantId);
        const current = items.find((item) => item.id === secret.id);
        if (current?.status === 'EXPIRED' || enrollmentExpired(current?.expires_at ?? secret.expires_at)) {
          setPhase('expired');
          return;
        }
        if (current?.status === 'CONSUMED' && current.device_id && current.device_key_id) {
          setActivation(current);
          setName((value) => value || current.display_name || '新节点');
          setPhase('finish');
        }
      } catch {
        // Keep waiting; the explicit refresh button reports persistent failures.
      }
    };
    if (syncExpiry()) return undefined;
    void poll();
    const remaining = Date.parse(secret.expires_at) - Date.now();
    const expiryTimer = window.setTimeout(syncExpiry, Math.max(0, remaining));
    const timer = window.setInterval(() => void poll(), 3000);
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible' && !syncExpiry()) void poll();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      window.clearTimeout(expiryTimer);
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [phase, secret, session.token, tenantId]);

  const begin = async () => {
    if (!tenantId || !name.trim() || !siteId || !architecture || !validCloudAddress(cloudAddress)) {
      message.warning?.('请填写节点名称、处理器架构和有效的 Cloud 地址');
      return;
    }
    setBusy(true);
    try {
      setSecret(await createNodeJoinCode(session.token, tenantId, 600, { site_id: siteId, display_name: name.trim(), platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX', architecture }));
      setPhase('waiting');
    } catch (reason) {
      message.error?.(reason instanceof Error ? reason.message : '加入码创建失败');
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    if (!tenantId || !activation?.device_id || !activation.device_key_id) return;
    setBusy(true);
    try {
      await createResource(session.token, tenantId, 'nodes', { kind: 'NODE', spec: {
        device_id: activation.device_id,
        device_key_id: activation.device_key_id,
        site_id: siteId,
        display_name: name.trim(),
        platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX',
        architecture,
      } });
      message.success?.('节点身份已确认并加入站点');
      setPhase('details');
      setSecret(null);
      setActivation(null);
      setName('');
      onSaved();
    } catch (reason) {
      message.error?.(reason instanceof Error ? reason.message : '节点配置失败');
    } finally {
      setBusy(false);
    }
  };

  return <div className="quick-enrollment">
    {messageHolder}
    {phase === 'details' && <Form layout="vertical">
      <Alert type="info" showIcon content={`正在为“${siteName}”加入节点。设备主动连接 Cloud，不要求具备公网 IP。`} />
      <Form.Item label="设备类型" required><Radio.Group type="button" value={platform} onChange={setPlatform} options={[{ label: 'OpenWrt', value: 'OPEN_WRT' }, { label: 'Linux Server', value: 'LINUX_SERVER' }]} /></Form.Item>
      <div className="form-grid two"><Form.Item label="节点名称" required><Input value={name} onChange={setName} placeholder="例如：上海主网关" /></Form.Item><Form.Item label="处理器架构" required><Select value={architecture} onChange={setArchitecture} options={enrollmentArchitectureOptions(platform)} /></Form.Item></div>
      {!validCloudAddress(cloudAddress) && <Alert type="error" showIcon content="节点加入文件只能由 HTTPS Cloud 生成。请先通过 HTTPS 地址访问当前管理端。" />}
      <div className="embedded-editor-actions"><Button type="primary" disabled={!validCloudAddress(cloudAddress)} loading={busy} onClick={() => void begin()}>生成加入文件</Button></div>
    </Form>}
    {phase === 'waiting' && secret && <div className="quick-activation">
      <div className="activation-status"><Spin dot /><div><strong>等待设备完成安全注册</strong><span>每 3 秒自动检查，加入码在 {new Date(secret.expires_at).toLocaleString()} 前有效</span></div><Tag color="arcoblue">等待设备</Tag></div>
      <section className="bootstrap-download">
        <div><IconDownload /><span><strong>下载自动加入文件</strong><small>已包含 Cloud 地址和一次性注册信息，不需要再输入加入码</small></span></div>
        <Button type="primary" icon={<IconDownload />} onClick={() => downloadEnrollmentBootstrap({ secret, cloudAddress })}>下载文件</Button>
      </section>
      <ol className="bootstrap-steps"><li>把 <code>candy-node-bootstrap.json</code> 传到目标设备</li><li>{platform === 'LINUX_SERVER' ? <>执行 <code>sudo candy-server bootstrap candy-node-bootstrap.json</code></> : <>打开 OpenWrt 的 Candy → SD-WAN，导入该文件</>}</li><li>已安装的 Candy Runtime 会读取文件并完成安全注册</li></ol>
      <Alert type="info" showIcon content="设备完成注册后，本页会自动确认上线。加入文件成功使用后会自行删除。" />
    </div>}
    {phase === 'expired' && secret && <div className="quick-activation">
      <Alert type="warning" showIcon title="加入文件已过期" content={`本次加入文件已于 ${new Date(secret.expires_at).toLocaleString()} 失效，页面已停止等待。请重新生成加入文件后再执行安装。`} />
      <div className="embedded-editor-actions"><Button type="primary" onClick={() => { setPhase('details'); setSecret(null); setActivation(null); }}>重新生成加入文件</Button></div>
    </div>}
    {phase === 'finish' && activation && <div className="quick-activation">
      <div className="activation-status completed"><IconCheckCircle /><div><strong>设备身份已签发</strong><span>最后确认节点名称和站点归属</span></div><Tag color="green">可信设备</Tag></div>
      <Form layout="vertical"><div className="form-grid two"><Form.Item label="节点名称" required><Input value={name} onChange={setName} /></Form.Item><Form.Item label="所属站点"><Input value={siteName} disabled /></Form.Item></div></Form>
      <div className="embedded-editor-actions"><Button type="primary" loading={busy} onClick={() => void finish()}>完成节点添加</Button></div>
    </div>}
  </div>;
}
