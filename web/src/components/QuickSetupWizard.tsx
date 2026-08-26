import { useCallback, useEffect, useRef, useState } from 'react';
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
  IconPlus,
  IconRefresh,
  IconRight,
} from '@arco-design/web-react/icon';
import {
  createNodeJoinCode,
  createResource,
  fetchRuntimeActivationReadiness,
  listNodeJoinCodes,
  listResources,
  replaceResource,
} from '../api';
import { pathDefinition, resourceDefinitions } from '../resource-definitions';
import { parseCidr } from '../resource-form';
import type {
  ControlResource,
  EnrollmentActivation,
  EnrollmentActivationSecret,
  ResourceDefinition,
  RuntimeActivationReadiness,
  Session,
} from '../types';
import { downloadEnrollmentBootstrap, enrollmentExpired, validCloudAddress } from '../enrollment-bootstrap';
import { compatibleEnrollmentArchitecture, defaultEnrollmentArchitecture, enrollmentArchitectureOptions, type EnrollmentPlatform } from '../enrollment-platform';
import {
  matchingPrefix,
  matchingSegmentPrefix,
  nextOverlayAddress,
  pathDirection,
  samePair,
  type QuickSetupSelection as Selection,
} from '../quick-setup-orchestration';
import { activationDisplay } from '../activation-status';
import { ResourceEditor } from './ResourceEditor';

type Props = {
  visible: boolean;
  session: Session;
  onClose: () => void;
  onChanged: () => void;
};

type ResourceKey = 'sites' | 'nodes' | 'segments' | 'attachments' | 'prefixes' | 'peers' | 'paths' | 'relays';
type ResourceMap = Record<ResourceKey, ControlResource[]>;
const emptyResources: ResourceMap = {
  sites: [], nodes: [], segments: [], attachments: [], prefixes: [], peers: [], paths: [], relays: [],
};

const emptySelection: Selection = {
  siteA: '', siteB: '', nodeA: '', nodeB: '', segment: '', attachmentA: '', attachmentB: '', peer: '',
};

const stages = [
  { title: '选择互联两端', shortTitle: '选两端', detail: '选择两个业务站点以及各自承载 SD-WAN 的节点。' },
  { title: '确认网络范围', shortTitle: '定范围', detail: '选择要互通的内网；隧道地址和节点接入由 Candy 自动完成。' },
  { title: '连接并启用', shortTitle: '连接启用', detail: '选择连接偏好，Candy 自动生成双向线路并发布到节点。' },
] as const;

const definitionByKey = Object.fromEntries(
  [...resourceDefinitions, pathDefinition].map((definition) => [definition.key, definition]),
) as Record<string, ResourceDefinition>;

function specText(item: ControlResource | undefined, key: string): string {
  return String(item?.resource.spec[key] ?? '');
}

function byId(items: ControlResource[], id: string): ControlResource | undefined {
  return items.find((item) => item.metadata.id === id);
}

function resourceName(item: ControlResource | undefined): string {
  if (!item) return '未选择';
  const spec = item.resource.spec;
  return String(spec.name ?? spec.display_name ?? item.metadata.id);
}

function options(items: ControlResource[]) {
  return items.map((item) => ({ label: resourceName(item), value: item.metadata.id }));
}

function prefixText(item: ControlResource | undefined): string {
  const prefix = item?.resource.spec.prefix as { network?: string; prefix_len?: number } | undefined;
  return prefix?.network && prefix.prefix_len ? `${prefix.network}/${prefix.prefix_len}` : '';
}

export function QuickSetupWizard({ visible, session, onClose, onChanged }: Props) {
  const [message, messageHolder] = Message.useMessage();
  const [resources, setResources] = useState<ResourceMap>(emptyResources);
  const [selection, setSelection] = useState<Selection>(emptySelection);
  const [current, setCurrent] = useState(0);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [siteEditorVisible, setSiteEditorVisible] = useState(false);
  const [enrollSiteId, setEnrollSiteId] = useState('');
  const [networkName, setNetworkName] = useState('站点互联网络');
  const [overlayCidr, setOverlayCidr] = useState('100.64.0.0/24');
  const [prefixA, setPrefixA] = useState('');
  const [prefixB, setPrefixB] = useState('');
  const [pathPolicy, setPathPolicy] = useState<'DIRECT_PREFERRED' | 'DIRECT_ONLY' | 'RELAY_REQUIRED'>('DIRECT_PREFERRED');
  const [transportNodeId, setTransportNodeId] = useState('');
  const [relayId, setRelayId] = useState('');
  const [activationReadiness, setActivationReadiness] = useState<RuntimeActivationReadiness | null>(null);
  const [activationLoading, setActivationLoading] = useState(false);
  const [activationError, setActivationError] = useState<string | null>(null);
  const readinessRequest = useRef(0);
  const tenantId = session.claims.tenant_id;

  const load = useCallback(async () => {
    if (!tenantId) return null;
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
      setError(reason instanceof Error ? reason.message : '配置资源加载失败');
      return null;
    } finally {
      setLoading(false);
    }
  }, [session.token, tenantId]);

  useEffect(() => { if (visible) void load(); }, [load, visible]);

  useEffect(() => {
    if (!visible) return;
    setSelection((previous) => {
      const sitesWithNodes = resources.sites.filter((site) => resources.nodes.some((node) => specText(node, 'site_id') === site.metadata.id));
      const candidates = sitesWithNodes.length >= 2 ? sitesWithNodes : resources.sites;
      const siteA = byId(resources.sites, previous.siteA)?.metadata.id ?? candidates[0]?.metadata.id ?? '';
      const siteB = byId(resources.sites, previous.siteB)?.metadata.id
        ?? candidates.find((site) => site.metadata.id !== siteA)?.metadata.id
        ?? '';
      const nodeA = resources.nodes.find((node) => node.metadata.id === previous.nodeA && specText(node, 'site_id') === siteA)?.metadata.id
        ?? resources.nodes.find((node) => specText(node, 'site_id') === siteA)?.metadata.id
        ?? '';
      const nodeB = resources.nodes.find((node) => node.metadata.id === previous.nodeB && specText(node, 'site_id') === siteB)?.metadata.id
        ?? resources.nodes.find((node) => specText(node, 'site_id') === siteB)?.metadata.id
        ?? '';
      const segment = byId(resources.segments, previous.segment)?.metadata.id
        ?? (resources.segments.length === 1 ? resources.segments[0].metadata.id : '');
      const attachmentA = resources.attachments.find((item) => specText(item, 'node_id') === nodeA && specText(item, 'segment_id') === segment)?.metadata.id ?? '';
      const attachmentB = resources.attachments.find((item) => specText(item, 'node_id') === nodeB && specText(item, 'segment_id') === segment)?.metadata.id ?? '';
      const draft = { ...previous, siteA, siteB, nodeA, nodeB, segment, attachmentA, attachmentB };
      const peer = resources.peers.find((item) => samePair(item, draft))?.metadata.id ?? '';
      return { ...draft, peer };
    });
  }, [resources, visible]);

  useEffect(() => {
    if (!visible || current !== 1 || !selection.segment) return;
    const existingA = resources.prefixes.find((item) => specText(item, 'site_id') === selection.siteA && specText(item, 'segment_id') === selection.segment);
    const existingB = resources.prefixes.find((item) => specText(item, 'site_id') === selection.siteB && specText(item, 'segment_id') === selection.segment);
    setPrefixA((value) => value || prefixText(existingA));
    setPrefixB((value) => value || prefixText(existingB));
  }, [current, resources.prefixes, selection.segment, selection.siteA, selection.siteB, visible]);

  useEffect(() => {
    if (transportNodeId || !selection.nodeA || !selection.nodeB) return;
    const nodes = [byId(resources.nodes, selection.nodeA), byId(resources.nodes, selection.nodeB)];
    setTransportNodeId(nodes.find((node) => specText(node, 'platform') === 'LINUX')?.metadata.id ?? selection.nodeB);
  }, [resources.nodes, selection.nodeA, selection.nodeB, transportNodeId]);

  const refreshReadiness = useCallback(async () => {
    const request = ++readinessRequest.current;
    const segmentId = selection.segment;
    if (!tenantId || !segmentId) {
      setActivationReadiness(null);
      setActivationError(null);
      setActivationLoading(false);
      return;
    }
    setActivationLoading(true);
    setActivationError(null);
    try {
      const result = await fetchRuntimeActivationReadiness(session.token, tenantId, segmentId);
      if (request === readinessRequest.current) setActivationReadiness(result);
    } catch (reason) {
      if (request === readinessRequest.current) {
        setActivationError(reason instanceof Error ? reason.message : 'Cloud 暂时无法读取激活状态');
      }
    } finally {
      if (request === readinessRequest.current) setActivationLoading(false);
    }
  }, [selection.segment, session.token, tenantId]);

  useEffect(() => {
    if (!visible || current !== 2 || !selection.segment) {
      readinessRequest.current += 1;
      setActivationReadiness(null);
      setActivationError(null);
      setActivationLoading(false);
      return undefined;
    }
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      await refreshReadiness();
      if (!cancelled) timer = window.setTimeout(() => void poll(), 4000);
    };
    void poll();
    return () => {
      cancelled = true;
      readinessRequest.current += 1;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [current, refreshReadiness, selection.segment, visible]);

  const endpointsReady = Boolean(selection.siteA && selection.siteB && selection.siteA !== selection.siteB
    && selection.nodeA && selection.nodeB && selection.nodeA !== selection.nodeB);
  const networkReady = Boolean(selection.segment && selection.attachmentA && selection.attachmentB);
  const forwardReady = resources.paths.some((item) => pathDirection(item, selection.attachmentA, selection.attachmentB, selection));
  const reverseReady = resources.paths.some((item) => pathDirection(item, selection.attachmentB, selection.attachmentA, selection));
  const connectionReady = Boolean(selection.peer && forwardReady && reverseReady && activationReadiness?.ready);
  const completed = [endpointsReady, networkReady, connectionReady];
  const doneCount = completed.filter(Boolean).length;

  const updateSite = (side: 'A' | 'B', siteId: string) => {
    setSelection((value) => ({
      ...value,
      [`site${side}`]: siteId,
      [`node${side}`]: '',
      [`attachment${side}`]: '',
      peer: '',
    }));
    if (side === 'A') setPrefixA(''); else setPrefixB('');
  };

  const orchestrateNetwork = async () => {
    if (!tenantId || !endpointsReady) return;
    const parsedOverlay = selection.segment ? null : parseCidr(overlayCidr);
    const parsedA = prefixA.trim() ? parseCidr(prefixA) : null;
    const parsedB = prefixB.trim() ? parseCidr(prefixB) : null;
    if (!selection.segment && (!networkName.trim() || !parsedOverlay)) {
      setError('请填写网络名称和规范的隧道地址池');
      return;
    }
    if ((prefixA.trim() && !parsedA) || (prefixB.trim() && !parsedB)) {
      setError('站点内网必须使用规范 CIDR，例如 192.168.1.0/24；没有内网的站点可以留空');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const working = { ...resources, segments: [...resources.segments], attachments: [...resources.attachments], prefixes: [...resources.prefixes] };
      let segment = byId(working.segments, selection.segment);
      if (!segment) {
        const response = await createResource(session.token, tenantId, 'segments', {
          kind: 'SEGMENT', spec: { name: networkName.trim(), overlay_prefix: parsedOverlay },
        });
        segment = response.resource;
        working.segments.push(segment);
      }
      const ensureAttachment = async (siteId: string, nodeId: string, preferredOffset: number) => {
        const existing = working.attachments.find((item) => specText(item, 'segment_id') === segment!.metadata.id && specText(item, 'node_id') === nodeId);
        if (existing) return existing;
        const address = nextOverlayAddress(segment!, working.attachments, preferredOffset);
        if (!address) throw new Error('隧道地址池没有可分配的地址');
        const response = await createResource(session.token, tenantId, 'attachments', {
          kind: 'ATTACHMENT', spec: { segment_id: segment!.metadata.id, site_id: siteId, node_id: nodeId, overlay_router_ipv4: address, epoch_floor: 1 },
        });
        working.attachments.push(response.resource);
        return response.resource;
      };
      const attachmentA = await ensureAttachment(selection.siteA, selection.nodeA, 2);
      const attachmentB = await ensureAttachment(selection.siteB, selection.nodeB, 3);
      const ensurePrefix = async (siteId: string, cidr: string, parsed: ReturnType<typeof parseCidr>) => {
        if (!parsed || matchingPrefix(working.prefixes, siteId, segment!.metadata.id, cidr)) return;
        const spec = { site_id: siteId, segment_id: segment!.metadata.id, prefix: parsed, source: 'CONFIGURED' };
        const existing = matchingSegmentPrefix(working.prefixes, segment!.metadata.id, cidr);
        if (!existing) {
          const response = await createResource(session.token, tenantId, 'prefixes', { kind: 'PREFIX', spec });
          working.prefixes.push(response.resource);
          return;
        }
        const response = await replaceResource(
          session.token,
          tenantId,
          'prefixes',
          existing.metadata.id,
          existing.metadata.revision,
          { kind: 'PREFIX', spec },
        );
        working.prefixes[working.prefixes.indexOf(existing)] = response.resource;
      };
      await ensurePrefix(selection.siteA, prefixA.trim(), parsedA);
      await ensurePrefix(selection.siteB, prefixB.trim(), parsedB);
      setSelection((value) => ({ ...value, segment: segment!.metadata.id, attachmentA: attachmentA.metadata.id, attachmentB: attachmentB.metadata.id }));
      await load();
      onChanged();
      message.success?.('网络已编排，隧道地址由 Candy 自动分配');
      setCurrent(2);
    } catch (reason) {
      setError(`${reason instanceof Error ? reason.message : '网络编排失败'}。已成功保存的项目会保留，再次提交将从未完成处继续。`);
      await load();
    } finally {
      setSaving(false);
    }
  };

  const orchestrateConnection = async () => {
    if (!tenantId || !networkReady) return;
    if (pathPolicy === 'RELAY_REQUIRED' && !relayId) { setError('请选择一个可用中继'); return; }
    if (pathPolicy !== 'RELAY_REQUIRED' && ![selection.nodeA, selection.nodeB].includes(transportNodeId)) {
      setError('请选择互联两端中具备公网 UDP 端点的节点');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const workingPeers = [...resources.peers];
      const workingPaths = [...resources.paths];
      let peer = workingPeers.find((item) => samePair(item, selection));
      const peerSpec = { segment_id: selection.segment, site_a_id: [selection.siteA, selection.siteB].sort()[0], site_b_id: [selection.siteA, selection.siteB].sort()[1], path_policy: pathPolicy };
      if (!peer) {
        peer = (await createResource(session.token, tenantId, 'peers', { kind: 'PEER', spec: peerSpec })).resource;
        workingPeers.push(peer);
      } else if (specText(peer, 'path_policy') !== pathPolicy) {
        peer = (await replaceResource(session.token, tenantId, 'peers', peer.metadata.id, peer.metadata.revision, { kind: 'PEER', spec: peerSpec })).resource;
      }
      const relay = byId(resources.relays, relayId);
      const pathKind = pathPolicy === 'RELAY_REQUIRED' ? 'RELAY' : 'DIRECT';
      const effectiveTransportNode = pathKind === 'RELAY' ? specText(relay, 'service_node_id') : transportNodeId;
      if (!effectiveTransportNode) throw new Error('线路缺少可用的公网传输节点');
      const upsertPath = async (source: string, destination: string) => {
        const draftSelection = { ...selection, peer: peer!.metadata.id };
        const existing = workingPaths.find((item) => pathDirection(item, source, destination, draftSelection));
        const spec = {
          segment_id: selection.segment,
          peer_id: peer!.metadata.id,
          source_attachment_id: source,
          destination_attachment_id: destination,
          kind: pathKind,
          relay_id: pathKind === 'RELAY' ? relayId : null,
          transport_node_id: effectiveTransportNode,
          priority: 100,
        };
        if (!existing) {
          workingPaths.push((await createResource(session.token, tenantId, 'path-candidates', { kind: 'PATH_CANDIDATE', spec })).resource);
          return;
        }
        if (specText(existing, 'kind') !== pathKind
          || specText(existing, 'relay_id') !== String(spec.relay_id ?? '')
          || specText(existing, 'transport_node_id') !== effectiveTransportNode) {
          await replaceResource(session.token, tenantId, 'path-candidates', existing.metadata.id, existing.metadata.revision, { kind: 'PATH_CANDIDATE', spec });
        }
      };
      await upsertPath(selection.attachmentA, selection.attachmentB);
      await upsertPath(selection.attachmentB, selection.attachmentA);
      setSelection((value) => ({ ...value, peer: peer!.metadata.id }));
      await load();
      await refreshReadiness();
      onChanged();
      message.success?.('双向线路已生成，Cloud 正在发布节点配置');
    } catch (reason) {
      setError(`${reason instanceof Error ? reason.message : '连接编排失败'}。已成功保存的项目会保留，再次提交将从未完成处继续。`);
      await load();
    } finally {
      setSaving(false);
    }
  };

  const stageBody = (() => {
    if (current === 0) return <>
      <div className="endpoint-pair-grid">
        {(['A', 'B'] as const).map((side) => {
          const siteId = selection[`site${side}`];
          const nodeId = selection[`node${side}`];
          const otherSite = selection[`site${side === 'A' ? 'B' : 'A'}`];
          return <section className="endpoint-panel" key={side}>
            <header><span>{side === 'A' ? '第一端' : '第二端'}</span><strong>{resourceName(byId(resources.sites, siteId))}</strong></header>
            <Form layout="vertical">
              <Form.Item label="站点" required><Select value={siteId || undefined} onChange={(value) => updateSite(side, value)} options={options(resources.sites.filter((site) => site.metadata.id !== otherSite))} placeholder="选择业务站点" /></Form.Item>
              <Form.Item label="承载节点" required><Select value={nodeId || undefined} onChange={(value) => setSelection((currentSelection) => ({ ...currentSelection, [`node${side}`]: value, [`attachment${side}`]: '', peer: '' }))} options={options(resources.nodes.filter((node) => specText(node, 'site_id') === siteId))} placeholder={siteId ? '选择已加入节点' : '请先选择站点'} /></Form.Item>
            </Form>
            <Button type="text" icon={<IconPlus />} disabled={!siteId} onClick={() => setEnrollSiteId(siteId)}>为此站点添加节点</Button>
          </section>;
        })}
      </div>
      <Button type="text" icon={<IconPlus />} onClick={() => setSiteEditorVisible(true)}>新建站点</Button>
      {enrollSiteId && <section className="inline-orchestration"><div className="inline-orchestration-heading"><div><strong>添加节点</strong><span>节点完成安全注册后会自动回到当前编排。</span></div><Button type="text" onClick={() => setEnrollSiteId('')}>取消</Button></div><QuickNodeEnrollment session={session} siteId={enrollSiteId} siteName={resourceName(byId(resources.sites, enrollSiteId))} onSaved={() => { setEnrollSiteId(''); void load(); onChanged(); }} /></section>}
    </>;
    if (current === 1) return <Form layout="vertical" className="orchestration-form">
      <Form.Item label="互联网络"><Select allowClear value={selection.segment || undefined} onChange={(value) => setSelection((currentSelection) => ({ ...currentSelection, segment: value ?? '', attachmentA: '', attachmentB: '', peer: '' }))} options={options(resources.segments)} placeholder="选择已有网络，或清空后新建" /></Form.Item>
      {!selection.segment && <div className="form-grid two"><Form.Item label="网络名称" required><Input value={networkName} onChange={setNetworkName} /></Form.Item><Form.Item label="隧道地址池" required><Input className="mono-input" value={overlayCidr} onChange={setOverlayCidr} placeholder="100.64.0.0/24" /></Form.Item></div>}
      <div className="network-prefix-heading"><strong>需要被对端访问的站点内网</strong><span>仅填写需要发布的真实网段。纯云主机、只提供出口或传输能力的站点可以留空。</span></div>
      <div className="form-grid two"><Form.Item label={resourceName(byId(resources.sites, selection.siteA))}><Input className="mono-input" value={prefixA} onChange={setPrefixA} placeholder="例如 192.168.1.0/24（可选）" /></Form.Item><Form.Item label={resourceName(byId(resources.sites, selection.siteB))}><Input className="mono-input" value={prefixB} onChange={setPrefixB} placeholder="例如 10.20.0.0/16（可选）" /></Form.Item></div>
      <div className="orchestration-actions"><Button type="primary" loading={saving} onClick={() => void orchestrateNetwork()}>自动编排网络</Button></div>
    </Form>;
    const directNodes = [byId(resources.nodes, selection.nodeA), byId(resources.nodes, selection.nodeB)].filter(Boolean) as ControlResource[];
    const automaticTransportNode = byId(directNodes, transportNodeId) ?? directNodes[0];
    return <>
      <Form layout="vertical" className="orchestration-form">
        <Form.Item label="连接偏好" required><Radio.Group type="button" value={pathPolicy} onChange={setPathPolicy} options={[{ label: '自动连接', value: 'DIRECT_PREFERRED' }, { label: '仅直连', value: 'DIRECT_ONLY' }, { label: '固定中继', value: 'RELAY_REQUIRED' }]} /></Form.Item>
        {pathPolicy === 'RELAY_REQUIRED'
          ? <Form.Item label="中继节点" required><Select value={relayId || undefined} onChange={setRelayId} options={options(resources.relays)} placeholder="选择可用中继" /></Form.Item>
          : <div className="automatic-connection"><IconCheckCircle /><div><strong>接入点自动选择</strong><span>Candy 将优先使用 {resourceName(automaticTransportNode)} 的可用 UDP 端点；节点不可达时会在激活检查中给出明确原因。</span></div></div>}
        <div className="orchestration-actions"><Button type="primary" loading={saving || activationLoading} onClick={() => void (forwardReady && reverseReady ? refreshReadiness() : orchestrateConnection())}>{forwardReady && reverseReady ? '重新检查状态' : '生成双向线路并发布'}</Button></div>
      </Form>
      <PathStatus forward={forwardReady} reverse={reverseReady} readiness={activationReadiness} loading={activationLoading} error={activationError} onRetry={() => void refreshReadiness()} />
    </>;
  })();

  return <Drawer
    width={1180}
    visible={visible}
    onCancel={onClose}
    className="cloud-drawer setup-drawer"
    footer={null}
    title={<div className="drawer-title"><strong>快速配置</strong><span>只做必要选择，其余由 Candy 自动编排</span></div>}
  >
    {messageHolder}
    <Spin loading={loading && resources.sites.length === 0} block>
      {error && <Alert type="error" showIcon content={error} action={<Button size="small" icon={<IconRefresh />} onClick={() => void load()}>刷新资源</Button>} />}
      <div className="quick-setup-shell">
        <aside className="quick-setup-nav">
          <div className="quick-setup-progress"><div><strong>{doneCount} / 3</strong><span>基础网络</span></div><Progress percent={Math.round(doneCount / 3 * 100)} showText={false} /></div>
          <div className="quick-step-list">{stages.map((stage, index) => <button key={stage.title} type="button" className={`quick-step ${index === current ? 'active' : ''} ${completed[index] ? 'done' : ''}`} disabled={index > 0 && !completed[index - 1]} onClick={() => setCurrent(index)}><span className="quick-step-index">{completed[index] ? <IconCheck /> : index + 1}</span><span><strong className="quick-step-title-desktop">{stage.title}</strong><strong className="quick-step-title-mobile">{stage.shortTitle}</strong></span></button>)}</div>
        </aside>
        <main className="quick-setup-workspace">
          <header className="quick-workspace-heading"><div><span>步骤 {current + 1} / 3</span><Typography.Title heading={4}>{stages[current].title}</Typography.Title><Typography.Text type="secondary">{stages[current].detail}</Typography.Text></div>{completed[current] && <Tag color="green" icon={<IconCheckCircle />}>已完成</Tag>}</header>
          <div className="quick-workspace-body">{stageBody}</div>
          <footer className="quick-workspace-footer">
            <Button icon={<IconLeft />} disabled={current === 0} onClick={() => setCurrent((value) => Math.max(0, value - 1))}>上一步</Button>
            <Space>{current < 2 ? <Button type="primary" icon={<IconRight />} disabled={!completed[current]} onClick={() => setCurrent((value) => value + 1)}>下一步</Button> : <Button type="primary" disabled={!connectionReady} onClick={onClose}>完成</Button>}</Space>
          </footer>
        </main>
      </div>
    </Spin>
    <ResourceEditor visible={siteEditorVisible} definition={definitionByKey.sites} session={session} resource={null} initialSpec={{ name: '', kind: 'EDGE' }} onClose={() => setSiteEditorVisible(false)} onSaved={() => { setSiteEditorVisible(false); void load(); onChanged(); }} />
  </Drawer>;
}

function PathStatus({ forward, reverse, readiness, loading, error, onRetry }: {
  forward: boolean;
  reverse: boolean;
  readiness: RuntimeActivationReadiness | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  const display = activationDisplay(readiness, error, loading);
  return <div className="activation-monitor">
    <div className="path-direction-status"><div className={forward ? 'done' : ''}><span>{forward ? <IconCheck /> : '1'}</span><strong>去程线路</strong><small>第一端 → 第二端</small></div><IconRight /><div className={reverse ? 'done' : ''}><span>{reverse ? <IconCheck /> : '2'}</span><strong>返程线路</strong><small>第二端 → 第一端</small></div></div>
    {readiness?.ready ? <div className="quick-stage-complete"><IconCheckCircle /><div><strong>网络已启用</strong><span>节点已同步并验证当前配置，全双工 TUN 数据面正在运行。</span></div></div> : <Alert
      type={error && !readiness ? 'error' : forward && reverse ? 'warning' : 'info'}
      showIcon
      title={display.label}
      content={display.detail}
      action={error ? <Button size="small" icon={<IconRefresh />} onClick={onRetry}>重试</Button> : undefined}
    />}
    {error && readiness && <Alert className="activation-stale-warning" type="warning" showIcon content={`显示的是最近一次状态；本次刷新失败：${error}`} action={<Button size="small" onClick={onRetry}>重试</Button>} />}
  </div>;
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
        const item = items.find((candidate) => candidate.id === secret.id);
        if (item?.status === 'EXPIRED' || enrollmentExpired(item?.expires_at ?? secret.expires_at)) { setPhase('expired'); return; }
        if (item?.status === 'CONSUMED' && item.device_id && item.device_key_id) {
          setActivation(item);
          setName((value) => value || item.display_name || '新节点');
          setPhase('finish');
        }
      } catch {
        // A transient polling failure must not consume or replace the join credential.
      }
    };
    if (syncExpiry()) return undefined;
    void poll();
    const expiryTimer = window.setTimeout(syncExpiry, Math.max(0, Date.parse(secret.expires_at) - Date.now()));
    const timer = window.setInterval(() => void poll(), 3000);
    return () => { window.clearTimeout(expiryTimer); window.clearInterval(timer); };
  }, [phase, secret, session.token, tenantId]);

  const begin = async () => {
    if (!tenantId || !name.trim() || !siteId || !architecture || !validCloudAddress(cloudAddress)) { message.warning?.('请填写节点名称、处理器架构和有效的 Cloud 地址'); return; }
    setBusy(true);
    try {
      setSecret(await createNodeJoinCode(session.token, tenantId, 600, { site_id: siteId, display_name: name.trim(), platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX', architecture }));
      setPhase('waiting');
    } catch (reason) { message.error?.(reason instanceof Error ? reason.message : '加入文件创建失败'); }
    finally { setBusy(false); }
  };

  const finish = async () => {
    if (!tenantId || !activation?.device_id || !activation.device_key_id) return;
    setBusy(true);
    try {
      await createResource(session.token, tenantId, 'nodes', { kind: 'NODE', spec: { device_id: activation.device_id, device_key_id: activation.device_key_id, site_id: siteId, display_name: name.trim(), platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX', architecture } });
      message.success?.('节点身份已确认并加入站点');
      onSaved();
    } catch (reason) { message.error?.(reason instanceof Error ? reason.message : '节点配置失败'); }
    finally { setBusy(false); }
  };

  return <div className="quick-enrollment">
    {messageHolder}
    {phase === 'details' && <Form layout="vertical"><Alert type="info" showIcon content={`正在为“${siteName}”添加节点。设备主动连接 Cloud，不要求具备公网 IP。`} /><Form.Item label="设备类型" required><Radio.Group type="button" value={platform} onChange={setPlatform} options={[{ label: 'OpenWrt', value: 'OPEN_WRT' }, { label: 'Linux Server', value: 'LINUX_SERVER' }]} /></Form.Item><div className="form-grid two"><Form.Item label="节点名称" required><Input value={name} onChange={setName} placeholder="例如：上海主网关" /></Form.Item><Form.Item label="处理器架构" required><Select value={architecture} onChange={setArchitecture} options={enrollmentArchitectureOptions(platform)} /></Form.Item></div>{!validCloudAddress(cloudAddress) && <Alert type="error" showIcon content="节点加入文件只能由 HTTPS Cloud 生成。" />}<div className="embedded-editor-actions"><Button type="primary" disabled={!validCloudAddress(cloudAddress)} loading={busy} onClick={() => void begin()}>生成加入文件</Button></div></Form>}
    {phase === 'waiting' && secret && <div className="quick-activation"><section className="bootstrap-download"><div><IconDownload /><span><strong>下载自动加入文件</strong><small>已包含 Cloud 地址和一次性注册信息</small></span></div><Button type="primary" icon={<IconDownload />} onClick={() => downloadEnrollmentBootstrap({ secret, cloudAddress })}>下载文件</Button></section><Alert type="info" showIcon content={`等待设备安全注册，加入文件在 ${new Date(secret.expires_at).toLocaleString()} 前有效。`} /></div>}
    {phase === 'expired' && <Alert type="warning" showIcon title="加入文件已过期" content="请重新生成后再执行安装。" action={<Button size="small" onClick={() => { setPhase('details'); setSecret(null); }}>重新生成</Button>} />}
    {phase === 'finish' && activation && <div className="quick-activation"><div className="quick-stage-complete"><IconCheckCircle /><div><strong>设备身份已签发</strong><span>确认后节点会直接加入当前站点。</span></div></div><Button type="primary" loading={busy} onClick={() => void finish()}>完成节点添加</Button></div>}
  </div>;
}
