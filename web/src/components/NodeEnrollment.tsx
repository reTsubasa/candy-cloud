import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Drawer, Empty, Form, Input, Message, Modal, Radio, Select, Space, Spin, Table, Tag, Tooltip, Typography } from '@arco-design/web-react';
import { IconArrowLeft, IconCheckCircle, IconCopy, IconDelete, IconDesktop, IconDownload, IconPlus, IconRefresh, IconRight } from '@arco-design/web-react/icon';
import {
  createNodeJoinCode,
  createResource,
  listNodeJoinCodes,
  listResources,
  revokeNodeJoinCode,
} from '../api';
import type { ControlResource, EnrollmentActivation, EnrollmentActivationSecret, Session } from '../types';
import { buildEnrollmentInstallCommand, downloadEnrollmentBootstrap, validCloudAddress } from '../enrollment-bootstrap';
import { compatibleEnrollmentArchitecture, defaultEnrollmentArchitecture, enrollmentArchitectureOptions, type EnrollmentPlatform } from '../enrollment-platform';

type Props = {
  session: Session;
  onBack: () => void;
  onCreateSite: () => void;
  onFinished: () => void;
};

const statusLabel: Record<EnrollmentActivation['status'], string> = {
  ACTIVE: '等待设备', RESERVED: '正在注册', CONSUMED: '身份已签发', REVOKED: '已撤销', EXPIRED: '已过期',
};

function statusColor(status: EnrollmentActivation['status']): string {
  if (status === 'ACTIVE') return 'arcoblue';
  if (status === 'RESERVED') return 'orange';
  if (status === 'CONSUMED') return 'green';
  return 'gray';
}

function resourceName(item: ControlResource): string {
  return String(item.resource.spec.name ?? item.resource.spec.display_name ?? item.metadata.id);
}

export function NodeEnrollment({ session, onBack, onCreateSite, onFinished }: Props) {
  const [message, messageHolder] = Message.useMessage();
  const tenantId = session.claims.tenant_id;
  const [items, setItems] = useState<EnrollmentActivation[]>([]);
  const [sites, setSites] = useState<ControlResource[]>([]);
  const [nodes, setNodes] = useState<ControlResource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [step, setStep] = useState(0);
  const [secret, setSecret] = useState<EnrollmentActivationSecret | null>(null);
  const [activation, setActivation] = useState<EnrollmentActivation | null>(null);
  const [creating, setCreating] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<EnrollmentActivation | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [platform, setPlatform] = useState<EnrollmentPlatform>('LINUX_SERVER');
  const [siteId, setSiteId] = useState('');
  const [nodeName, setNodeName] = useState('');
  const [architecture, setArchitecture] = useState(defaultEnrollmentArchitecture('LINUX_SERVER'));
  const [installationState, setInstallationState] = useState<'new' | 'installed'>('new');
  const cloudAddress = window.location.origin;

  const configuredDeviceIds = useMemo(() => new Set(nodes.map((item) => String(item.resource.spec.device_id))), [nodes]);

  const load = useCallback(async (quiet = false) => {
    if (!tenantId) return;
    if (!quiet) setLoading(true);
    setError(null);
    try {
      const [activations, sitePage, nodePage] = await Promise.all([
        listNodeJoinCodes(session.token, tenantId),
        listResources(session.token, tenantId, 'sites'),
        listResources(session.token, tenantId, 'nodes'),
      ]);
      setItems(activations);
      setSites(sitePage.items);
      setNodes(nodePage.items);
      if (secret) {
        const current = activations.find((item) => item.id === secret.id);
        if (current) {
          setActivation(current);
          if (current.status === 'CONSUMED' && current.device_id && current.device_key_id) {
            setNodeName((value) => value || current.display_name || '新节点');
            setStep(2);
          }
        }
      }
    } catch (reason) {
      if (!quiet) setError(reason instanceof Error ? reason.message : '节点加入状态加载失败');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [secret, session.token, tenantId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { setArchitecture((value) => compatibleEnrollmentArchitecture(platform, value)); }, [platform]);
  useEffect(() => {
    if (!drawerVisible || step !== 1 || !secret) return undefined;
    const timer = window.setInterval(() => void load(true), 3000);
    return () => window.clearInterval(timer);
  }, [drawerVisible, load, secret, step]);

  const resetWizard = () => {
    setStep(0);
    setSecret(null);
    setActivation(null);
    setPlatform('LINUX_SERVER');
    setSiteId(sites.length === 1 ? sites[0].metadata.id : '');
    setNodeName('');
    setArchitecture(defaultEnrollmentArchitecture('LINUX_SERVER'));
    setInstallationState('new');
    setDrawerVisible(true);
  };

  const create = async () => {
    if (!tenantId) return;
    if (!siteId || !nodeName.trim() || !architecture || !validCloudAddress(cloudAddress)) {
      message.warning?.('请先完成设备类型、节点名称、所属站点和有效的 Cloud 地址');
      return;
    }
    setCreating(true);
    try {
      const created = await createNodeJoinCode(session.token, tenantId, 600, {
        site_id: siteId,
        display_name: nodeName.trim(),
        platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX',
        architecture,
      });
      setSecret(created);
      setActivation(null);
      setStep(1);
      await load(true);
    } catch (reason) {
      message.error?.(reason instanceof Error ? reason.message : '加入码创建失败');
    } finally {
      setCreating(false);
    }
  };

  const resume = (item: EnrollmentActivation) => {
    setSecret(null);
    setActivation(item);
    setStep(2);
    setPlatform(item.requested_platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX_SERVER');
    setSiteId(item.site_id ?? (sites.length === 1 ? sites[0].metadata.id : ''));
    setNodeName(item.requested_display_name ?? item.display_name ?? '新节点');
    setArchitecture(compatibleEnrollmentArchitecture(item.requested_platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX_SERVER', item.requested_architecture ?? ''));
    setDrawerVisible(true);
  };

  const finish = async () => {
    if (!tenantId || !activation?.device_id || !activation.device_key_id) return;
    if (!siteId || !nodeName.trim() || !architecture) {
      message.warning?.('请填写节点名称、所属站点和处理器架构');
      return;
    }
    setFinishing(true);
    try {
      await createResource(session.token, tenantId, 'nodes', {
        kind: 'NODE',
        spec: {
          device_id: activation.device_id,
          device_key_id: activation.device_key_id,
          site_id: siteId,
          display_name: nodeName.trim(),
          platform: platform === 'OPEN_WRT' ? 'OPEN_WRT' : 'LINUX',
          architecture,
        },
      });
      message.success?.('节点已加入 Cloud 并完成站点归属');
      setDrawerVisible(false);
      await load(true);
      onFinished();
    } catch (reason) {
      message.error?.(reason instanceof Error ? reason.message : '节点配置失败');
    } finally {
      setFinishing(false);
    }
  };

  const revoke = async () => {
    if (!tenantId || !revokeTarget) return;
    setRevoking(true);
    try {
      await revokeNodeJoinCode(session.token, tenantId, revokeTarget.id);
      setRevokeTarget(null);
      message.success?.('加入请求已撤销');
      await load();
    } catch (reason) {
      message.error?.(reason instanceof Error ? reason.message : '撤销失败');
    } finally {
      setRevoking(false);
    }
  };

  const copyInstallCommand = async () => {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(buildEnrollmentInstallCommand({ secret, cloudAddress }));
      message.success?.('安装命令已复制，有效期与本次节点授权一致');
    } catch {
      message.error?.('复制失败，请手动选择命令文本');
    }
  };

  const activeCount = items.filter((item) => ['ACTIVE', 'RESERVED'].includes(item.status)).length;
  const pendingConfiguration = items.filter((item) => item.status === 'CONSUMED' && item.device_id && !configuredDeviceIds.has(item.device_id)).length;
  const actionableItems = items.filter((item) => ['ACTIVE', 'RESERVED'].includes(item.status) || (item.status === 'CONSUMED' && item.device_id && !configuredDeviceIds.has(item.device_id)));

  const columns = [
    {
      title: '设备',
      render: (_: unknown, item: EnrollmentActivation) => (
        <div className="enrollment-device"><strong>{item.display_name ?? '等待设备连接'}</strong><span>{item.status === 'CONSUMED' ? '设备身份已安全签发' : `创建于 ${new Date(item.created_at).toLocaleString()}`}</span></div>
      ),
    },
    { title: '状态', width: 126, render: (_: unknown, item: EnrollmentActivation) => <Tag color={statusColor(item.status)}>{configuredDeviceIds.has(item.device_id ?? '') ? '已配置' : statusLabel[item.status]}</Tag> },
    { title: '有效期', width: 180, render: (_: unknown, item: EnrollmentActivation) => new Date(item.expires_at).toLocaleString() },
    {
      title: '', width: 128, align: 'right' as const,
      render: (_: unknown, item: EnrollmentActivation) => {
        if (item.status === 'CONSUMED' && item.device_id && item.device_key_id && !configuredDeviceIds.has(item.device_id)) {
          return <Button type="text" size="small" icon={<IconRight />} onClick={() => resume(item)}>完成配置</Button>;
        }
        if (['ACTIVE', 'RESERVED'].includes(item.status)) {
          return <Tooltip content="撤销本次加入"><Button type="text" status="danger" icon={<IconDelete />} aria-label="撤销" onClick={() => setRevokeTarget(item)} /></Tooltip>;
        }
        return null;
      },
    },
  ];

  return (
    <section className="enrollment-section">
      {messageHolder}
      <button type="button" className="page-back" onClick={onBack}><IconArrowLeft /> 节点</button>
      <header className="page-header">
        <div><Typography.Title heading={4}>添加节点</Typography.Title><Typography.Text type="secondary">在设备上执行一次安全加入，即可获得 Cloud 身份并归属到站点</Typography.Text></div>
        <Button icon={<IconRefresh />} loading={loading} onClick={() => void load()}>刷新</Button>
      </header>
      <div className="enrollment-guide concise">
        <div><span>1</span><strong>填写节点信息</strong></div>
        <IconRight />
        <div><span>2</span><strong>下载并运行加入文件</strong></div>
        <IconRight />
        <div><span>3</span><strong>自动确认设备上线</strong></div>
      </div>
      {error && <Alert type="error" showIcon content={error} action={<Button size="small" onClick={() => void load()}>重试</Button>} />}
      <section className="enrollment-start-panel">
        <div><IconDesktop /><span><Typography.Title heading={5}>添加一台 Candy 节点</Typography.Title><Typography.Text type="secondary">设备从内网主动连接 Cloud，不要求公网 IP。加入文件已包含一次性注册信息。</Typography.Text></span></div>
        <Button type="primary" size="large" icon={<IconPlus />} onClick={resetWizard}>开始添加</Button>
      </section>
      {actionableItems.length > 0 && <><div className="toolbar-row enrollment-toolbar"><div><Typography.Text bold>待完成任务</Typography.Text><Typography.Text type="secondary">只显示仍可继续操作的节点加入</Typography.Text></div><Typography.Text type="secondary">{activeCount} 个等待设备 · {pendingConfiguration} 个待确认</Typography.Text></div>
        <div className="table-surface enrollment-table compact">
          <Table rowKey="id" loading={loading} data={actionableItems} columns={columns} pagination={false} scroll={{ x: 720 }} />
        </div></>}
      {actionableItems.length === 0 && !loading && <Empty className="enrollment-empty" description="当前没有待完成的节点任务" />}
      <Drawer
        width={680}
        visible={drawerVisible}
        onCancel={() => setDrawerVisible(false)}
        className="cloud-drawer resource-drawer enrollment-drawer"
        title={<div className="drawer-title"><strong>添加节点</strong><span>{step === 0 ? '先确定设备角色与归属' : step === 1 ? '在目标设备上完成安全加入' : '确认设备身份并完成配置'}</span></div>}
        footer={step === 0
          ? <Space><Button onClick={() => setDrawerVisible(false)}>取消</Button><Button type="primary" disabled={!validCloudAddress(cloudAddress)} loading={creating} onClick={() => void create()}>生成加入文件</Button></Space>
          : step === 1
            ? <Space><Button onClick={() => setDrawerVisible(false)}>稍后继续</Button><Button type="primary" icon={<IconRefresh />} onClick={() => void load(true)}>检查设备状态</Button></Space>
            : <Space><Button onClick={() => setDrawerVisible(false)}>稍后继续</Button><Button type="primary" loading={finishing} onClick={() => void finish()}>完成添加</Button></Space>}
      >
        {step === 0 && <Form layout="vertical" className="enrollment-form">
          <Form.Item label="设备类型" required>
            <Radio.Group className="device-type-options" value={platform} onChange={setPlatform}>
              <Radio value="OPEN_WRT"><span><IconDesktop /><strong>OpenWrt</strong><small>路由器、家庭网关、分支网关</small></span></Radio>
              <Radio value="LINUX_SERVER"><span><IconDesktop /><strong>Linux Server</strong><small>云服务器、数据中心、私有云节点</small></span></Radio>
            </Radio.Group>
            <Typography.Text type="secondary" className="field-help">设备由内向外连接 Cloud，因此无论是否有公网 IP，加入方式都相同。</Typography.Text>
          </Form.Item>
          <div className="form-grid two"><Form.Item label="节点名称" required><Input value={nodeName} onChange={setNodeName} placeholder="例如：东京云服务器（47.83.1.189）" /></Form.Item><Form.Item label="所属站点" required><Select value={siteId || undefined} onChange={setSiteId} placeholder="选择节点所在站点" options={sites.map((item) => ({ label: resourceName(item), value: item.metadata.id }))} /></Form.Item></div>
          {sites.length === 0 && <Alert type="warning" showIcon content="需要先创建节点所属的站点。" action={<Button size="small" onClick={onCreateSite}>创建站点</Button>} />}
          <Form.Item label="处理器架构" required><Select value={architecture} onChange={setArchitecture} options={enrollmentArchitectureOptions(platform)} /></Form.Item>
          {!validCloudAddress(cloudAddress) && <Alert type="error" showIcon content="节点加入文件只能由 HTTPS Cloud 生成。请先通过 HTTPS 地址访问当前管理端。" />}
        </Form>}
        {step === 1 && secret && <div className="activation-content">
          <div className="activation-status"><Spin dot /><div><strong>等待设备完成注册</strong><span>页面每 3 秒自动检查一次，加入文件有效期至 {new Date(secret.expires_at).toLocaleString()}</span></div><Tag color="arcoblue">实时等待</Tag></div>
          {platform === 'LINUX_SERVER' && <Radio.Group type="button" className="installation-state-switch" value={installationState} onChange={setInstallationState}>
            <Radio value="new">尚未安装 Candy</Radio>
            <Radio value="installed">已安装 Candy</Radio>
          </Radio.Group>}
          {platform === 'LINUX_SERVER' && installationState === 'new' && <section className="bootstrap-command-panel">
            <div className="bootstrap-command-heading"><span><strong>在节点上执行一条命令</strong><small>自动识别架构，下载并校验 Candy，完成安装后使用本次授权注册</small></span><Button icon={<IconCopy />} onClick={() => void copyInstallCommand()}>复制命令</Button></div>
            <pre><code>{buildEnrollmentInstallCommand({ secret, cloudAddress })}</code></pre>
            <Typography.Text type="secondary">安装失败不会启用 SD-WAN，也不会修改节点现有的路由、DNS 或转发规则。</Typography.Text>
          </section>}
          {(platform === 'OPEN_WRT' || installationState === 'installed') && <>
            <section className="bootstrap-download primary">
              <div><IconDownload /><span><strong>下载自动加入文件</strong><small>文件已包含 Cloud 地址和一次性注册信息，无需复制加入码</small></span></div>
              <Button type="primary" size="large" icon={<IconDownload />} onClick={() => downloadEnrollmentBootstrap({ secret, cloudAddress })}>下载文件</Button>
            </section>
            <div className="bootstrap-existing-note">{platform === 'LINUX_SERVER' ? <>将文件传到节点后执行 <code>sudo candy-server bootstrap candy-node-bootstrap.json</code></> : <>在 OpenWrt 的 Candy → SD-WAN 中导入该文件</>}</div>
          </>}
          <Alert type="info" showIcon content="运行成功后，加入文件和临时凭据会自动删除；页面会自动确认设备上线。" />
          {window.location.hostname === 'localhost' && <Alert type="warning" showIcon content="本地 TLS 地址只适合本机验证；远程设备必须能够解析并访问加入文件中的 Cloud 地址。" />}
        </div>}
        {step === 2 && activation && <div className="activation-content">
          <div className="activation-status completed"><IconCheckCircle /><div><strong>设备身份注册完成</strong><span>{activation.display_name ?? 'Candy 节点'} 已通过一次性凭据和密钥证明</span></div><Tag color="green">可信设备</Tag></div>
          <Alert type="info" showIcon content="最后确认节点名称和所属站点。完成后，这台设备会出现在节点列表并参与后续网络编排。" />
          <Form layout="vertical" className="enrollment-form">
            <div className="form-grid two"><Form.Item label="节点名称" required><Input value={nodeName} onChange={setNodeName} /></Form.Item><Form.Item label="所属站点" required><Select value={siteId || undefined} onChange={setSiteId} placeholder="选择站点" options={sites.map((item) => ({ label: resourceName(item), value: item.metadata.id }))} /></Form.Item></div>
            <div className="form-grid two"><Form.Item label="设备类型" required><Radio.Group type="button" value={platform} onChange={setPlatform} options={[{ label: 'OpenWrt', value: 'OPEN_WRT' }, { label: 'Linux Server', value: 'LINUX_SERVER' }]} /></Form.Item><Form.Item label="处理器架构" required><Select value={architecture} onChange={setArchitecture} options={enrollmentArchitectureOptions(platform)} /></Form.Item></div>
          </Form>
        </div>}
      </Drawer>
      <Modal visible={revokeTarget !== null} title="撤销本次节点加入？" okText="确认撤销" cancelText="取消" okButtonProps={{ status: 'danger' }} confirmLoading={revoking} onCancel={() => { if (!revoking) setRevokeTarget(null); }} onOk={() => void revoke()} unmountOnExit>
        <Typography.Paragraph>尚未完成加入的设备将无法继续使用这个凭据；已经加入的其他节点不会受到影响。</Typography.Paragraph>
      </Modal>
    </section>
  );
}
