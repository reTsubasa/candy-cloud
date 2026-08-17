import type { ResourceDefinition, ResourceSpec } from './types';

export const resourceDefinitions: ResourceDefinition[] = [
  { key: 'sites', label: '站点', collection: 'sites', kind: 'SITE', description: '业务位置和私有云边界', emptyTitle: '尚未创建站点' },
  { key: 'nodes', label: '节点', collection: 'nodes', kind: 'NODE', description: 'OpenWrt 与 Linux 接入节点', emptyTitle: '尚未注册节点' },
  { key: 'segments', label: '网络分段', collection: 'segments', kind: 'SEGMENT', description: '隔离不同业务并承载站点互联', emptyTitle: '尚未创建网络分段' },
  { key: 'attachments', label: '网络接入', collection: 'attachments', kind: 'ATTACHMENT', description: '将已加入节点连接到网络分段', emptyTitle: '尚未配置网络接入' },
  { key: 'prefixes', label: '网段', collection: 'prefixes', kind: 'PREFIX', description: '声明其他站点可以访问的本地网络', emptyTitle: '尚未声明网段' },
  { key: 'peers', label: '站点互联', collection: 'peers', kind: 'PEER', description: '建立站点间双向连接并选择线路', emptyTitle: '尚未创建站点互联' },
  { key: 'egress', label: '出口', collection: 'egresses', kind: 'EGRESS', description: '允许策略选择本站或远端互联网出口', emptyTitle: '尚未配置出口' },
  { key: 'policies', label: '策略', collection: 'service-policies', kind: 'SERVICE_POLICY', description: '按业务条件选择本地或远端出口', emptyTitle: '尚未发布流量策略' },
  { key: 'dns', label: 'DNS', collection: 'dns-intents', kind: 'DNS_INTENT', description: '为站点间服务提供内部域名解析', emptyTitle: '尚未配置内部 DNS' },
  { key: 'relays', label: '中继', collection: 'relays', kind: 'RELAY', description: '在直连不可用时提供可选转发路径', emptyTitle: '当前没有中继节点' },
];

export const pathDefinition: ResourceDefinition = {
  key: 'paths',
  label: '线路配置',
  collection: 'path-candidates',
  kind: 'PATH_CANDIDATE',
  description: '配置站点两个方向使用的直连或中继线路',
  emptyTitle: '当前没有线路配置',
};

export function defaultSpec(kind: string): ResourceSpec {
  const examples: Record<string, Record<string, unknown>> = {
    SITE: { name: '', kind: 'EDGE' },
    NODE: { device_id: '', device_key_id: '', site_id: '', display_name: '', platform: 'OPEN_WRT', architecture: '' },
    SEGMENT: { name: '', overlay_prefix: { network: '100.64.0.0', prefix_len: 24 } },
    ATTACHMENT: { segment_id: '', site_id: '', node_id: '', overlay_router_ipv4: '', epoch_floor: 1 },
    PREFIX: { site_id: '', segment_id: '', prefix: { network: '10.0.0.0', prefix_len: 24 }, source: 'CONFIGURED' },
    PEER: { segment_id: '', site_a_id: '', site_b_id: '', path_policy: 'DIRECT_PREFERRED' },
    PATH_CANDIDATE: { segment_id: '', peer_id: '', source_attachment_id: '', destination_attachment_id: '', kind: 'DIRECT', relay_id: null, transport_node_id: '', priority: 100 },
    EGRESS: { name: '', site_id: '', attachment_id: '', max_sessions: 10000, max_bits_per_second: 1000000000 },
    SERVICE_POLICY: { segment_id: '', generation: 1, rules: [] },
    DNS_INTENT: { segment_id: '', site_id: '', zone: '', records: [] },
    RELAY: { service_node_id: '', name: '', region: '', max_sessions: 10000, max_bits_per_second: 1000000000 },
  };
  return { kind, spec: examples[kind] ?? {} };
}
