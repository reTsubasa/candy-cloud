import type { ResourceDefinition, ResourceSpec } from './types';

export const resourceDefinitions: ResourceDefinition[] = [
  { key: 'sites', label: '站点', collection: 'sites', kind: 'SITE', description: '业务位置和私有云边界', emptyTitle: '尚未创建站点' },
  { key: 'nodes', label: '节点', collection: 'nodes', kind: 'NODE', description: 'OpenWrt 与 Linux 接入节点', emptyTitle: '尚未注册节点' },
  { key: 'segments', label: '网络分段', collection: 'segments', kind: 'SEGMENT', description: '租户隔离的覆盖网络', emptyTitle: '尚未创建网络分段' },
  { key: 'prefixes', label: '网段', collection: 'prefixes', kind: 'PREFIX', description: '站点可达 IPv4 前缀', emptyTitle: '尚未声明网段' },
  { key: 'peers', label: '对等与路径', collection: 'peers', kind: 'PEER', description: '站点互联关系和选路策略', emptyTitle: '尚未创建对等关系' },
  { key: 'egress', label: '出口', collection: 'egresses', kind: 'EGRESS', description: '站点 Candy 出口能力', emptyTitle: '尚未配置出口' },
  { key: 'policies', label: '策略', collection: 'service-policies', kind: 'SERVICE_POLICY', description: '站点间与出口流量意图', emptyTitle: '尚未发布服务策略' },
  { key: 'dns', label: 'DNS', collection: 'dns-intents', kind: 'DNS_INTENT', description: '内部区域和路由绑定记录', emptyTitle: '尚未配置 DNS 意图' },
  { key: 'relays', label: '中继', collection: 'relays', kind: 'RELAY', description: '仅在需要时参与路径调度', emptyTitle: '当前没有中继资源' },
];

export const pathDefinition: ResourceDefinition = {
  key: 'paths',
  label: '路径候选',
  collection: 'path-candidates',
  kind: 'PATH_CANDIDATE',
  description: '直接与中继候选路径',
  emptyTitle: '尚未生成路径候选',
};

export function defaultSpec(kind: string): ResourceSpec {
  const examples: Record<string, Record<string, unknown>> = {
    SITE: { name: '', kind: 'EDGE' },
    NODE: { device_id: '', device_key_id: '', site_id: '', display_name: '', platform: 'OPEN_WRT', architecture: '' },
    SEGMENT: { name: '', overlay_prefix: { network: '100.64.0.0', prefix_len: 24 } },
    PREFIX: { site_id: '', segment_id: '', prefix: { network: '10.0.0.0', prefix_len: 24 }, source: 'CONFIGURED' },
    PEER: { segment_id: '', site_a_id: '', site_b_id: '', path_policy: 'DIRECT_PREFERRED' },
    PATH_CANDIDATE: { segment_id: '', peer_id: '', source_attachment_id: '', destination_attachment_id: '', kind: 'DIRECT', relay_id: null, endpoint: '', priority: 100 },
    EGRESS: { name: '', site_id: '', attachment_id: '', max_sessions: 10000, max_bits_per_second: 1000000000 },
    SERVICE_POLICY: { segment_id: '', generation: 1, rules: [] },
    DNS_INTENT: { segment_id: '', site_id: '', zone: '', records: [] },
    RELAY: { service_node_id: '', name: '', region: '', max_sessions: 10000, max_bits_per_second: 1000000000 },
  };
  return { kind, spec: examples[kind] ?? {} };
}
