import type { ControlResource, RuntimeActivationReadiness } from './types';

export type QuickSetupSelection = {
  siteA: string;
  siteB: string;
  nodeA: string;
  nodeB: string;
  segment: string;
  attachmentA: string;
  attachmentB: string;
  peer: string;
};

function specText(item: ControlResource | undefined, key: string): string {
  return String(item?.resource.spec[key] ?? '');
}

function prefixText(item: ControlResource | undefined): string {
  const prefix = item?.resource.spec.prefix as { network?: string; prefix_len?: number } | undefined;
  return prefix?.network && prefix.prefix_len ? `${prefix.network}/${prefix.prefix_len}` : '';
}

export function samePair(peer: ControlResource, selection: QuickSetupSelection): boolean {
  const a = specText(peer, 'site_a_id');
  const b = specText(peer, 'site_b_id');
  return specText(peer, 'segment_id') === selection.segment
    && ((a === selection.siteA && b === selection.siteB) || (a === selection.siteB && b === selection.siteA));
}

export function pathDirection(
  path: ControlResource,
  source: string,
  destination: string,
  selection: QuickSetupSelection,
): boolean {
  return specText(path, 'segment_id') === selection.segment
    && specText(path, 'peer_id') === selection.peer
    && specText(path, 'source_attachment_id') === source
    && specText(path, 'destination_attachment_id') === destination;
}

export function matchingPrefix(
  items: ControlResource[],
  siteId: string,
  segmentId: string,
  cidr: string,
): ControlResource | undefined {
  return items.find((item) => specText(item, 'site_id') === siteId
    && specText(item, 'segment_id') === segmentId
    && prefixText(item) === cidr);
}

export function nextOverlayAddress(
  segment: ControlResource,
  attachments: ControlResource[],
  preferredOffset: number,
): string {
  const prefix = segment.resource.spec.overlay_prefix as { network?: string; prefix_len?: number } | undefined;
  const octets = String(prefix?.network ?? '').split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return '';
  const base = octets.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
  const used = new Set(attachments.map((item) => specText(item, 'overlay_router_ipv4')));
  for (let offset = preferredOffset; offset < preferredOffset + 128; offset += 1) {
    const value = (base + offset) >>> 0;
    const candidate = [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
    if (!used.has(candidate)) return candidate;
  }
  return '';
}

export function activationMessage(readiness: RuntimeActivationReadiness | null): string {
  if (!readiness) return '尚未读取 Cloud 激活状态。';
  if (readiness.ready) return 'Cloud 配置已完整，等待节点同步后会自动启用。';
  const messages: string[] = [];
  if (readiness.candidate_count === 0) messages.push('尚未生成双向线路');
  if (readiness.reason_codes.includes('service_not_enabled')) messages.push('当前租户的 SD-WAN 服务尚未开通');
  if (readiness.reason_codes.includes('remote_egress_unsupported')) messages.push('当前策略包含远端出口，但数据面出口契约尚未实现；请先移除该规则或使用站点互联前缀验证线路');
  if (readiness.reason_codes.includes('node_apply_failed')) messages.push(String(readiness.failed_apply_count || 1) + ' 个节点应用配置失败：' + ((readiness.apply_error_codes ?? []).join('、') || '请查看运行日志'));
  if (readiness.reason_codes.includes('node_offline')) messages.push(`有 ${readiness.missing_transport_count} 条线路等待公网节点发布 UDP 端点`);
  if (readiness.reason_codes.includes('config_pending')) messages.push('Cloud 正在生成并签名节点配置');
  if (readiness.reason_codes.includes('node_apply_pending')) messages.push('配置已发布，等待 ' + String(readiness.pending_apply_count || 1) + ' 个节点确认生效');
  return messages.join('；') || '等待 Cloud 完成配置发布。';
}
