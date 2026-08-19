import type { ControlResource } from './types';

export function attachmentTableValues(
  resource: ControlResource,
  nodeNames: Record<string, string> = {},
): { nodeName: string; tunnelIp: string } {
  const spec = resource.resource.spec;
  const nodeName = nodeNames[String(spec.node_id)]?.trim();
  const tunnelIp = typeof spec.overlay_router_ipv4 === 'string'
    ? spec.overlay_router_ipv4.trim()
    : '';

  return {
    nodeName: nodeName || '—',
    tunnelIp: tunnelIp || '—',
  };
}
