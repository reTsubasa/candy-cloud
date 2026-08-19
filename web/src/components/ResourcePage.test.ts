import { describe, expect, it } from 'vitest';
import type { ControlResource } from '../types';
import { attachmentTableValues } from '../resource-table';

function attachment(spec: Record<string, unknown>): ControlResource {
  return {
    metadata: {
      schema_version: 1,
      id: 'attachment-id',
      tenant_id: 'tenant-id',
      revision: 1,
      state: 'ACTIVE',
    },
    resource: { kind: 'ATTACHMENT', spec },
  };
}

describe('network attachment table values', () => {
  it('shows the related node name and the bare tunnel IP', () => {
    const resource = attachment({ node_id: 'node-id', overlay_router_ipv4: '100.64.0.2' });

    expect(attachmentTableValues(resource, { 'node-id': '杭州网关' })).toEqual({
      nodeName: '杭州网关',
      tunnelIp: '100.64.0.2',
    });
  });

  it('does not present the tunnel IP as a node name when the node is unavailable', () => {
    const resource = attachment({ node_id: 'missing-node', overlay_router_ipv4: '100.64.0.3' });

    expect(attachmentTableValues(resource)).toEqual({
      nodeName: '—',
      tunnelIp: '100.64.0.3',
    });
  });
});
