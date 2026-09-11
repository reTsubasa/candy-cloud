import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildOperationalTopology, emptyOperationalResources } from '../operational-topology';
import type { ControlResource, RuntimeTelemetry } from '../types';
import { DataplanePhaseList } from './DataplanePhaseList';

const node: ControlResource = {
  metadata: { schema_version: 1, id: 'node', tenant_id: 'tenant', revision: 1, state: 'ACTIVE' },
  resource: { kind: 'NODE', spec: { display_name: 'Linux', site_id: 'site', device_id: 'device', device_key_id: 'key' } },
};
const sample: RuntimeTelemetry = {
  device_id: 'device', device_key_id: 'key', boot_id: 'boot', sequence: 1,
  lifecycle: 'active', dataplane_phase: 'data_plane_active',
  configured_peers: 1, active_peers: 1, required_route_owners: 1, ready_route_owners: 1,
  fail_open_required: false, last_error_code: null,
  rtt_ms: null, jitter_ms: null, packet_loss_ppm: null, rx_bps: null, tx_bps: null,
  reconnects: 0, path_changes: 0, paths: [], local_networks: [], reported_at: '2026-09-11T00:00:00Z',
};
function nodes(age: number, telemetry: RuntimeTelemetry[] = [sample], resource = node) {
  return buildOperationalTopology(
    { ...emptyOperationalResources, nodes: [resource] }, [], {}, '', telemetry, 60,
    Date.parse(sample.reported_at) + age * 1000,
  ).nodes;
}

describe('dataplane phase freshness', () => {
  it('expires historical active phases with the same clock as the topology', () => {
    const { rerender } = render(<DataplanePhaseList nodes={nodes(59)} />);
    expect(screen.getByText('数据面运行中')).toBeInTheDocument();
    rerender(<DataplanePhaseList nodes={nodes(61)} />);
    expect(screen.queryByText('数据面运行中')).not.toBeInTheDocument();
    expect(screen.getByText('离线 · 遥测已过期')).toHaveAttribute('title', expect.stringContaining('历史阶段：数据面运行中'));
    expect(screen.getByText('Linux')).toBeInTheDocument();
  });

  it('does not infer a running phase for missing telemetry', () => {
    render(<DataplanePhaseList nodes={nodes(1, [])} />);
    expect(screen.getByText('未上报遥测')).toBeInTheDocument();
  });

  it('does not infer a running phase from a fresh lifecycle without phase', () => {
    render(<DataplanePhaseList nodes={nodes(1, [{ ...sample, dataplane_phase: undefined }])} />);
    expect(screen.getByText('未上报数据面阶段')).toBeInTheDocument();
  });

  it('does not treat an invalid timestamp as current', () => {
    render(<DataplanePhaseList nodes={nodes(1, [{ ...sample, reported_at: 'invalid' }])} />);
    expect(screen.queryByText('数据面运行中')).not.toBeInTheDocument();
  });

  it('does not treat a future timestamp as a live heartbeat', () => {
    render(<DataplanePhaseList nodes={nodes(1, [{ ...sample, reported_at: '2026-09-12T00:00:00Z' }])} />);
    expect(screen.getByText('未上报遥测')).toBeInTheDocument();
  });

  it('prioritizes de-registration over a fresh historical active sample', () => {
    render(<DataplanePhaseList nodes={nodes(1, [sample], { ...node, metadata: { ...node.metadata, state: 'DELETED' } })} />);
    expect(screen.queryByText('数据面运行中')).not.toBeInTheDocument();
  });
});
