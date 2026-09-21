import { describe, expect, it } from 'vitest';
import type { RuntimeTelemetry } from './types';
import { dataplanePhaseLabel, pathHealth, runtimeDataPlaneReady, runtimeAttention, streamHealth } from './runtime-observability';

const base = (overrides: Partial<RuntimeTelemetry> = {}): RuntimeTelemetry => ({
  device_id: 'device', device_key_id: 'key', boot_id: 'boot', sequence: 1,
  lifecycle: 'active', configured_peers: 1, active_peers: 1,
  required_route_owners: 1, ready_route_owners: 1, fail_open_required: false,
  last_error_code: null, rtt_ms: 10, jitter_ms: 1, packet_loss_ppm: 0,
  rx_bps: 1, tx_bps: 1, reconnects: 0, path_changes: 0,
  paths: [], local_networks: [], reported_at: new Date().toISOString(), ...overrides,
});

describe('runtime observability contract', () => {
  it('uses the Runtime data-plane readiness contract, not lifecycle alone', () => {
    expect(runtimeDataPlaneReady(base())).toBe(true);
    expect(runtimeDataPlaneReady(base({ lifecycle: 'active', ready_route_owners: 0 }))).toBe(false);
    expect(runtimeDataPlaneReady(base({ last_error_code: 'tun_route_probe_timeout' }))).toBe(false);
  });

  it('treats route drift as a data-plane fault until Runtime reports recovery', () => {
    const diagnostics = {
      schema_version: 2 as const, integrity: 'drifted' as const, expected_snapshot_sha256: 'a', observed_snapshot_sha256: 'b',
      expected_routes: 1, observed_routes: 1, orphaned_routes: 0, reconcile_attempts: 1, reconcile_successes: 0,
      last_checked_at_unix: 1, last_reconciled_at_unix: 1, last_recovered_at_unix: null, last_recovery_duration_ms: null,
      last_error_code: null, probe_state: 'pending' as const, probe_targets: 1, probe_successes: 0, probe_rtt_ms: null,
      probe_checked_at_unix: null, active_issues: [], last_recovered_issues: [],
    };
    expect(runtimeDataPlaneReady(base({ route_diagnostics: diagnostics }))).toBe(false);
    expect(runtimeAttention(base({ route_diagnostics: diagnostics }))).toBe('route_snapshot_mismatch');
    expect(runtimeDataPlaneReady(base({ route_diagnostics: { ...diagnostics, integrity: 'reconciling' } }))).toBe(true);
  });

  it('surfaces route/probe evidence as the attention reason', () => {
    expect(runtimeAttention(base({ failed_route_prefixes: ['10.0.0.0/24'] }))).toContain('10.0.0.0/24');
    const probeFailure = base({ route_diagnostics: {
      schema_version: 2, integrity: 'consistent', expected_snapshot_sha256: 'a', observed_snapshot_sha256: 'a',
      expected_routes: 1, observed_routes: 1, orphaned_routes: 0, reconcile_attempts: 1, reconcile_successes: 1,
      last_checked_at_unix: 1, last_reconciled_at_unix: 1, last_recovered_at_unix: null, last_recovery_duration_ms: null,
      last_error_code: 'probe_timeout', probe_state: 'failed', probe_targets: 1, probe_successes: 0, probe_rtt_ms: null,
      probe_checked_at_unix: 1, active_issues: [], last_recovered_issues: [],
    } });
    expect(runtimeAttention(probeFailure)).toBe('probe_timeout');
    expect(runtimeDataPlaneReady(probeFailure)).toBe(false);
  });

  it('classifies stream pressure and stream faults consistently', () => {
    const stream = { slot: 0, stream_id: 1, state: 'ready', generation: 1, tx_packets: 0, rx_packets: 0, tx_bytes: 0, rx_bytes: 0, tx_frames: 0, rx_frames: 0, active_flows: 0, queue_depth: 90, queue_limit: 100, queue_peak: 90, last_ack_seq: null, ack_rtt_ms: null, rx_bps: null, tx_bps: null, reset_count: 0, decode_errors: 0, high_watermark_hits: 1, low_watermark_hits: 0, blocked_ms: 2, send_window_bytes: 10, last_tx_monotonic_ms: null, last_rx_monotonic_ms: null, last_error_code: null };
    expect(streamHealth(stream)).toBe('backpressured');
    expect(streamHealth({ ...stream, last_error_code: 'peer_stream_write_failed' })).toBe('fault');
    expect(pathHealth({ peer_attachment_id: 'peer', candidate_id: null, path_kind: 'direct', transport: 'quic_udp', connection_epoch: 1, rtt_ms: 1, jitter_ms: 1, packet_loss_ppm: 0, rx_bps: 1, tx_bps: 1, reconnects: 0, path_changes: 0, streams: [stream] })).toBe('backpressured');
    expect(pathHealth({ peer_attachment_id: 'peer', candidate_id: null, path_kind: 'direct', transport: 'quic_udp', connection_epoch: 1, rtt_ms: 1, jitter_ms: 1, packet_loss_ppm: 0, rx_bps: 1, tx_bps: 1, reconnects: 0, path_changes: 0, streams: [{ ...stream, last_error_code: 'peer_stream_closed' }] })).toBe('fault');
  });

  it('does not hide unknown wire phases', () => {
    expect(dataplanePhaseLabel('future_phase')).toBe('未知阶段（future_phase）');
  });
});
