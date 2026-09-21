import { Alert, Descriptions, Space, Table, Tag, Typography } from '@arco-design/web-react';
import type { OperationalNode } from '../operational-topology';
import { dataplanePhaseLabel, pathHealth, runtimeDataPlaneReady, streamHealth } from '../runtime-observability';

function timestamp(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function number(value: number | null | undefined): string {
  return value == null ? '—' : value.toLocaleString();
}

function tone(state: string): 'green' | 'orange' | 'red' | 'gray' {
  if (state === 'ready' || state === 'active' || state === 'succeeded') return 'green';
  if (state === 'starting' || state === 'backpressured' || state === 'pending' || state === 'reconciling') return 'orange';
  if (state === 'fault' || state === 'failed' || state === 'degraded') return 'red';
  return 'gray';
}

const lifecycleLabel: Record<string, string> = {
  starting: '启动中', active: '运行中', degraded: '已降级', fail_open: '故障开放', stopped: '已停止', unknown: '未知',
};

const integrityLabel: Record<string, string> = {
  consistent: '一致', drifted: '发现漂移', reconciling: '自愈中', failed: '自愈失败',
};

const probeLabel: Record<string, string> = {
  unreported: '未上报', pending: '等待探测', succeeded: '通过', failed: '失败',
};

const stateLabel: Record<string, string> = {
  ready: '就绪', starting: '建立中', backpressured: '背压', fault: '故障',
  active: '运行中', succeeded: '通过', pending: '等待', reconciling: '自愈中',
};

export function RuntimeTelemetryPanel({ node }: { node: OperationalNode }) {
  const telemetry = node.telemetry;
  if (!telemetry) return <Alert type="warning" showIcon content="节点尚未上报 Runtime 遥测，无法确认当前数据面状态。" />;
  const ready = runtimeDataPlaneReady(telemetry);
  const diagnostics = telemetry.route_diagnostics;
  const paths = telemetry.paths ?? [];
  const streams = paths.flatMap((path) => (path.streams ?? []).map((stream) => ({ ...stream, pathId: path.peer_attachment_id })));
  const routeIssues = diagnostics ? [
    ...diagnostics.active_issues.map((issue) => ({ ...issue, evidenceState: 'active' as const })),
    ...diagnostics.last_recovered_issues.map((issue) => ({ ...issue, evidenceState: 'recovered' as const })),
  ] : [];
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    {node.telemetryState !== 'online' && <Alert type="warning" showIcon content={`以下是 ${timestamp(telemetry.reported_at)} 的历史快照，当前遥测${node.telemetryState === 'stale' ? '已过期' : '尚未在线'}，不能代表现场实时状态。`} />}
    {node.telemetryState === 'online' && !ready && <Alert type={node.status.tone === 'orange' ? 'warning' : 'error'} showIcon content={node.status.detail} />}
    <Descriptions column={2} data={[
      { label: 'Runtime 状态', value: <Tag color={tone(telemetry.lifecycle)}>{lifecycleLabel[telemetry.lifecycle] ?? telemetry.lifecycle}</Tag> },
      { label: '数据面阶段', value: <Tag color={tone(telemetry.dataplane_phase ?? '')}>{dataplanePhaseLabel(telemetry.dataplane_phase)}</Tag> },
      { label: '最后上报', value: timestamp(telemetry.reported_at) },
      { label: 'Peer', value: `${number(telemetry.active_peers)} / ${number(telemetry.configured_peers)} 活跃` },
      { label: '路由 owner', value: `${number(telemetry.ready_route_owners)} / ${number(telemetry.required_route_owners)} 就绪` },
      { label: '隧道 / 策略代际', value: `${number(telemetry.tunnel_generation)} / ${number(telemetry.policy_generation ?? telemetry.runtime_generation)}` },
      { label: '重连 / 路径变更', value: `${number(telemetry.reconnects)} / ${number(telemetry.path_changes)}` },
      { label: '最后错误', value: telemetry.last_error_code ? <Typography.Text type="error">{telemetry.last_error_code}</Typography.Text> : '无' },
    ]} />
    {diagnostics && <Descriptions column={2} title="路由与真实包探测" data={[
      { label: '路由完整性', value: <Tag color={tone(diagnostics.integrity)}>{integrityLabel[diagnostics.integrity] ?? diagnostics.integrity}</Tag> },
      { label: '声明 / 实测 / 孤儿', value: `${diagnostics.expected_routes} / ${diagnostics.observed_routes} / ${diagnostics.orphaned_routes}` },
      { label: '自愈', value: `${diagnostics.reconcile_successes} / ${diagnostics.reconcile_attempts} 成功` },
      { label: '真实包探测', value: <Tag color={tone(diagnostics.probe_state)}>{probeLabel[diagnostics.probe_state] ?? diagnostics.probe_state} · {diagnostics.probe_successes}/{diagnostics.probe_targets}{diagnostics.probe_rtt_ms == null ? '' : ` · ${diagnostics.probe_rtt_ms} ms`}</Tag> },
      { label: '当前故障前缀', value: telemetry.failed_route_prefixes?.length ? telemetry.failed_route_prefixes.join('、') : '无' },
      { label: '诊断错误', value: diagnostics.last_error_code ?? '无' },
    ]} />}
    {diagnostics && (diagnostics.active_issues.length > 0 || diagnostics.last_recovered_issues.length > 0) && <div>
      <Typography.Text bold>路由异常证据</Typography.Text>
      <Table<(typeof routeIssues)[number]>
        rowKey={(issue) => `${issue.evidenceState}:${issue.prefix}:${issue.table_id}:${issue.reason}`}
        size="small"
        pagination={false}
        columns={[
          { title: '前缀', dataIndex: 'prefix' },
          { title: '路由表', dataIndex: 'table_id' },
          { title: '状态', render: (_: unknown, issue: typeof routeIssues[number]) => <Tag color={issue.evidenceState === 'active' ? 'red' : 'green'}>{issue.evidenceState === 'active' ? '当前异常' : '已恢复'}</Tag> },
          { title: '期望 / 实测', render: (_: unknown, issue: typeof routeIssues[number]) => `${issue.expected_kind} / ${issue.observed_kind}` },
          { title: '原因 / 处置', render: (_: unknown, issue: typeof routeIssues[number]) => `${issue.reason} · ${issue.action}` },
        ]}
        data={routeIssues}
      />
    </div>}
    <div>
      <Typography.Text bold>路径与 Stream</Typography.Text>
      <Table
        rowKey={(path) => `${path.peer_attachment_id}:${path.connection_epoch}`}
        size="small"
        pagination={false}
        columns={[
          { title: 'Peer Attachment', dataIndex: 'peer_attachment_id', ellipsis: true },
          { title: '路径', render: (_: unknown, path: typeof paths[number]) => <Tag color={tone(pathHealth(path))}>{stateLabel[pathHealth(path)] ?? pathHealth(path)}</Tag> },
          { title: 'RTT / 丢包', render: (_: unknown, path: typeof paths[number]) => `${number(path.rtt_ms)} ms / ${path.packet_loss_ppm == null ? '—' : `${(path.packet_loss_ppm / 10_000).toFixed(2)}%`}` },
          { title: 'Stream', render: (_: unknown, path: typeof paths[number]) => `${number(path.ready_streams)} / ${number(path.stream_count)}` },
          { title: '队列', render: (_: unknown, path: typeof paths[number]) => path.queue_limit == null ? '—' : `${number(path.queue_depth)} / ${number(path.queue_limit)}` },
        ]}
        data={paths}
      />
    </div>
    {streams.length > 0 && <div>
      <Typography.Text bold>Stream 细节</Typography.Text>
      <Table
        rowKey={(stream) => `${stream.pathId}:${stream.slot}:${stream.generation}`}
        size="small"
        pagination={false}
        columns={[
          { title: '路径 / Slot', render: (_: unknown, stream: typeof streams[number]) => `${stream.pathId.slice(0, 8)}… / ${stream.slot}` },
          { title: '状态', render: (_: unknown, stream: typeof streams[number]) => <Tag color={tone(streamHealth(stream))}>{stateLabel[streamHealth(stream)] ?? stream.state}</Tag> },
          { title: '队列 / 上限', render: (_: unknown, stream: typeof streams[number]) => `${number(stream.queue_depth)} / ${number(stream.queue_limit)}` },
          { title: '窗口 / 阻塞', render: (_: unknown, stream: typeof streams[number]) => `${number(stream.send_window_bytes)} B / ${number(stream.blocked_ms)} ms` },
          { title: '错误', render: (_: unknown, stream: typeof streams[number]) => stream.last_error_code ?? (stream.decode_errors ? `decode_errors=${stream.decode_errors}` : '无') },
        ]}
        data={streams}
      />
    </div>}
  </Space>;
}
