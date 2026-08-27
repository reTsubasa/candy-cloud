import type { RuntimeActivationReadiness } from './types';
import { runtimeErrorReason } from './runtime-error';

export type ActivationDisplay = {
  label: string;
  detail: string;
  tone: 'green' | 'orange' | 'red' | 'gray' | 'arcoblue';
};

function applyFailureDetail(readiness: RuntimeActivationReadiness): string {
  const errors = (readiness.apply_error_codes ?? []).map((code) => runtimeErrorReason(code) ?? code);
  const reason = [...new Set(errors)].join('、');
  return String(readiness.failed_apply_count || 1) + ' 个节点未能应用配置' + (reason ? '：' + reason : '');
}

export function activationDisplay(
  readiness: RuntimeActivationReadiness | null | undefined,
  error: string | null | undefined,
  loading: boolean,
): ActivationDisplay {
  if (loading && !readiness) return { label: '读取中', detail: '正在读取 Cloud 激活状态', tone: 'arcoblue' };
  if (error && !readiness) return { label: '读取失败', detail: error, tone: 'red' };
  if (!readiness) return { label: '待检查', detail: '尚未读取 Cloud 激活状态', tone: 'gray' };
  if (readiness.ready) return { label: '已启用', detail: '配置已发布，等待节点保持在线', tone: 'green' };
  if (readiness.reason_codes.includes('service_not_enabled')) return { label: '服务未开通', detail: '当前租户尚未开通 SD-WAN 服务', tone: 'orange' };
  if (readiness.reason_codes.includes('node_apply_failed')) return { label: '节点应用失败', detail: applyFailureDetail(readiness), tone: 'red' };
  if (readiness.reason_codes.includes('node_offline')) return { label: '等待节点', detail: `${readiness.missing_transport_count} 条线路等待公网 UDP 端点`, tone: 'orange' };
  if (readiness.reason_codes.includes('config_pending')) return { label: '配置发布中', detail: 'Cloud 正在生成并签名节点配置', tone: 'arcoblue' };
  if (readiness.reason_codes.includes('node_apply_pending')) return { label: '等待节点应用', detail: '配置已发布，等待 ' + String(readiness.pending_apply_count || 1) + ' 个节点确认生效', tone: 'orange' };
  return { label: '等待激活', detail: '线路已保存，等待节点配置生效', tone: 'orange' };
}
