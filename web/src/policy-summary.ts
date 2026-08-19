import type { ControlResource } from './types';

export type PolicyReferences = {
  segments: Record<string, string>;
  sites: Record<string, string>;
  egresses: Record<string, string>;
};

export type PolicyRuleSummary = {
  id: string;
  priority: number;
  sources: string[];
  conditions: string[];
  action: string;
  remote: boolean;
};

export type PolicySummary = {
  segmentName: string;
  rules: PolicyRuleSummary[];
  defaultAction: string;
};

const trafficClassLabels: Record<string, string> = {
  interactive: '交互业务',
  realtime: '实时音视频',
  bulk: '批量传输',
  default: '默认流量',
};

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((item) => String(item ?? '').trim()).filter(Boolean)
    : [];
}

function cidrList(rule: Record<string, unknown>): string[] {
  const editorCidrs = stringList(rule.destination_cidrs);
  if (editorCidrs.length > 0) return editorCidrs;
  if (!Array.isArray(rule.destination_prefixes)) return [];
  return rule.destination_prefixes.flatMap((item) => {
    const prefix = item as { network?: unknown; prefix_len?: unknown } | null;
    if (!prefix?.network && prefix?.network !== 0) return [];
    const length = Number(prefix.prefix_len);
    return Number.isInteger(length) ? [`${String(prefix.network)}/${length}`] : [];
  });
}

function resolvedNames(ids: string[], names: Record<string, string>, fallback: string): string[] {
  return ids.map((id) => names[id]?.trim() || fallback);
}

export function summarizePolicy(resource: ControlResource, references: PolicyReferences): PolicySummary {
  const spec = resource.resource.spec;
  const segmentId = String(spec.segment_id ?? '');
  const rules = Array.isArray(spec.rules) ? spec.rules : [];

  return {
    segmentName: references.segments[segmentId]?.trim() || '未知网络',
    defaultAction: '全部流量保持本站出口',
    rules: rules.map((value, index) => {
      const rule = (value ?? {}) as Record<string, unknown>;
      const sourceIds = stringList(rule.source_site_ids);
      const action = (rule.action ?? {}) as Record<string, unknown>;
      const actionType = String(action.type ?? rule.action_type ?? 'LOCAL_EGRESS');
      const egressId = String(action.egress_id ?? rule.egress_id ?? '');
      const priority = Number(rule.priority);
      const conditions = [
        ...cidrList(rule),
        ...stringList(rule.domains),
        ...stringList(rule.traffic_classes).map((item) => trafficClassLabels[item] ?? item),
      ];

      return {
        id: String(rule.id ?? `rule-${index}`),
        priority: Number.isFinite(priority) ? priority : Number.MAX_SAFE_INTEGER,
        sources: sourceIds.length > 0 ? resolvedNames(sourceIds, references.sites, '未知站点') : ['全部站点'],
        conditions: conditions.length > 0 ? conditions : ['全部流量'],
        action: actionType === 'REMOTE_EGRESS'
          ? references.egresses[egressId]?.trim() || '未知出口'
          : '本站出口',
        remote: actionType === 'REMOTE_EGRESS',
      };
    }).sort((a, b) => a.priority - b.priority),
  };
}

export function compactPolicyValues(values: string[], limit = 2): string {
  if (values.length <= limit) return values.join(' · ');
  return `${values.slice(0, limit).join(' · ')} 等 ${values.length} 项`;
}
