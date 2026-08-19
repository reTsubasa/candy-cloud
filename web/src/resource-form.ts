import type { ResourceSpec } from './types';

export type Spec = Record<string, unknown>;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const hostnamePattern = /^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i;

function ipv4Number(value: string): number | null {
  const octets = value.split('.');
  if (octets.length !== 4 || octets.some((item) => !/^\d{1,3}$/.test(item) || Number(item) > 255)) return null;
  return octets.reduce((result, item) => result * 256 + Number(item), 0) >>> 0;
}

function validIpv4(value: string): boolean {
  return ipv4Number(value) !== null;
}

function validUnicastIpv4(value: string): boolean {
  const address = ipv4Number(value);
  if (address === null || address === 0 || address === 0xffffffff) return false;
  const firstOctet = address >>> 24;
  return firstOctet !== 127 && (firstOctet < 224 || firstOctet > 239);
}

function validIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-f:]+$/i.test(value) || value.length > 39) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

export function parseCidr(value: string): { network: string; prefix_len: number } | null {
  const [network, prefixText, ...extra] = value.trim().split('/');
  const prefix = Number(prefixText);
  const address = ipv4Number(network);
  if (extra.length || address === null || !Number.isInteger(prefix) || prefix < 1 || prefix > 32) return null;
  const hostBits = 32 - prefix;
  const mask = hostBits === 0 ? 0xffffffff : (0xffffffff << hostBits) >>> 0;
  if ((address & mask) >>> 0 !== address) return null;
  return { network, prefix_len: prefix };
}

export function formatCidr(value: unknown): string {
  const prefix = value as { network?: unknown; prefix_len?: unknown } | undefined;
  return prefix?.network && prefix?.prefix_len ? `${prefix.network}/${prefix.prefix_len}` : '';
}

export function normalizeSpecForEditor(resource: ResourceSpec): Spec {
  const spec = structuredClone(resource.spec);
  if (resource.kind === 'DNS_INTENT') {
    const legacySiteId = typeof spec.site_id === 'string' ? spec.site_id : '';
    const siteIds = Array.isArray(spec.site_ids) ? spec.site_ids : legacySiteId ? [legacySiteId] : [];
    spec.site_ids = siteIds;
    spec.publish_scope = siteIds.length > 0 ? 'SELECTED' : 'ALL';
  }
  if ('overlay_prefix' in spec) spec.overlay_cidr = formatCidr(spec.overlay_prefix);
  if ('prefix' in spec) spec.cidr = formatCidr(spec.prefix);
  if ('max_bits_per_second' in spec) spec.capacity_mbps = Number(spec.max_bits_per_second) / 1_000_000;
  return spec;
}

function cleanText(value: unknown): string {
  return String(value ?? '').trim();
}

function positiveInteger(value: unknown): number {
  return Number(value);
}

export function buildResourceSpec(kind: string, editor: Spec): ResourceSpec {
  const spec = structuredClone(editor);
  delete spec.overlay_cidr;
  delete spec.cidr;
  delete spec.capacity_mbps;

  if (kind === 'SEGMENT') spec.overlay_prefix = parseCidr(cleanText(editor.overlay_cidr));
  if (kind === 'ATTACHMENT') spec.epoch_floor = positiveInteger(editor.epoch_floor);
  if (kind === 'PREFIX') spec.prefix = parseCidr(cleanText(editor.cidr));
  if (kind === 'PEER') {
    const sites = [cleanText(editor.site_a_id), cleanText(editor.site_b_id)].sort();
    spec.site_a_id = sites[0];
    spec.site_b_id = sites[1];
  }
  if (kind === 'RELAY' || kind === 'EGRESS') {
    spec.max_sessions = positiveInteger(editor.max_sessions);
    spec.max_bits_per_second = Math.round(Number(editor.capacity_mbps) * 1_000_000);
  }
  if (kind === 'PATH_CANDIDATE') {
    spec.priority = positiveInteger(editor.priority);
    spec.relay_id = editor.kind === 'RELAY' ? cleanText(editor.relay_id) : null;
  }
  if (kind === 'SERVICE_POLICY') {
    spec.generation = positiveInteger(editor.generation);
    spec.rules = ((editor.rules as Spec[]) ?? []).map((rule) => ({
      id: cleanText(rule.id) || crypto.randomUUID(),
      priority: positiveInteger(rule.priority),
      source_site_ids: (rule.source_site_ids as string[]) ?? [],
      destination_prefixes: ((rule.destination_cidrs as string[]) ?? []).map(parseCidr),
      domains: ((rule.domains as string[]) ?? []).map(cleanText).filter(Boolean),
      traffic_classes: ((rule.traffic_classes as string[]) ?? []).map(cleanText).filter(Boolean),
      action: rule.action_type === 'REMOTE_EGRESS'
        ? { type: 'REMOTE_EGRESS', egress_id: cleanText(rule.egress_id) }
        : { type: 'LOCAL_EGRESS' },
    }));
  }
  if (kind === 'DNS_INTENT') {
    delete spec.publish_scope;
    delete spec.site_id;
    spec.site_ids = ((editor.site_ids as string[]) ?? []).filter(Boolean);
    spec.records = ((editor.records as Spec[]) ?? []).map((record) => ({
      name: cleanText(record.name),
      ttl_seconds: positiveInteger(record.ttl_seconds),
      data: { type: record.type, value: cleanText(record.value) },
      required_prefix_id: cleanText(record.required_prefix_id) || null,
    }));
  }
  return { kind, spec };
}

function required(spec: Spec, fields: string[], errors: string[]) {
  fields.forEach((field) => { if (!cleanText(spec[field])) errors.push(`${field}:required`); });
}

export function validateResourceEditor(kind: string, spec: Spec): string[] {
  const errors: string[] = [];
  const uuidFields: Record<string, string[]> = {
    NODE: ['device_id', 'device_key_id', 'site_id'],
    ATTACHMENT: ['segment_id', 'site_id', 'node_id'],
    PREFIX: ['site_id', 'segment_id'],
    PEER: ['segment_id', 'site_a_id', 'site_b_id'],
    PATH_CANDIDATE: ['segment_id', 'peer_id', 'source_attachment_id', 'destination_attachment_id', 'transport_node_id'],
    EGRESS: ['site_id', 'attachment_id'],
    RELAY: ['service_node_id'],
    SERVICE_POLICY: ['segment_id'],
    DNS_INTENT: ['segment_id'],
  };
  const textFields: Record<string, string[]> = {
    SITE: ['name', 'kind'], NODE: ['display_name', 'platform', 'architecture'], SEGMENT: ['name'], ATTACHMENT: ['overlay_router_ipv4'],
    PREFIX: ['source'], PEER: ['path_policy'], PATH_CANDIDATE: ['kind'],
    EGRESS: ['name'], RELAY: ['name', 'region'], DNS_INTENT: ['zone'],
  };
  required(spec, [...(uuidFields[kind] ?? []), ...(textFields[kind] ?? [])], errors);
  (uuidFields[kind] ?? []).forEach((field) => {
    const value = cleanText(spec[field]);
    if (value && !uuidPattern.test(value)) errors.push(`${field}:uuid`);
  });
  if (kind === 'SEGMENT' && !parseCidr(cleanText(spec.overlay_cidr))) errors.push('overlay_cidr:cidr');
  if (kind === 'ATTACHMENT') {
    if (!validUnicastIpv4(cleanText(spec.overlay_router_ipv4))) errors.push('overlay_router_ipv4:ipv4');
    if (!Number.isInteger(Number(spec.epoch_floor)) || Number(spec.epoch_floor) < 1) errors.push('epoch_floor:positive');
  }
  if (kind === 'PREFIX' && !parseCidr(cleanText(spec.cidr))) errors.push('cidr:cidr');
  if (kind === 'PEER' && spec.site_a_id === spec.site_b_id) errors.push('site_b_id:different');
  if (kind === 'RELAY' || kind === 'EGRESS') {
    if (!Number.isInteger(Number(spec.max_sessions)) || Number(spec.max_sessions) < 1) errors.push('max_sessions:positive');
    if (!(Number(spec.capacity_mbps) > 0)) errors.push('capacity_mbps:positive');
  }
  if (kind === 'PATH_CANDIDATE') {
    if (!Number.isInteger(Number(spec.priority)) || Number(spec.priority) < 1 || Number(spec.priority) > 65535) errors.push('priority:range');
    if (spec.source_attachment_id === spec.destination_attachment_id) errors.push('destination_attachment_id:different');
    if (spec.kind === 'RELAY' && !uuidPattern.test(cleanText(spec.relay_id))) errors.push('relay_id:uuid');
  }
  if (kind === 'SERVICE_POLICY') {
    const rules = (spec.rules as Spec[]) ?? [];
    if (!Number.isInteger(Number(spec.generation)) || Number(spec.generation) < 1) errors.push('generation:positive');
    const priorities = new Set<number>();
    rules.forEach((rule, index) => {
      const priority = Number(rule.priority);
      if (!Number.isInteger(priority) || priority < 0 || priorities.has(priority)) errors.push(`rules.${index}.priority:unique`);
      priorities.add(priority);
      ((rule.destination_cidrs as string[]) ?? []).forEach((cidr) => { if (!parseCidr(cidr)) errors.push(`rules.${index}.destination_cidrs:cidr`); });
      ((rule.domains as string[]) ?? []).forEach((domain) => { if (!hostnamePattern.test(domain)) errors.push(`rules.${index}.domains:domain`); });
      if (rule.action_type === 'REMOTE_EGRESS' && !uuidPattern.test(cleanText(rule.egress_id))) errors.push(`rules.${index}.egress_id:uuid`);
    });
  }
  if (kind === 'DNS_INTENT') {
    const siteIds = (spec.site_ids as string[]) ?? [];
    if (!['ALL', 'SELECTED'].includes(cleanText(spec.publish_scope))) errors.push('publish_scope:invalid');
    if (cleanText(spec.publish_scope) === 'SELECTED' && siteIds.length === 0) errors.push('site_ids:required');
    siteIds.forEach((siteId, index) => { if (!uuidPattern.test(cleanText(siteId))) errors.push(`site_ids.${index}:uuid`); });
    if (!hostnamePattern.test(cleanText(spec.zone))) errors.push('zone:domain');
    ((spec.records as Spec[]) ?? []).forEach((record, index) => {
      if (!hostnamePattern.test(cleanText(record.name))) errors.push(`records.${index}.name:domain`);
      if (!Number.isInteger(Number(record.ttl_seconds)) || Number(record.ttl_seconds) < 5 || Number(record.ttl_seconds) > 86400) errors.push(`records.${index}.ttl_seconds:range`);
      if (!cleanText(record.value)) errors.push(`records.${index}.value:required`);
      if (record.type === 'A' && !validIpv4(cleanText(record.value))) errors.push(`records.${index}.value:ipv4`);
      if (record.type === 'AAAA' && !validIpv6(cleanText(record.value))) errors.push(`records.${index}.value:ipv6`);
      if (record.type === 'CNAME' && !hostnamePattern.test(cleanText(record.value))) errors.push(`records.${index}.value:domain`);
    });
  }
  return errors;
}

export function policyRulesForEditor(value: unknown): Spec[] {
  return ((value as Spec[]) ?? []).map((rule) => {
    const action = (rule.action as Spec) ?? {};
    return {
      ...rule,
      destination_cidrs: ((rule.destination_prefixes as unknown[]) ?? []).map(formatCidr),
      action_type: action.type ?? 'LOCAL_EGRESS',
      egress_id: action.egress_id ?? '',
    };
  });
}

export function dnsRecordsForEditor(value: unknown): Spec[] {
  return ((value as Spec[]) ?? []).map((record) => {
    const data = (record.data as Spec) ?? {};
    return { ...record, type: data.type ?? 'A', value: data.value ?? '' };
  });
}
