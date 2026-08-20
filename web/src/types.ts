export type SessionClaims = {
  sub?: string;
  sid?: string;
  organization_id?: string;
  tenant_id?: string;
  role?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
};

export type Session = {
  token: string;
  claims: SessionClaims;
  user?: IdentityUser;
  membership?: IdentityMembership;
};

export type IdentityUser = {
  id: string;
  email: string;
  display_name: string;
  email_verified: boolean;
};

export type IdentityMembership = {
  organization_id: string;
  organization_name: string;
  tenant_id: string;
  tenant_name: string;
  role: string;
};

export type IdentitySessionResponse = {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
  user: IdentityUser;
  membership: IdentityMembership;
};

export type IdentityRegistrationResponse = {
  message: 'verification_required';
};

export type IdentityMessageResponse = {
  message: string;
};

export type HumanSession = {
  id: string;
  organization_id: string;
  tenant_id: string;
  role: string;
  device_label: string | null;
  expires_at: string;
  revoked_at: string | null;
};

export type OrganizationMember = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  active: boolean;
  created_at: string;
};

export type HealthState = {
  live: EndpointHealth;
  ready: EndpointHealth;
  degraded: EndpointHealth;
};

export type EndpointHealth = {
  status: number | null;
  text: string;
  loading: boolean;
  checkedAt: number | null;
};

export type CloudVersionInfo = {
  schema_version: number;
  cloud_version: string;
  cloud_revision: string;
  core_version: string;
};

export type ResourceMetadata = {
  schema_version: number;
  id: string;
  tenant_id: string;
  revision: number;
  state: 'ACTIVE' | 'DISABLED' | 'DELETED';
};

export type ResourceSpec = {
  kind: string;
  spec: Record<string, unknown>;
};

export type ControlResource = {
  metadata: ResourceMetadata;
  resource: ResourceSpec;
};

export type ResourceListResponse = {
  schema_version: number;
  items: ControlResource[];
  next_cursor: string | null;
};

export type MutationResponse = {
  schema_version: number;
  replayed: boolean;
  resource: ControlResource;
};

export type RuntimeActivationReadiness = {
  schema_version: number;
  segment_id: string;
  ready: boolean;
  candidate_count: number;
  ready_candidate_count: number;
  missing_transport_count: number;
  reason_codes: ('node_offline' | 'service_not_enabled' | 'config_pending')[];
};

export type RuntimeConfigurationStatus = {
  device_id: string;
  device_key_id: string;
  projection_publication_id: string;
  state: 'active' | 'rejected';
  error_code: string | null;
  reported_at: string;
  current: boolean;
};

export type RuntimeConfigurationStatusResponse = {
  schema_version: number;
  items: RuntimeConfigurationStatus[];
};

export type AuditEvent = {
  id: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  metadata_json: string;
  created_at: string;
};

export type AuditEventResponse = {
  schema_version: number;
  items: AuditEvent[];
};

export type EnrollmentActivation = {
  id: string;
  tenant_id: string;
  site_id: string | null;
  requested_display_name: string | null;
  requested_platform: 'OPEN_WRT' | 'LINUX' | null;
  requested_architecture: string | null;
  status: 'ACTIVE' | 'RESERVED' | 'CONSUMED' | 'REVOKED' | 'EXPIRED';
  expires_at: string;
  created_at: string;
  reserved_at: string | null;
  consumed_at: string | null;
  display_name: string | null;
  device_id: string | null;
  device_key_id: string | null;
};

export type EnrollmentActivationSecret = {
  id: string;
  credential: string;
  expires_at: string;
};

export type EnrollmentBootstrapManifest = {
  schema_version: 1;
  activation_id: string;
  tenant_id: string;
  site_id: string;
  display_name: string;
  platform: 'OPEN_WRT' | 'LINUX';
  architecture: string;
  enrollment_endpoint: string;
  enrollment_authorization: string;
  signing_key_id: string;
  expires_at: string;
  replayed: boolean;
};

export type ApiErrorBody = {
  schema_version?: number;
  code?: string;
  message?: string;
};

export type ResourceDefinition = {
  key: string;
  label: string;
  collection: string;
  kind: string;
  description: string;
  emptyTitle: string;
};

export type ResourceOption = {
  value: string;
  label: string;
  description?: string;
};
