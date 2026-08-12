export type SessionClaims = {
  sub?: string;
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
