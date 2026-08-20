export type ManagementRole =
  | 'ORGANIZATION_OWNER'
  | 'TENANT_ADMIN'
  | 'OPERATOR'
  | 'BILLING_VIEWER'
  | 'AUDITOR';

export type WebCapabilities = {
  readConfiguration: boolean;
  writeConfiguration: boolean;
  manageDevices: boolean;
  readMembers: boolean;
  manageMembers: boolean;
  manageBilling: boolean;
  readAudit: boolean;
};

const denied: WebCapabilities = {
  readConfiguration: false,
  writeConfiguration: false,
  manageDevices: false,
  readMembers: false,
  manageMembers: false,
  manageBilling: false,
  readAudit: false,
};

export function capabilitiesForRole(role?: string): WebCapabilities {
  switch (role as ManagementRole | undefined) {
    case 'ORGANIZATION_OWNER':
      return {
        readConfiguration: true,
        writeConfiguration: true,
        manageDevices: true,
        readMembers: true,
        manageMembers: true,
        manageBilling: true,
        readAudit: true,
      };
    case 'TENANT_ADMIN':
      return {
        readConfiguration: true,
        writeConfiguration: true,
        manageDevices: true,
        readMembers: true,
        manageMembers: false,
        manageBilling: true,
        readAudit: true,
      };
    case 'OPERATOR':
      return {
        ...denied,
        readConfiguration: true,
        writeConfiguration: true,
        manageDevices: true,
      };
    case 'BILLING_VIEWER':
      return {
        ...denied,
        readConfiguration: true,
        manageBilling: true,
      };
    case 'AUDITOR':
      return {
        ...denied,
        readConfiguration: true,
        readMembers: true,
        readAudit: true,
      };
    default:
      return denied;
  }
}

export function roleLabel(role?: string): string {
  switch (role as ManagementRole | undefined) {
    case 'ORGANIZATION_OWNER': return '组织所有者';
    case 'TENANT_ADMIN': return '租户管理员';
    case 'OPERATOR': return '网络运维';
    case 'BILLING_VIEWER': return '账务只读';
    case 'AUDITOR': return '审计员';
    default: return role || '权限未识别';
  }
}
