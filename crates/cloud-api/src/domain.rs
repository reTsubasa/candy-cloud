use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceClass { Private, CandyShared, CandyDedicated, Partner }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role { OrganizationOwner, TenantAdmin, Operator, BillingViewer, Auditor }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { ReadConfiguration, WriteConfiguration, ManageDevices, ManageBilling, ReadAudit }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext { pub organization_id: Uuid, pub tenant_id: Uuid, pub role: Role }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device { pub id: Uuid, pub tenant_id: Uuid, pub device_id: String, pub status: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement { pub tenant_id: Uuid, pub node_pool_id: Uuid, pub service_class: ServiceClass, pub permission: String, pub generation: u64 }

pub fn authorize(context: &TenantContext, organization_id: Uuid, tenant_id: Uuid, action: Action) -> Result<(), &'static str> {
    if context.organization_id != organization_id || context.tenant_id != tenant_id {
        return Err("cross-tenant access denied");
    }
    let permitted = match context.role {
        Role::OrganizationOwner | Role::TenantAdmin => true,
        Role::Operator => matches!(action, Action::ReadConfiguration | Action::WriteConfiguration | Action::ManageDevices),
        Role::BillingViewer => matches!(action, Action::ReadConfiguration | Action::ManageBilling),
        Role::Auditor => matches!(action, Action::ReadConfiguration | Action::ReadAudit),
    };
    permitted.then_some(()).ok_or("role is not permitted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_context_rejects_cross_tenant_access() {
        let tenant = Uuid::new_v4();
        let organization = Uuid::new_v4();
        let context = TenantContext { organization_id: organization, tenant_id: tenant, role: Role::TenantAdmin };
        assert!(authorize(&context, organization, tenant, Action::ManageDevices).is_ok());
        assert!(authorize(&context, organization, Uuid::new_v4(), Action::ManageDevices).is_err());
    }

    #[test]
    fn auditor_can_read_audit_but_cannot_change_configuration() {
        let organization = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let context = TenantContext { organization_id: organization, tenant_id: tenant, role: Role::Auditor };
        assert!(authorize(&context, organization, tenant, Action::ReadAudit).is_ok());
        assert!(authorize(&context, organization, tenant, Action::WriteConfiguration).is_err());
    }
}
