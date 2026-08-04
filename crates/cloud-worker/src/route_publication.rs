use candy_proto::{
    cloud_grant::PolicyId,
    dynamic_route_contract::DynamicRouteSnapshotV1,
    error::ProtocolError,
    fabric_assignment_contract::HubFabricAssignmentV1,
    ip_tunnel::AttachmentId,
    mesh_contract::MeshMembershipProjectionV1,
    route_contract::{
        AllowedHubNodeV1, AttachmentPrincipalV1, AttachmentState, FailoverPolicyV1, Ipv4PrefixV1,
        PacketResourcePolicyV1, RemoteRouteV1, SegmentAttachmentV1, SegmentRouteSnapshotV1,
        SegmentRouteV1, SiteRouteProjectionV1,
    },
    shared_hub_contract::SharedHubAdmissionPolicyV1,
};
use carrier_crypto::route_contract::{
    seal_dynamic_route_snapshot, seal_fabric_assignment, seal_mesh_membership,
    seal_segment_snapshot, seal_shared_hub_admission, seal_site_projection,
    RouteContractCryptoError, SealedRouteObject,
};
use cloud_db::sdwan::{
    ExpansionObjectKind, ExpansionObjectPublicationWrite, PublicationOutcome, SdwanError,
    SdwanRepository, SegmentPublicationWrite, SignedObjectWrite, SiteProjectionPublicationWrite,
};
use ed25519_dalek::SigningKey;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct RouteSigner {
    key_id: Vec<u8>,
    signing_key: SigningKey,
}

impl RouteSigner {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            key_id: key_id.into().into_bytes(),
            signing_key,
        }
    }

    pub fn sign_shared_hub_admission(
        &self,
        policy: SharedHubAdmissionPolicyV1,
    ) -> Result<SealedRouteObject<SharedHubAdmissionPolicyV1>, RoutePublicationError> {
        Ok(seal_shared_hub_admission(
            policy,
            self.key_id.clone(),
            &self.signing_key,
        )?)
    }

    pub fn sign_mesh_membership(
        &self,
        projection: MeshMembershipProjectionV1,
    ) -> Result<SealedRouteObject<MeshMembershipProjectionV1>, RoutePublicationError> {
        Ok(seal_mesh_membership(
            projection,
            self.key_id.clone(),
            &self.signing_key,
        )?)
    }

    pub fn sign_dynamic_route_snapshot(
        &self,
        snapshot: DynamicRouteSnapshotV1,
    ) -> Result<SealedRouteObject<DynamicRouteSnapshotV1>, RoutePublicationError> {
        Ok(seal_dynamic_route_snapshot(
            snapshot,
            self.key_id.clone(),
            &self.signing_key,
        )?)
    }

    pub fn sign_fabric_assignment(
        &self,
        assignment: HubFabricAssignmentV1,
    ) -> Result<SealedRouteObject<HubFabricAssignmentV1>, RoutePublicationError> {
        Ok(seal_fabric_assignment(
            assignment,
            self.key_id.clone(),
            &self.signing_key,
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProjectionInput {
    pub publication_id: Uuid,
    pub attachment_id: AttachmentId,
    pub projection_id: PolicyId,
    pub projection_generation: u64,
    pub previous_hash: [u8; 32],
    pub allowed_hub_nodes: Vec<AllowedHubNodeV1>,
    pub max_inner_mtu: u16,
    pub failover: FailoverPolicyV1,
    pub resources: PacketResourcePolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePublicationInput {
    pub publication_id: Uuid,
    pub audit_event_id: Uuid,
    pub actor_id: String,
    pub tenant_id: candy_proto::cloud_grant::TenantId,
    pub segment_id: candy_proto::ip_tunnel::SegmentId,
    pub generation: u64,
    pub previous_hash: [u8; 32],
    pub hub_node_pool_id: candy_proto::cloud_grant::NodePoolId,
    pub segment_overlay_prefix: Ipv4PrefixV1,
    pub attachments: Vec<SegmentAttachmentV1>,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub projections: Vec<DeviceProjectionInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltDeviceProjection {
    pub publication_id: Uuid,
    pub sealed: SealedRouteObject<SiteRouteProjectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltRoutePublication {
    pub publication_id: Uuid,
    pub audit_event_id: Uuid,
    pub actor_id: String,
    pub segment: SealedRouteObject<SegmentRouteSnapshotV1>,
    pub projections: Vec<BuiltDeviceProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltExpansionPublication {
    SharedHub {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<SharedHubAdmissionPolicyV1>>,
    },
    Mesh {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<MeshMembershipProjectionV1>>,
    },
    DynamicRoute {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<DynamicRouteSnapshotV1>>,
    },
    FabricAssignment {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<HubFabricAssignmentV1>>,
    },
}

impl BuiltRoutePublication {
    pub fn database_write(&self) -> Result<SegmentPublicationWrite, RoutePublicationError> {
        self.database_write_with_expansions(&[])
    }

    pub fn database_write_with_expansions(
        &self,
        expansions: &[BuiltExpansionPublication],
    ) -> Result<SegmentPublicationWrite, RoutePublicationError> {
        let generation = self.segment.object.segment_generation;
        let expected_previous_generation = generation
            .checked_sub(1)
            .ok_or(RoutePublicationError::InvalidGeneration)?;
        Ok(SegmentPublicationWrite {
            publication_id: self.publication_id,
            tenant_id: uuid(self.segment.object.tenant_id.0),
            segment_id: uuid(self.segment.object.segment_id.0),
            expected_previous_generation,
            expected_previous_hash: self.segment.object.previous_hash,
            generation,
            snapshot: SignedObjectWrite {
                content_hash: self.segment.object.content_hash,
                signed_envelope: self.segment.envelope.encode()?,
            },
            projections: self
                .projections
                .iter()
                .map(|built| {
                    let projection = &built.sealed.object;
                    Ok(SiteProjectionPublicationWrite {
                        publication_id: built.publication_id,
                        projection_id: uuid(projection.projection_id.0),
                        tenant_id: uuid(projection.tenant_id.0),
                        segment_id: uuid(projection.segment_id.0),
                        site_id: uuid(projection.site_id.0),
                        attachment_id: uuid(projection.attachment_id.0),
                        device_id: uuid(projection.device_id.0),
                        device_key_id: uuid(projection.device_key_id.0),
                        segment_generation: projection.segment_generation,
                        segment_content_hash: projection.segment_content_hash,
                        projection_generation: projection.projection_generation,
                        previous_hash: projection.previous_hash,
                        object: SignedObjectWrite {
                            content_hash: projection.content_hash,
                            signed_envelope: built.sealed.envelope.encode()?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, RoutePublicationError>>()?,
            expansions: expansions
                .iter()
                .map(|expansion| self.expansion_write(expansion))
                .collect::<Result<Vec<_>, RoutePublicationError>>()?,
            audit_event_id: self.audit_event_id,
            actor_id: self.actor_id.clone(),
        })
    }

    fn expansion_write(
        &self,
        expansion: &BuiltExpansionPublication,
    ) -> Result<ExpansionObjectPublicationWrite, RoutePublicationError> {
        let segment = &self.segment.object;
        let (
            publication_id,
            kind,
            policy_id,
            generation,
            tenant_id,
            segment_id,
            segment_generation,
            segment_content_hash,
            site_id,
            attachment_id,
            content_hash,
            signed_envelope,
        ) = match expansion {
            BuiltExpansionPublication::SharedHub {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::SharedHubAdmission,
                sealed.object.policy_id,
                sealed.object.policy_generation,
                sealed.object.tenant_id,
                sealed.object.segment_id,
                sealed.object.segment_generation,
                sealed.object.segment_content_hash,
                None,
                None,
                sealed.object.content_hash,
                sealed.envelope.encode()?,
            ),
            BuiltExpansionPublication::Mesh {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::MeshMembership,
                sealed.object.projection_id,
                sealed.object.projection_generation,
                sealed.object.tenant_id,
                sealed.object.segment_id,
                sealed.object.segment_generation,
                sealed.object.segment_content_hash,
                Some(sealed.object.local_site_id),
                Some(sealed.object.local_attachment_id),
                sealed.object.content_hash,
                sealed.envelope.encode()?,
            ),
            BuiltExpansionPublication::DynamicRoute {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::DynamicRouteSnapshot,
                sealed.object.policy_id,
                sealed.object.generation,
                sealed.object.tenant_id,
                sealed.object.segment_id,
                sealed.object.base_segment_generation,
                sealed.object.base_segment_content_hash,
                None,
                None,
                sealed.object.content_hash,
                sealed.envelope.encode()?,
            ),
            BuiltExpansionPublication::FabricAssignment {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::FabricAssignment,
                sealed.object.policy_id,
                sealed.object.generation,
                sealed.object.tenant_id,
                sealed.object.segment_id,
                sealed.object.segment_generation,
                sealed.object.segment_content_hash,
                None,
                None,
                sealed.object.content_hash,
                sealed.envelope.encode()?,
            ),
        };
        if publication_id.is_nil()
            || tenant_id != segment.tenant_id
            || segment_id != segment.segment_id
            || segment_generation != segment.segment_generation
            || segment_content_hash != segment.content_hash
        {
            return Err(RoutePublicationError::ExpansionScopeMismatch);
        }
        Ok(ExpansionObjectPublicationWrite {
            publication_id,
            kind,
            policy_id: uuid(policy_id.0),
            tenant_id: uuid(tenant_id.0),
            segment_id: uuid(segment_id.0),
            generation,
            segment_generation,
            segment_content_hash,
            site_id: site_id.map(|id| uuid(id.0)),
            attachment_id: attachment_id.map(|id| uuid(id.0)),
            object: SignedObjectWrite {
                content_hash,
                signed_envelope,
            },
        })
    }
}

#[derive(Debug, Error)]
pub enum RoutePublicationError {
    #[error("publication generation is invalid")]
    InvalidGeneration,
    #[error("a route owner is not ACTIVE")]
    InactiveOwner,
    #[error("route ownership overlaps across Sites")]
    OverlappingOwnership,
    #[error("every active DeviceAttachment requires exactly one projection")]
    IncompleteProjectionSet,
    #[error("projection does not bind the selected DeviceAttachment")]
    ProjectionAttachmentMismatch,
    #[error("expansion object does not bind the selected Segment publication")]
    ExpansionScopeMismatch,
    #[error("at least one active diagnostic NodeAttachment is required")]
    MissingDiagnosticHub,
    #[error("projection Hub identity differs from the Segment NodeAttachment")]
    HubIdentityMismatch,
    #[error("every device projection requires a reverse route")]
    MissingReverseRoute,
    #[error("Core route contract rejected the publication")]
    Protocol(#[from] ProtocolError),
    #[error("Core route signing rejected the publication")]
    Crypto(#[from] RouteContractCryptoError),
    #[error("SD-WAN repository rejected the publication")]
    Repository(#[from] SdwanError),
}

pub fn build_route_publication(
    input: &RoutePublicationInput,
    signer: &RouteSigner,
) -> Result<BuiltRoutePublication, RoutePublicationError> {
    if input.generation == 0
        || input.publication_id.is_nil()
        || input.audit_event_id.is_nil()
        || input.actor_id.is_empty()
    {
        return Err(RoutePublicationError::InvalidGeneration);
    }

    let mut attachments = input.attachments.clone();
    attachments.sort_unstable_by_key(|attachment| attachment.attachment_id.0);
    let routes = compile_routes(&attachments)?;
    let expected_hubs = diagnostic_hubs(&attachments)?;
    let device_attachments: Vec<&SegmentAttachmentV1> = attachments
        .iter()
        .filter(|attachment| {
            attachment.state == AttachmentState::Active
                && matches!(attachment.principal, AttachmentPrincipalV1::Device { .. })
        })
        .collect();
    if input.projections.len() != device_attachments.len() {
        return Err(RoutePublicationError::IncompleteProjectionSet);
    }

    let segment = seal_segment_snapshot(
        SegmentRouteSnapshotV1 {
            tenant_id: input.tenant_id,
            segment_id: input.segment_id,
            segment_generation: input.generation,
            hub_node_pool_id: input.hub_node_pool_id,
            segment_overlay_prefix: input.segment_overlay_prefix,
            attachments: attachments.clone(),
            routes: routes.clone(),
            not_before: input.not_before,
            expires_at: input.expires_at,
            stale_until: input.stale_until,
            previous_hash: input.previous_hash,
            content_hash: [0; 32],
        },
        signer.key_id.clone(),
        &signer.signing_key,
    )?;

    let mut plans: Vec<&DeviceProjectionInput> = input.projections.iter().collect();
    plans.sort_unstable_by_key(|plan| plan.attachment_id.0);
    if plans
        .windows(2)
        .any(|pair| pair[0].attachment_id == pair[1].attachment_id)
    {
        return Err(RoutePublicationError::IncompleteProjectionSet);
    }
    let mut projections = Vec::with_capacity(plans.len());
    for plan in plans {
        let attachment = device_attachments
            .iter()
            .copied()
            .find(|attachment| attachment.attachment_id == plan.attachment_id)
            .ok_or(RoutePublicationError::ProjectionAttachmentMismatch)?;
        if plan.publication_id.is_nil() {
            return Err(RoutePublicationError::ProjectionAttachmentMismatch);
        }
        let mut hubs = plan.allowed_hub_nodes.clone();
        hubs.sort_unstable_by_key(hub_key);
        if hubs != expected_hubs {
            return Err(RoutePublicationError::HubIdentityMismatch);
        }
        let (device_id, device_key_id) = match attachment.principal {
            AttachmentPrincipalV1::Device {
                device_id,
                device_key_id,
            } => (device_id, device_key_id),
            AttachmentPrincipalV1::Node { .. } => {
                return Err(RoutePublicationError::ProjectionAttachmentMismatch)
            }
        };
        let site_id = attachment
            .site_id
            .ok_or(RoutePublicationError::ProjectionAttachmentMismatch)?;
        let remote_routes: Vec<RemoteRouteV1> = routes
            .iter()
            .filter(|route| route.owner_site_id != Some(site_id))
            .map(|route| {
                Ok(RemoteRouteV1 {
                    destination_prefix: route.destination_prefix,
                    owner_site_id: route
                        .owner_site_id
                        .ok_or(RoutePublicationError::OverlappingOwnership)?,
                    owner_attachment_ids: route.owner_attachment_ids.clone(),
                })
            })
            .collect::<Result<Vec<_>, RoutePublicationError>>()?;
        if remote_routes.is_empty() {
            return Err(RoutePublicationError::MissingReverseRoute);
        }
        let sealed = seal_site_projection(
            SiteRouteProjectionV1 {
                tenant_id: input.tenant_id,
                segment_id: input.segment_id,
                segment_generation: input.generation,
                segment_content_hash: segment.object.content_hash,
                site_id,
                attachment_id: attachment.attachment_id,
                device_id,
                device_key_id,
                overlay_router_ipv4: attachment.overlay_router_ipv4,
                local_prefixes: attachment.local_prefixes.clone(),
                remote_routes,
                allowed_hub_nodes: hubs,
                max_inner_mtu: plan.max_inner_mtu,
                failover: plan.failover,
                resources: plan.resources,
                epoch_floor: attachment.epoch_floor,
                not_before: input.not_before,
                expires_at: input.expires_at,
                stale_until: input.stale_until,
                projection_id: plan.projection_id,
                projection_generation: plan.projection_generation,
                previous_hash: plan.previous_hash,
                content_hash: [0; 32],
            },
            signer.key_id.clone(),
            &signer.signing_key,
        )?;
        projections.push(BuiltDeviceProjection {
            publication_id: plan.publication_id,
            sealed,
        });
    }

    Ok(BuiltRoutePublication {
        publication_id: input.publication_id,
        audit_event_id: input.audit_event_id,
        actor_id: input.actor_id.clone(),
        segment,
        projections,
    })
}

fn compile_routes(
    attachments: &[SegmentAttachmentV1],
) -> Result<Vec<SegmentRouteV1>, RoutePublicationError> {
    let mut routes: Vec<SegmentRouteV1> = Vec::new();
    for attachment in attachments {
        if !attachment.local_prefixes.is_empty() && attachment.state != AttachmentState::Active {
            return Err(RoutePublicationError::InactiveOwner);
        }
        if attachment.state != AttachmentState::Active {
            continue;
        }
        let Some(site_id) = attachment.site_id else {
            continue;
        };
        for prefix in &attachment.local_prefixes {
            if let Some(route) = routes
                .iter_mut()
                .find(|route| route.destination_prefix == *prefix)
            {
                if route.owner_site_id != Some(site_id) {
                    return Err(RoutePublicationError::OverlappingOwnership);
                }
                route.owner_attachment_ids.push(attachment.attachment_id);
            } else if routes
                .iter()
                .any(|route| route.destination_prefix.overlaps(prefix))
            {
                return Err(RoutePublicationError::OverlappingOwnership);
            } else {
                routes.push(SegmentRouteV1 {
                    destination_prefix: *prefix,
                    owner_site_id: Some(site_id),
                    owner_attachment_ids: vec![attachment.attachment_id],
                });
            }
        }
    }
    routes.sort_unstable_by_key(|route| route.destination_prefix);
    for route in &mut routes {
        route
            .owner_attachment_ids
            .sort_unstable_by_key(|attachment| attachment.0);
    }
    Ok(routes)
}

fn diagnostic_hubs(
    attachments: &[SegmentAttachmentV1],
) -> Result<Vec<AllowedHubNodeV1>, RoutePublicationError> {
    let mut hubs = Vec::new();
    for attachment in attachments {
        if attachment.state != AttachmentState::Active || attachment.site_id.is_some() {
            continue;
        }
        if let AttachmentPrincipalV1::Node {
            node_id,
            node_key_id,
        } = attachment.principal
        {
            hubs.push(AllowedHubNodeV1 {
                node_id,
                node_key_id,
                diagnostic_attachment_id: attachment.attachment_id,
            });
        }
    }
    if hubs.is_empty() {
        return Err(RoutePublicationError::MissingDiagnosticHub);
    }
    hubs.sort_unstable_by_key(hub_key);
    Ok(hubs)
}

fn hub_key(hub: &AllowedHubNodeV1) -> ([u8; 16], [u8; 16], [u8; 16]) {
    (
        hub.node_id.0,
        hub.node_key_id.0,
        hub.diagnostic_attachment_id.0,
    )
}

fn uuid(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

#[derive(Clone)]
pub struct RoutePublisher {
    repository: SdwanRepository,
    signer: RouteSigner,
}

impl RoutePublisher {
    pub fn new(repository: SdwanRepository, signer: RouteSigner) -> Self {
        Self { repository, signer }
    }

    pub async fn publish(
        &self,
        input: &RoutePublicationInput,
    ) -> Result<PublicationOutcome, RoutePublicationError> {
        let built = build_route_publication(input, &self.signer)?;
        Ok(self.repository.publish(&built.database_write()?).await?)
    }
}
