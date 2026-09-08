-- Preparing or rejecting a candidate must not erase the identity of the
-- configuration that is still forwarding traffic. Advance only on ACTIVE.
ALTER TABLE runtime_configuration_status
    ADD COLUMN active_projection_publication_id BINARY(16) NULL,
    ADD CONSTRAINT fk_runtime_active_projection_identity
        FOREIGN KEY (tenant_id, device_id, device_key_id, active_projection_publication_id)
        REFERENCES site_route_projection_publications(tenant_id, device_id, device_key_id, id);

UPDATE runtime_configuration_status
SET active_projection_publication_id = projection_publication_id
WHERE apply_state = 'ACTIVE';
