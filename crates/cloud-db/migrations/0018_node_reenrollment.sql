ALTER TABLE enrollment_activation_codes
    ADD COLUMN replace_node_id BINARY(16) NULL AFTER requested_architecture,
    ADD KEY idx_enrollment_activation_replacement (tenant_id, replace_node_id);
