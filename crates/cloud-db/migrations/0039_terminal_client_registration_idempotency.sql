ALTER TABLE client_devices
    ADD COLUMN request_id BINARY(16) NOT NULL AFTER install_id,
    ADD COLUMN request_hash BINARY(32) NOT NULL AFTER request_id,
    ADD UNIQUE KEY uq_client_devices_request (tenant_id, user_id, request_id);
