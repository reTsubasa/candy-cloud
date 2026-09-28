-- Two additions to the terminal Projection tables created in 0038, both closing
-- gaps that only show up once Projections are actually served.
--
-- 1. `client_projections` had no way to answer "is the stored Projection still
--    the one Cloud would sign right now?". The Projection deliberately does not
--    carry the policy or settings generation, so without these columns a reader
--    could not tell whether a new access policy or a new settings document had
--    landed since the signature, and would either re-sign on every poll --
--    churning generations and forcing the Client to re-commit a document that
--    did not change -- or serve a stale document indefinitely.
--
--    `inputs_hash` is the fingerprint Cloud recomputes on each read. It is
--    deliberately *not* unique: a Projection whose window expired is re-signed
--    from identical inputs, and the superseded predecessor keeps the same hash.
--
-- 2. `client_projection_receipts` keyed idempotency on `request_id` alone, so a
--    device that reused a request id for a different state or projection would
--    have been handed the first receipt back as if it were the second.
--    `request_hash` turns that into an explicit conflict.

ALTER TABLE client_projections
    ADD COLUMN policy_generation BIGINT UNSIGNED NOT NULL AFTER grant_id,
    ADD COLUMN settings_generation BIGINT UNSIGNED NOT NULL AFTER policy_generation,
    ADD COLUMN device_traffic_mode ENUM('POLICY','GLOBAL') NOT NULL AFTER settings_generation,
    ADD COLUMN inputs_hash BINARY(32) NOT NULL AFTER content_hash,
    ADD KEY idx_client_projections_inputs (tenant_id, client_device_id, device_key_id, inputs_hash),
    ADD CONSTRAINT client_projections_policy_generation_positive CHECK (policy_generation >= 1),
    ADD CONSTRAINT client_projections_settings_generation_positive CHECK (settings_generation >= 1);

ALTER TABLE client_projection_receipts
    ADD COLUMN request_hash BINARY(32) NOT NULL AFTER request_id;
