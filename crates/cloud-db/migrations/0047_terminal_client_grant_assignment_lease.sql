-- The node set a Grant names is only valid until `assignment_lease_until`, but
-- until now that instant existed *only* inside the signed `grant_envelope` blob.
-- Issuance therefore had no way to answer "is the assignment this device is
-- already holding still live?" without parsing every candidate envelope, so a
-- device that refreshed its Grant inside the lease window was re-routed to a
-- possibly different node set for no reason.
--
-- This column is a *derived redundancy* of the value already signed into every
-- `nodes[].assignment_lease_until`. It is never authoritative: the envelope stays
-- the signed source of truth, and nothing about the wire contract, the signature
-- domain, or the canonicalization changes. Reading the column is only how the
-- reuse decision avoids decoding a blob it did not have to decode.
--
-- It is NULL-able on purpose. Rows written before this migration carry no lease
-- evidence, and "no evidence" must be a safe state that forces re-selection
-- rather than a value Cloud guessed. Writers always set it, and the window is
-- kept self-consistent with the envelope rule `issued_at < lease_until <=
-- expires_at` by `ClientGrantWrite::validate`.

ALTER TABLE client_grants
    ADD COLUMN assignment_lease_until TIMESTAMP(6) NULL AFTER expires_at,
    -- Serves the lease-liveness question directly ("does this device key still
    -- hold a live assignment?") instead of requiring a scan of the device's Grant
    -- generations. The reuse read path itself is served by
    -- `idx_client_grants_active`, which already covers
    -- (tenant_id, client_device_id, device_key_id, status, generation).
    ADD KEY idx_client_grants_assignment_lease (tenant_id, client_device_id, device_key_id, status, assignment_lease_until);
