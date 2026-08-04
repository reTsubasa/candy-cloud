ALTER TABLE enrollment_challenges
    ADD COLUMN certificate_id BINARY(16) NULL AFTER device_id,
    ADD COLUMN completion_fingerprint BINARY(32) NULL AFTER completion_request_id,
    ADD UNIQUE KEY uq_enrollment_completion_request (tenant_id, completion_request_id),
    ADD KEY idx_enrollment_challenge_certificate (certificate_id),
    ADD CONSTRAINT fk_enrollment_challenge_certificate FOREIGN KEY (certificate_id) REFERENCES device_certificates(id);
