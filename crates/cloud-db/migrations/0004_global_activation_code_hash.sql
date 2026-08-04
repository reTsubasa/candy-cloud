ALTER TABLE enrollment_activation_codes
    DROP INDEX uq_enrollment_activation_code_hash,
    ADD UNIQUE KEY uq_enrollment_activation_code_hash (code_hash);
