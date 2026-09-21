ALTER TABLE segment_generation_jobs
    ADD COLUMN activation_mode ENUM('TUNNEL','POLICY_ONLY') NOT NULL DEFAULT 'TUNNEL'
        AFTER idempotency_hash;

ALTER TABLE segment_route_publications
    ADD COLUMN activation_mode ENUM('TUNNEL','POLICY_ONLY') NOT NULL DEFAULT 'TUNNEL'
        AFTER generation;

ALTER TABLE runtime_configuration_rollouts
    ADD COLUMN activation_mode ENUM('TUNNEL','POLICY_ONLY') NOT NULL DEFAULT 'TUNNEL'
        AFTER member_count;
