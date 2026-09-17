ALTER TABLE runtime_telemetry_latest
    ADD COLUMN tunnel_generation BIGINT UNSIGNED NULL AFTER runtime_generation,
    ADD COLUMN policy_generation BIGINT UNSIGNED NULL AFTER tunnel_generation;

UPDATE runtime_telemetry_latest
SET tunnel_generation = runtime_generation,
    policy_generation = runtime_generation
WHERE runtime_generation IS NOT NULL;
