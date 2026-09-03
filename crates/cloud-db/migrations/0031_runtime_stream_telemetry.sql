ALTER TABLE runtime_telemetry_latest
    ADD COLUMN transport_mode VARCHAR(32) NULL AFTER path_changes,
    ADD COLUMN runtime_generation BIGINT UNSIGNED NULL AFTER transport_mode;
