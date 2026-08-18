ALTER TABLE runtime_telemetry_latest
    ADD COLUMN paths_json JSON NULL AFTER path_changes;

UPDATE runtime_telemetry_latest SET paths_json = JSON_ARRAY() WHERE paths_json IS NULL;

ALTER TABLE runtime_telemetry_latest
    MODIFY COLUMN paths_json JSON NOT NULL,
    ADD CONSTRAINT chk_runtime_telemetry_paths_array
        CHECK (JSON_TYPE(paths_json) = 'ARRAY' AND JSON_LENGTH(paths_json) <= 256);
