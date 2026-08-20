ALTER TABLE runtime_telemetry_latest
    ADD COLUMN local_networks_json JSON NOT NULL DEFAULT (JSON_ARRAY()) AFTER paths_json,
    ADD CONSTRAINT chk_runtime_telemetry_local_networks_array
        CHECK (
            JSON_TYPE(local_networks_json) = 'ARRAY'
            AND JSON_LENGTH(local_networks_json) <= 64
        );
