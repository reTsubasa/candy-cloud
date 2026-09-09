ALTER TABLE runtime_telemetry_latest
    ADD COLUMN failed_route_prefixes_json JSON NOT NULL DEFAULT (JSON_ARRAY());
