ALTER TABLE runtime_telemetry_latest
    ADD COLUMN route_diagnostics_json JSON NULL AFTER failed_route_prefixes_json;
