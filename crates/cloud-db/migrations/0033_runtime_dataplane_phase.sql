ALTER TABLE runtime_telemetry_latest
    ADD COLUMN dataplane_phase VARCHAR(40) NULL AFTER lifecycle;
