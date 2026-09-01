ALTER TABLE runtime_telemetry_latest
    ADD COLUMN last_error_detail VARCHAR(1024) NULL AFTER last_error_code;
