ALTER TABLE runtime_upgrade_jobs
    ADD COLUMN error_detail VARCHAR(512) NULL AFTER error_code,
    ADD CONSTRAINT upgrade_job_error_detail_failed_only CHECK (
        error_detail IS NULL OR (
            state = 'failed' AND CHAR_LENGTH(error_detail) BETWEEN 1 AND 512
        )
    );
