ALTER TABLE runtime_upgrade_jobs
    ADD COLUMN phase VARCHAR(32) NOT NULL DEFAULT 'pending' AFTER state;

UPDATE runtime_upgrade_jobs
SET phase = CASE state
    WHEN 'pending' THEN 'pending'
    WHEN 'running' THEN 'running'
    WHEN 'succeeded' THEN 'succeeded'
    WHEN 'failed' THEN 'failed'
    WHEN 'expired' THEN 'expired'
    ELSE state
END;

ALTER TABLE runtime_upgrade_jobs
    ADD CONSTRAINT upgrade_job_phase_valid CHECK (phase IN (
        'pending', 'prepared', 'running', 'executing', 'verifying',
        'installing', 'health_check', 'succeeded', 'failed', 'rolled_back', 'expired'
    ));
