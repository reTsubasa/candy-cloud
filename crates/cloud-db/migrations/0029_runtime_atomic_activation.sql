-- Existing generations were delivered before the prepare/commit barrier. Keep
-- them active and mark their rollout complete while enabling the new phases.
ALTER TABLE runtime_configuration_rollouts
    MODIFY COLUMN state ENUM('ACTIVE','PREPARING','COMMITTING','BLOCKED','COMPLETE') NOT NULL;

UPDATE runtime_configuration_rollouts
SET state = 'COMPLETE'
WHERE state = 'ACTIVE';

ALTER TABLE runtime_configuration_rollouts
    MODIFY COLUMN state ENUM('PREPARING','COMMITTING','BLOCKED','COMPLETE') NOT NULL;

-- MySQL assigns an implementation-defined name to the original anonymous
-- CHECK constraint, so resolve it from information_schema before replacing it.
SET @runtime_status_check = (
    SELECT tc.CONSTRAINT_NAME
    FROM information_schema.TABLE_CONSTRAINTS tc
    JOIN information_schema.CHECK_CONSTRAINTS cc
      ON cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
     AND cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
    WHERE tc.CONSTRAINT_SCHEMA = DATABASE()
      AND tc.TABLE_NAME = 'runtime_configuration_status'
      AND tc.CONSTRAINT_TYPE = 'CHECK'
      AND cc.CHECK_CLAUSE LIKE '%apply_state%'
    LIMIT 1
);
SET @drop_runtime_status_check = IF(
    @runtime_status_check IS NULL,
    'SELECT 1',
    CONCAT('ALTER TABLE runtime_configuration_status DROP CHECK `', @runtime_status_check, '`')
);
PREPARE runtime_status_statement FROM @drop_runtime_status_check;
EXECUTE runtime_status_statement;
DEALLOCATE PREPARE runtime_status_statement;

ALTER TABLE runtime_configuration_status
    MODIFY COLUMN apply_state ENUM('PREPARED','ACTIVE','REJECTED') NOT NULL,
    ADD CONSTRAINT chk_runtime_configuration_result CHECK (
        (apply_state IN ('PREPARED','ACTIVE') AND error_code IS NULL)
        OR (apply_state = 'REJECTED' AND error_code IS NOT NULL)
    );
