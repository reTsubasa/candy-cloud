CREATE TABLE identity_abuse_buckets (
    scope VARCHAR(48) NOT NULL,
    subject_hash BINARY(32) NOT NULL,
    attempts INT UNSIGNED NOT NULL,
    window_started_at TIMESTAMP(6) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (scope, subject_hash),
    KEY idx_identity_abuse_buckets_expiry (expires_at)
) ENGINE=InnoDB;
