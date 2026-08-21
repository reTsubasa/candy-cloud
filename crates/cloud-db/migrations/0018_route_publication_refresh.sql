ALTER TABLE segment_route_publications
    ADD COLUMN expires_at BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER signed_envelope,
    ADD COLUMN stale_until BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER expires_at;
