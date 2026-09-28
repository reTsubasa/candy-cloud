-- The latest legacy tenant setting was copied into the platform singleton by
-- 0053_geo_provider_platform.sql. Geo data is deployment-wide, so retaining a
-- tenant-keyed settings table would allow the schema to imply a false scope.
DROP TABLE IF EXISTS geo_provider_settings;
