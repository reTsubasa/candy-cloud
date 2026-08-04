ALTER TABLE segment_expansion_publications
    MODIFY COLUMN object_kind ENUM(
        'SHARED_HUB_ADMISSION',
        'MESH_MEMBERSHIP',
        'DYNAMIC_ROUTE_SNAPSHOT',
        'FABRIC_ASSIGNMENT'
    ) NOT NULL;
