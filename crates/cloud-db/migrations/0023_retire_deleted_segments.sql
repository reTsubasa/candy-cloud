UPDATE segments segment
JOIN sdwan_control_resources control_segment
  ON control_segment.tenant_id = segment.tenant_id
 AND control_segment.resource_kind = 'SEGMENT'
 AND control_segment.id = segment.id
 AND control_segment.state = 'DELETED'
SET segment.state = 'DELETED'
WHERE segment.state <> 'DELETED';

UPDATE segment_generation_jobs job
JOIN sdwan_control_resources control_segment
  ON control_segment.tenant_id = job.tenant_id
 AND control_segment.resource_kind = 'SEGMENT'
 AND control_segment.id = job.segment_id
 AND control_segment.state = 'DELETED'
SET job.state = 'PERMANENT_FAILURE',
    job.lease_owner = NULL,
    job.lease_until = NULL,
    job.published_generation = NULL,
    job.published_content_hash = NULL,
    job.last_error_code = 'SEGMENT_DELETED'
WHERE job.state IN ('PENDING','LEASED','RETRY');

UPDATE segment_generation_jobs job
JOIN segment_generation_heads head
  ON head.tenant_id = job.tenant_id
 AND head.segment_id = job.segment_id
 AND head.desired_revision = job.desired_revision
JOIN sdwan_control_resources control_segment
  ON control_segment.tenant_id = job.tenant_id
 AND control_segment.resource_kind = 'SEGMENT'
 AND control_segment.id = job.segment_id
 AND control_segment.state = 'DELETED'
SET job.last_error_code = 'SEGMENT_DELETED'
WHERE job.state = 'PERMANENT_FAILURE';
