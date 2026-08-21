-- Every tenant must have explicit authorization and revocation generations.
-- Grant issuance joins these rows and deliberately denies when either baseline
-- is absent; older tenant creation paths did not persist the baseline.
INSERT INTO authorization_generations (tenant_id, generation)
SELECT t.id, 1
FROM tenants t
LEFT JOIN authorization_generations ag ON ag.tenant_id = t.id
WHERE ag.tenant_id IS NULL;

INSERT INTO revocation_generations (tenant_id, generation)
SELECT t.id, 1
FROM tenants t
LEFT JOIN revocation_generations rg ON rg.tenant_id = t.id
WHERE rg.tenant_id IS NULL;

INSERT INTO policies (tenant_id, generation, policy_json)
SELECT t.id, 1, JSON_OBJECT()
FROM tenants t
LEFT JOIN policies p ON p.tenant_id = t.id
WHERE p.tenant_id IS NULL;
