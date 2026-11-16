ALTER TABLE attestations
    DROP CONSTRAINT IF EXISTS attestations_assurance_level_check;

ALTER TABLE attestations
    DROP COLUMN IF EXISTS last_evaluated_at,
    DROP COLUMN IF EXISTS attestation_certificate,
    DROP COLUMN IF EXISTS trust_source,
    DROP COLUMN IF EXISTS backup_state,
    DROP COLUMN IF EXISTS backup_eligible,
    DROP COLUMN IF EXISTS hardware_protected,
    DROP COLUMN IF EXISTS assurance_level,
    DROP COLUMN IF EXISTS aaguid;
