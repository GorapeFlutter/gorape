-- GF-10039 — Persists the verified evidence used for assurance evaluation.
--
-- The assurance level is never derived from the client-supplied platform name.
-- These columns record the verified attestation evidence so the server can
-- re-evaluate a credential when FIDO metadata status changes.
ALTER TABLE attestations
    ADD COLUMN aaguid UUID,
    ADD COLUMN assurance_level TEXT,
    ADD COLUMN hardware_protected BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN trust_source TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN attestation_certificate BYTEA,
    ADD COLUMN last_evaluated_at TIMESTAMPTZ;

ALTER TABLE attestations
    ADD CONSTRAINT attestations_assurance_level_check
    CHECK (assurance_level IS NULL OR assurance_level IN
        ('hardware_attested', 'device_bound_unattested', 'standard_passkey', 'rejected'));
