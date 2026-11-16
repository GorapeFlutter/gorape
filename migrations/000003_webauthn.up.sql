-- GF-10026 — Adds persisted WebAuthn credential state and web/Linux platform values.
ALTER TABLE device_keys
    ADD COLUMN credential_data JSONB;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_platform_check;

ALTER TABLE devices
    ADD CONSTRAINT devices_platform_check
    CHECK (platform IN ('android', 'windows', 'ios', 'macos', 'web', 'linux'));

ALTER TABLE projects
    DROP CONSTRAINT IF EXISTS projects_issuer_check;

ALTER TABLE projects
    ADD CONSTRAINT projects_issuer_check
    CHECK (issuer ~ '^https://' OR issuer ~ '^http://(localhost|127[.]0[.]0[.]1|([a-z0-9-]+[.])*gorapeflutter[.]site)(:[0-9]+)?/');
