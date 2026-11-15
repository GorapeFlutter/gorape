-- GF-10026 — Adds persisted WebAuthn credential state and web/Linux platform values.
ALTER TABLE device_keys
    ADD COLUMN credential_data JSONB;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_platform_check;

ALTER TABLE devices
    ADD CONSTRAINT devices_platform_check
    CHECK (platform IN ('android', 'windows', 'ios', 'macos', 'web', 'linux'));
