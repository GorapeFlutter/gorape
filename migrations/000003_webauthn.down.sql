ALTER TABLE device_keys
    DROP COLUMN IF EXISTS credential_data;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_platform_check;

ALTER TABLE devices
    ADD CONSTRAINT devices_platform_check
    CHECK (platform IN ('android', 'windows', 'ios', 'macos'));
