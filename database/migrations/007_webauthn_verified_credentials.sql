ALTER TABLE webauthn_credentials
  ADD COLUMN attestation_type VARCHAR(64) NOT NULL DEFAULT 'none' AFTER transports_json,
  ADD COLUMN uv_initialized TINYINT(1) NOT NULL DEFAULT 1 AFTER backup_state;
