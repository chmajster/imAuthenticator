ALTER TABLE oidc_sessions
  ADD COLUMN expires_at DATETIME NULL AFTER auth_level,
  ADD INDEX idx_oidc_session_active(application_id,user_id,revoked_at,expires_at);

UPDATE oidc_sessions SET expires_at=DATE_ADD(created_at,INTERVAL 30 DAY) WHERE expires_at IS NULL;
