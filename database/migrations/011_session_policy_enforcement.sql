ALTER TABLE oidc_sessions
  ADD COLUMN expires_at DATETIME NULL AFTER auth_level,
  ADD INDEX idx_oidc_session_active(application_id,user_id,revoked_at,expires_at);

UPDATE oidc_sessions SET expires_at=DATE_ADD(created_at,INTERVAL 30 DAY) WHERE expires_at IS NULL;

ALTER TABLE oauth_refresh_tokens
  ADD COLUMN oidc_session_id BIGINT UNSIGNED NULL AFTER auth_time,
  ADD INDEX idx_refresh_session(oidc_session_id),
  ADD CONSTRAINT fk_refresh_oidc_session FOREIGN KEY(oidc_session_id) REFERENCES oidc_sessions(id) ON DELETE SET NULL;
