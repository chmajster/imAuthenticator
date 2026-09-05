ALTER TABLE oauth_authorization_codes
  ADD COLUMN auth_level TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER nonce,
  ADD COLUMN auth_time DATETIME NULL AFTER auth_level;

ALTER TABLE oauth_refresh_tokens
  ADD COLUMN auth_level TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER scopes,
  ADD COLUMN auth_time DATETIME NULL AFTER auth_level;

ALTER TABLE oidc_sessions
  ADD COLUMN auth_level TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER user_id;
