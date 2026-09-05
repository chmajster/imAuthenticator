SET FOREIGN_KEY_CHECKS=0;

INSERT IGNORE INTO system_settings(setting_key,value_json) VALUES
 ('allow_private_webhook_targets','false'),
 ('external_auto_provision','false');

CREATE TABLE external_auth_states (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  identity_provider_id BIGINT UNSIGNED NOT NULL,
  state_hash CHAR(64) NOT NULL UNIQUE,
  code_verifier VARCHAR(128) NOT NULL,
  nonce VARCHAR(128) NULL,
  return_path VARCHAR(2048) NOT NULL DEFAULT '/dashboard',
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_external_state_idp FOREIGN KEY(identity_provider_id) REFERENCES identity_providers(id) ON DELETE CASCADE,
  INDEX idx_external_state_active(state_hash,expires_at,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE saml_request_replay (
  request_hash CHAR(64) PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_saml_replay_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  INDEX idx_saml_replay_expiry(expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_oauth_security (
  application_id BIGINT UNSIGNED PRIMARY KEY,
  require_par TINYINT(1) NOT NULL DEFAULT 0,
  require_pkce TINYINT(1) NOT NULL DEFAULT 0,
  require_dpop TINYINT(1) NOT NULL DEFAULT 0,
  require_mtls TINYINT(1) NOT NULL DEFAULT 0,
  jar_required TINYINT(1) NOT NULL DEFAULT 0,
  jarm_enabled TINYINT(1) NOT NULL DEFAULT 0,
  token_exchange_enabled TINYINT(1) NOT NULL DEFAULT 0,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  updated_by BIGINT UNSIGNED NULL,
  CONSTRAINT fk_oauth_sec_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_oauth_sec_actor FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE token_exchange_policies (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  source_application_id BIGINT UNSIGNED NOT NULL,
  target_application_id BIGINT UNSIGNED NOT NULL,
  allowed_scopes_json JSON NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_exchange_source FOREIGN KEY(source_application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_exchange_target FOREIGN KEY(target_application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_exchange_actor FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_exchange_pair(source_application_id,target_application_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE oauth_dpop_replay (
  jti_hash CHAR(64) PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_dpop_replay_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  INDEX idx_dpop_replay_expiry(expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE oauth_access_tokens ADD COLUMN dpop_jkt CHAR(64) NULL AFTER scopes;
ALTER TABLE oauth_refresh_tokens ADD COLUMN dpop_jkt CHAR(64) NULL AFTER scopes;

CREATE TABLE application_mtls_certificates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  thumbprint_sha256 CHAR(64) NOT NULL,
  subject_dn VARCHAR(1000) NULL,
  valid_from DATETIME NULL,
  valid_until DATETIME NULL,
  revoked_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_mtls_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  UNIQUE KEY uq_mtls_thumbprint(application_id,thumbprint_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_client_jwks (
  application_id BIGINT UNSIGNED PRIMARY KEY,
  jwks_json JSON NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_client_jwks_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE scim_connectors ADD COLUMN bearer_token_encrypted MEDIUMTEXT NULL AFTER bearer_token_hash;

SET FOREIGN_KEY_CHECKS=1;
