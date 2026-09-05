SET FOREIGN_KEY_CHECKS=0;

ALTER TABLE applications
  ADD COLUMN frontchannel_logout_uri VARCHAR(2048) NULL AFTER logout_url,
  ADD COLUMN backchannel_logout_uri VARCHAR(2048) NULL AFTER frontchannel_logout_uri,
  ADD COLUMN backchannel_logout_session_required TINYINT(1) NOT NULL DEFAULT 1 AFTER backchannel_logout_uri;

CREATE TABLE oauth_device_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NULL,
  device_code_hash CHAR(64) NOT NULL UNIQUE,
  user_code_hash CHAR(64) NOT NULL UNIQUE,
  user_code_display VARCHAR(32) NOT NULL,
  scopes TEXT NOT NULL,
  status ENUM('pending','authorized','denied','consumed') NOT NULL DEFAULT 'pending',
  interval_seconds SMALLINT UNSIGNED NOT NULL DEFAULT 5,
  poll_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_polled_at DATETIME NULL,
  auth_level TINYINT UNSIGNED NULL,
  auth_time DATETIME NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  authorized_at DATETIME NULL,
  consumed_at DATETIME NULL,
  CONSTRAINT fk_device_code_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_device_code_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_device_code_user_code(user_code_hash,status,expires_at),
  INDEX idx_device_code_poll(device_code_hash,status,expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE oauth_par_requests (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  request_uri_hash CHAR(64) NOT NULL UNIQUE,
  params_json JSON NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_par_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  INDEX idx_par_active(request_uri_hash,expires_at,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE dynamic_registration_tokens (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(190) NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  allowed_domains_json JSON NULL,
  valid_until DATETIME NULL,
  revoked_at DATETIME NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  CONSTRAINT fk_dcr_token_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_dcr_token_active(token_hash,valid_until,revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE logout_deliveries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NULL,
  sid CHAR(64) NULL,
  channel ENUM('front','back') NOT NULL,
  endpoint_url VARCHAR(2048) NOT NULL,
  status ENUM('pending','success','failure','skipped') NOT NULL DEFAULT 'pending',
  response_code SMALLINT UNSIGNED NULL,
  error_message VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delivered_at DATETIME NULL,
  CONSTRAINT fk_logout_delivery_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_logout_delivery_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_logout_delivery_status(status,created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS=1;
