SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE system_settings (
  setting_key VARCHAR(190) PRIMARY KEY,
  value_json JSON NOT NULL,
  updated_by BIGINT UNSIGNED NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_system_setting_actor FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO system_settings(setting_key,value_json) VALUES
 ('maintenance_mode','false'),
 ('external_login_emergency_disabled','false'),
 ('announcement_banner','null'),
 ('inactive_account_days','90'),
 ('audit_retention_days','365');

CREATE TABLE magic_login_tokens (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  return_path VARCHAR(2048) NULL,
  requested_ip VARCHAR(64) NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_magic_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_magic_active(token_hash,expires_at,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_emails (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  email VARCHAR(254) NOT NULL UNIQUE,
  is_primary TINYINT(1) NOT NULL DEFAULT 0,
  verified_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_user_email_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_email_lookup(email,user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO user_emails(user_id,email,is_primary,verified_at)
SELECT id,email,1,NOW() FROM users;

ALTER TABLE applications
  ADD COLUMN require_user_consent TINYINT(1) NOT NULL DEFAULT 0 AFTER access_policy;

CREATE TABLE user_application_consents (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  application_id BIGINT UNSIGNED NOT NULL,
  scopes_json JSON NOT NULL,
  granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME NULL,
  last_used_at DATETIME NULL,
  CONSTRAINT fk_consent_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_consent_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  UNIQUE KEY uq_user_app_consent(user_id,application_id),
  INDEX idx_consent_active(application_id,revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE webhook_deliveries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  webhook_id BIGINT UNSIGNED NOT NULL,
  event_outbox_id BIGINT UNSIGNED NOT NULL,
  attempt SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  status ENUM('pending','success','failure','dead') NOT NULL DEFAULT 'pending',
  response_code SMALLINT UNSIGNED NULL,
  error_message VARCHAR(500) NULL,
  next_attempt_at DATETIME NULL,
  delivered_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_webhook_delivery_hook FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
  CONSTRAINT fk_webhook_delivery_event FOREIGN KEY(event_outbox_id) REFERENCES event_outbox(id) ON DELETE CASCADE,
  UNIQUE KEY uq_webhook_event_attempt(webhook_id,event_outbox_id,attempt),
  INDEX idx_webhook_delivery_retry(status,next_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE alert_rules (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(190) NOT NULL,
  event_type VARCHAR(120) NOT NULL,
  minimum_severity ENUM('info','warning','high','critical') NOT NULL DEFAULT 'warning',
  channel ENUM('email','webhook','both') NOT NULL DEFAULT 'email',
  destination VARCHAR(2048) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_alert_rule_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_alert_rule_event(event_type,enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE alert_deliveries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  alert_rule_id BIGINT UNSIGNED NOT NULL,
  event_outbox_id BIGINT UNSIGNED NOT NULL,
  status ENUM('success','failure') NOT NULL,
  error_message VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_alert_delivery_rule FOREIGN KEY(alert_rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
  CONSTRAINT fk_alert_delivery_event FOREIGN KEY(event_outbox_id) REFERENCES event_outbox(id) ON DELETE CASCADE,
  UNIQUE KEY uq_alert_event(alert_rule_id,event_outbox_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS=1;
