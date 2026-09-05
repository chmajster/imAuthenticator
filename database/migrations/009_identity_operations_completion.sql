SET FOREIGN_KEY_CHECKS=0;

ALTER TABLE users
  ADD COLUMN break_glass TINYINT(1) NOT NULL DEFAULT 0 AFTER is_admin,
  ADD COLUMN inactive_lock_exempt TINYINT(1) NOT NULL DEFAULT 0 AFTER break_glass;

ALTER TABLE applications
  ADD COLUMN branding_json JSON NULL AFTER icon;

CREATE TABLE email_outbox (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NULL,
  recipient VARCHAR(254) NOT NULL,
  subject VARCHAR(500) NOT NULL,
  body MEDIUMTEXT NOT NULL,
  message_type VARCHAR(80) NOT NULL DEFAULT 'notification',
  status ENUM('pending','sent','failed','dead') NOT NULL DEFAULT 'pending',
  attempt SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  next_attempt_at DATETIME NULL,
  last_error VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at DATETIME NULL,
  CONSTRAINT fk_email_outbox_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_email_outbox_pending(status,next_attempt_at,created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE email_verification_tokens (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_email_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_email_verify_email FOREIGN KEY(user_email_id) REFERENCES user_emails(id) ON DELETE CASCADE,
  INDEX idx_email_verify_active(token_hash,expires_at,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE impersonation_sessions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  actor_user_id BIGINT UNSIGNED NOT NULL,
  target_user_id BIGINT UNSIGNED NOT NULL,
  reason VARCHAR(500) NOT NULL,
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at DATETIME NULL,
  ip_address VARCHAR(64) NULL,
  CONSTRAINT fk_impersonation_actor FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_impersonation_target FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_impersonation_active(actor_user_id,ended_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_merge_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  source_user_id BIGINT UNSIGNED NULL,
  target_user_id BIGINT UNSIGNED NOT NULL,
  source_snapshot_json JSON NOT NULL,
  merged_by BIGINT UNSIGNED NOT NULL,
  merged_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_merge_target FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_merge_actor FOREIGN KEY(merged_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_import_jobs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  file_name VARCHAR(500) NOT NULL,
  format ENUM('csv','xlsx') NOT NULL,
  status ENUM('pending','processing','completed','failed') NOT NULL DEFAULT 'pending',
  created_by BIGINT UNSIGNED NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  summary_json JSON NULL,
  error_message VARCHAR(500) NULL,
  CONSTRAINT fk_import_actor FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_import_rows (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  import_job_id BIGINT UNSIGNED NOT NULL,
  row_number INT UNSIGNED NOT NULL,
  payload_json JSON NOT NULL,
  status ENUM('pending','created','updated','duplicate','failed','skipped') NOT NULL DEFAULT 'pending',
  user_id BIGINT UNSIGNED NULL,
  message VARCHAR(500) NULL,
  CONSTRAINT fk_import_row_job FOREIGN KEY(import_job_id) REFERENCES user_import_jobs(id) ON DELETE CASCADE,
  CONSTRAINT fk_import_row_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_import_row_job(import_job_id,status,row_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_category_assignments (
  application_id BIGINT UNSIGNED NOT NULL,
  category_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY(application_id,category_id),
  CONSTRAINT fk_app_category_assignment_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_category_assignment_category FOREIGN KEY(category_id) REFERENCES application_categories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_templates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(120) NOT NULL UNIQUE,
  name VARCHAR(190) NOT NULL,
  app_type VARCHAR(80) NOT NULL,
  integration_type VARCHAR(80) NOT NULL,
  defaults_json JSON NOT NULL,
  instructions MEDIUMTEXT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO application_templates(slug,name,app_type,integration_type,defaults_json,instructions) VALUES
 ('wordpress','WordPress','wordpress','wordpress_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email','roles')),'Użyj kompatybilnego pluginu OpenID Connect i skonfiguruj discovery URL imAuthenticator.'),
 ('grafana','Grafana','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email','roles')),'Skonfiguruj Generic OAuth/OIDC w Grafanie.'),
 ('gitlab','GitLab','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email','roles')),'Skonfiguruj OmniAuth OpenID Connect.'),
 ('nextcloud','Nextcloud','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email')),'Skonfiguruj klienta OpenID Connect w Nextcloud.'),
 ('wikijs','Wiki.js','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email','roles')),'Skonfiguruj strategię OpenID Connect w Wiki.js.'),
 ('jenkins','Jenkins','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email','roles')),'Skonfiguruj plugin OIDC w Jenkins.'),
 ('portainer','Portainer','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email')),'Skonfiguruj OAuth/OIDC w Portainer.'),
 ('home-assistant','Home Assistant','website','generic_oidc',JSON_OBJECT('scopes',JSON_ARRAY('openid','profile','email')),'Użyj kompatybilnego providera OIDC dla Home Assistant.');

CREATE TABLE integration_diagnostic_runs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  started_by BIGINT UNSIGNED NULL,
  status ENUM('running','success','warning','failure') NOT NULL DEFAULT 'running',
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL,
  CONSTRAINT fk_diag_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_diag_actor FOREIGN KEY(started_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE integration_diagnostic_checks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  run_id BIGINT UNSIGNED NOT NULL,
  check_name VARCHAR(190) NOT NULL,
  status ENUM('success','warning','failure','skipped') NOT NULL,
  detail VARCHAR(1000) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_diag_check_run FOREIGN KEY(run_id) REFERENCES integration_diagnostic_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE scheduled_jobs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  job_type VARCHAR(120) NOT NULL,
  resource_type VARCHAR(80) NULL,
  resource_id BIGINT UNSIGNED NULL,
  schedule_expression VARCHAR(190) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_run_at DATETIME NULL,
  next_run_at DATETIME NULL,
  last_status ENUM('never','success','failure') NOT NULL DEFAULT 'never',
  last_error VARCHAR(500) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_scheduled_due(enabled,next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE webhooks
  ADD COLUMN secret_encrypted MEDIUMTEXT NULL AFTER secret_hash,
  ADD COLUMN last_success_at DATETIME NULL AFTER enabled,
  ADD COLUMN last_failure_at DATETIME NULL AFTER last_success_at;

CREATE TABLE syslog_targets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(190) NOT NULL,
  host VARCHAR(255) NOT NULL,
  port SMALLINT UNSIGNED NOT NULL DEFAULT 514,
  transport ENUM('udp','tcp','tls') NOT NULL DEFAULT 'udp',
  minimum_severity ENUM('info','warning','high','critical') NOT NULL DEFAULT 'warning',
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_retention_checkpoints (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  deleted_through_id BIGINT UNSIGNED NOT NULL,
  deleted_count BIGINT UNSIGNED NOT NULL,
  chain_head_hash CHAR(64) NULL,
  retained_first_previous_hash CHAR(64) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS=1;
