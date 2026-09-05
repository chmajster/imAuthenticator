SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE organizations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  name VARCHAR(190) NOT NULL,
  slug VARCHAR(190) NOT NULL UNIQUE,
  status ENUM('active','suspended','disabled') NOT NULL DEFAULT 'active',
  settings_json JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE organization_memberships (
  organization_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  role ENUM('owner','admin','member','viewer') NOT NULL DEFAULT 'member',
  status ENUM('active','pending','suspended','expired') NOT NULL DEFAULT 'active',
  valid_from DATETIME NULL,
  valid_until DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  PRIMARY KEY(organization_id,user_id),
  CONSTRAINT fk_org_member_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  CONSTRAINT fk_org_member_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_org_member_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_org_membership_user(user_id,status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE users
  ADD COLUMN username VARCHAR(190) NULL AFTER name,
  ADD COLUMN lifecycle_status ENUM('pending','active','suspended','disabled','expired') NOT NULL DEFAULT 'active' AFTER enabled,
  ADD COLUMN account_starts_at DATETIME NULL AFTER lifecycle_status,
  ADD COLUMN account_ends_at DATETIME NULL AFTER account_starts_at,
  ADD COLUMN last_login_at DATETIME NULL AFTER account_ends_at,
  ADD COLUMN last_activity_at DATETIME NULL AFTER last_login_at,
  ADD UNIQUE KEY uq_users_username(username);

ALTER TABLE applications
  ADD COLUMN organization_id BIGINT UNSIGNED NULL AFTER id,
  ADD COLUMN status_message VARCHAR(500) NULL AFTER last_used_at,
  ADD COLUMN maintenance_mode TINYINT(1) NOT NULL DEFAULT 0 AFTER status_message,
  ADD COLUMN session_ttl_seconds INT UNSIGNED NULL AFTER maintenance_mode,
  ADD COLUMN max_concurrent_sessions SMALLINT UNSIGNED NULL AFTER session_ttl_seconds,
  ADD CONSTRAINT fk_app_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
  ADD INDEX idx_app_org(organization_id,enabled,deleted_at);

CREATE TABLE application_owners (
  application_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  is_primary TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  PRIMARY KEY(application_id,user_id),
  CONSTRAINT fk_app_owner_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_owner_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_owner_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_admins (
  application_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  permissions_json JSON NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  PRIMARY KEY(application_id,user_id),
  CONSTRAINT fk_app_admin_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_admin_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_admin_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE application_users
  ADD COLUMN valid_from DATETIME NULL AFTER enabled,
  ADD COLUMN valid_until DATETIME NULL AFTER valid_from,
  ADD COLUMN grant_source ENUM('manual','request','dynamic','scim','sync','system') NOT NULL DEFAULT 'manual' AFTER valid_until,
  ADD COLUMN revoked_at DATETIME NULL AFTER grant_source,
  ADD COLUMN revoke_reason VARCHAR(500) NULL AFTER revoked_at;

CREATE TABLE access_requests (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  application_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  requested_role_id BIGINT UNSIGNED NULL,
  justification TEXT NULL,
  requested_duration_seconds INT UNSIGNED NULL,
  status ENUM('pending','approved','denied','cancelled','expired') NOT NULL DEFAULT 'pending',
  decided_by BIGINT UNSIGNED NULL,
  decision_reason TEXT NULL,
  decided_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NULL,
  CONSTRAINT fk_access_req_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_access_req_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_access_req_role FOREIGN KEY(requested_role_id) REFERENCES app_roles(id) ON DELETE SET NULL,
  CONSTRAINT fk_access_req_decider FOREIGN KEY(decided_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_access_req_queue(application_id,status,created_at),
  INDEX idx_access_req_user(user_id,status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE dynamic_access_rules (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(190) NOT NULL,
  rule_type ENUM('group','system_role','attribute','ip','network_zone','country','time','compound') NOT NULL,
  effect ENUM('allow','deny','require_mfa','require_step_up') NOT NULL DEFAULT 'allow',
  priority INT NOT NULL DEFAULT 100,
  condition_json JSON NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  CONSTRAINT fk_dynamic_rule_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_dynamic_rule_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_dynamic_rule_eval(application_id,enabled,priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_attributes (
  user_id BIGINT UNSIGNED NOT NULL,
  attribute_key VARCHAR(120) NOT NULL,
  attribute_value TEXT NULL,
  source ENUM('manual','ldap','scim','oidc','saml','system') NOT NULL DEFAULT 'manual',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,attribute_key),
  CONSTRAINT fk_user_attr_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_attr_lookup(attribute_key(80),attribute_value(120))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_security_policies (
  application_id BIGINT UNSIGNED PRIMARY KEY,
  require_mfa TINYINT(1) NOT NULL DEFAULT 0,
  minimum_auth_level TINYINT UNSIGNED NOT NULL DEFAULT 1,
  require_trusted_device TINYINT(1) NOT NULL DEFAULT 0,
  block_new_devices TINYINT(1) NOT NULL DEFAULT 0,
  risk_threshold TINYINT UNSIGNED NOT NULL DEFAULT 100,
  allowed_countries_json JSON NULL,
  denied_countries_json JSON NULL,
  ip_allowlist_json JSON NULL,
  ip_denylist_json JSON NULL,
  network_zones_json JSON NULL,
  access_hours_json JSON NULL,
  force_reauth_seconds INT UNSIGNED NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  updated_by BIGINT UNSIGNED NULL,
  CONSTRAINT fk_app_sec_policy_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_app_sec_policy_user FOREIGN KEY(updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE role_security_policies (
  system_role_id BIGINT UNSIGNED PRIMARY KEY,
  require_mfa TINYINT(1) NOT NULL DEFAULT 0,
  minimum_auth_level TINYINT UNSIGNED NOT NULL DEFAULT 1,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_role_sec_role FOREIGN KEY(system_role_id) REFERENCES system_roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE webauthn_credentials (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  credential_id VARBINARY(1024) NOT NULL,
  public_key_cose BLOB NOT NULL,
  sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  transports_json JSON NULL,
  aaguid CHAR(36) NULL,
  name VARCHAR(190) NULL,
  backup_eligible TINYINT(1) NOT NULL DEFAULT 0,
  backup_state TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  revoked_at DATETIME NULL,
  CONSTRAINT fk_webauthn_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_webauthn_cred(credential_id(255)),
  INDEX idx_webauthn_user(user_id,revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE authentication_challenges (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NULL,
  challenge_hash CHAR(64) NOT NULL UNIQUE,
  purpose ENUM('webauthn_register','webauthn_login','step_up','magic_link','mfa') NOT NULL,
  context_json JSON NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_challenge_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_auth_challenge_active(purpose,expires_at,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE mfa_methods (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  method ENUM('passkey','totp','email','backup_code','external') NOT NULL,
  label VARCHAR(190) NULL,
  secret_encrypted TEXT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  CONSTRAINT fk_mfa_method_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_mfa_user(user_id,enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE backup_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  used_at DATETIME NULL,
  CONSTRAINT fk_backup_code_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_backup_code_user(user_id,used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_devices (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  user_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(190) NULL,
  fingerprint_hash CHAR(64) NULL,
  platform VARCHAR(120) NULL,
  browser VARCHAR(120) NULL,
  trusted TINYINT(1) NOT NULL DEFAULT 0,
  trusted_until DATETIME NULL,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_ip VARCHAR(64) NULL,
  revoked_at DATETIME NULL,
  CONSTRAINT fk_device_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_device_user(user_id,revoked_at,last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE login_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NULL,
  application_id BIGINT UNSIGNED NULL,
  event_type ENUM('login_success','login_failure','mfa_success','mfa_failure','step_up','risk_denied','logout') NOT NULL,
  ip_address VARCHAR(64) NULL,
  country_code CHAR(2) NULL,
  latitude DECIMAL(9,6) NULL,
  longitude DECIMAL(9,6) NULL,
  device_id BIGINT UNSIGNED NULL,
  risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
  risk_reasons_json JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_login_event_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_login_event_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE SET NULL,
  CONSTRAINT fk_login_event_device FOREIGN KEY(device_id) REFERENCES user_devices(id) ON DELETE SET NULL,
  INDEX idx_login_event_user(user_id,created_at),
  INDEX idx_login_event_risk(risk_score,created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE identity_providers (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  name VARCHAR(190) NOT NULL,
  provider_type ENUM('oidc','saml','entra','google','github','ldap','active_directory') NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  config_json JSON NOT NULL,
  secrets_encrypted MEDIUMTEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_idp_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  INDEX idx_idp_org(organization_id,provider_type,enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE external_identities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  identity_provider_id BIGINT UNSIGNED NOT NULL,
  external_subject VARCHAR(512) NOT NULL,
  external_username VARCHAR(512) NULL,
  profile_json JSON NULL,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_ext_identity_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_ext_identity_idp FOREIGN KEY(identity_provider_id) REFERENCES identity_providers(id) ON DELETE CASCADE,
  UNIQUE KEY uq_ext_identity(identity_provider_id,external_subject(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE directory_sync_runs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  identity_provider_id BIGINT UNSIGNED NOT NULL,
  status ENUM('running','success','partial','failed') NOT NULL DEFAULT 'running',
  users_created INT UNSIGNED NOT NULL DEFAULT 0,
  users_updated INT UNSIGNED NOT NULL DEFAULT 0,
  users_disabled INT UNSIGNED NOT NULL DEFAULT 0,
  groups_updated INT UNSIGNED NOT NULL DEFAULT 0,
  error_summary TEXT NULL,
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME NULL,
  CONSTRAINT fk_sync_run_idp FOREIGN KEY(identity_provider_id) REFERENCES identity_providers(id) ON DELETE CASCADE,
  INDEX idx_sync_run_idp(identity_provider_id,started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_saml_settings (
  application_id BIGINT UNSIGNED PRIMARY KEY,
  entity_id VARCHAR(2048) NOT NULL,
  acs_url VARCHAR(2048) NOT NULL,
  slo_url VARCHAR(2048) NULL,
  name_id_format VARCHAR(255) NULL,
  sign_assertions TINYINT(1) NOT NULL DEFAULT 1,
  encrypt_assertions TINYINT(1) NOT NULL DEFAULT 0,
  metadata_xml MEDIUMTEXT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_saml_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE scim_connectors (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  base_url VARCHAR(2048) NULL,
  direction ENUM('inbound','outbound') NOT NULL DEFAULT 'outbound',
  bearer_token_hash VARCHAR(255) NULL,
  mapping_json JSON NULL,
  last_sync_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_scim_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE client_secrets (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  secret_hash VARCHAR(255) NOT NULL,
  secret_hint VARCHAR(32) NULL,
  valid_from DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  valid_until DATETIME NULL,
  revoked_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  CONSTRAINT fk_client_secret_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_client_secret_user FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_client_secret_active(application_id,valid_until,revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE signing_keys (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  kid VARCHAR(120) NOT NULL UNIQUE,
  algorithm VARCHAR(32) NOT NULL DEFAULT 'RS256',
  public_key_pem MEDIUMTEXT NOT NULL,
  private_key_ref VARCHAR(2048) NOT NULL,
  storage_provider ENUM('file','vault','aws_kms','azure_key_vault','hsm') NOT NULL DEFAULT 'file',
  status ENUM('active','retiring','retired','revoked') NOT NULL DEFAULT 'active',
  not_before DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  not_after DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  retired_at DATETIME NULL,
  INDEX idx_signing_key_status(status,not_before,not_after)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE service_accounts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  uuid CHAR(36) NOT NULL UNIQUE,
  name VARCHAR(190) NOT NULL,
  description TEXT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by BIGINT UNSIGNED NULL,
  CONSTRAINT fk_service_account_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  CONSTRAINT fk_service_account_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE api_keys (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  service_account_id BIGINT UNSIGNED NOT NULL,
  key_hash CHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(24) NOT NULL,
  scopes_json JSON NULL,
  valid_until DATETIME NULL,
  last_used_at DATETIME NULL,
  revoked_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_api_key_sa FOREIGN KEY(service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE claims_mappings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  claim_name VARCHAR(120) NOT NULL,
  source_type ENUM('standard','attribute','role','static') NOT NULL,
  source_key VARCHAR(190) NULL,
  static_value TEXT NULL,
  include_in_id_token TINYINT(1) NOT NULL DEFAULT 1,
  include_in_userinfo TINYINT(1) NOT NULL DEFAULT 1,
  required_scope VARCHAR(80) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_claim_map_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  UNIQUE KEY uq_claim_map(application_id,claim_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE access_reviews (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(190) NOT NULL,
  reviewer_user_id BIGINT UNSIGNED NULL,
  status ENUM('draft','active','completed','cancelled') NOT NULL DEFAULT 'draft',
  due_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  CONSTRAINT fk_access_review_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_access_review_reviewer FOREIGN KEY(reviewer_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE access_review_items (
  access_review_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  decision ENUM('pending','keep','revoke') NOT NULL DEFAULT 'pending',
  decided_by BIGINT UNSIGNED NULL,
  decided_at DATETIME NULL,
  note TEXT NULL,
  PRIMARY KEY(access_review_id,user_id),
  CONSTRAINT fk_review_item_review FOREIGN KEY(access_review_id) REFERENCES access_reviews(id) ON DELETE CASCADE,
  CONSTRAINT fk_review_item_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_review_item_decider FOREIGN KEY(decided_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE application_categories (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  name VARCHAR(120) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  CONSTRAINT fk_app_category_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  UNIQUE KEY uq_app_category(organization_id,name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_application_preferences (
  user_id BIGINT UNSIGNED NOT NULL,
  application_id BIGINT UNSIGNED NOT NULL,
  favorite TINYINT(1) NOT NULL DEFAULT 0,
  sort_order INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,application_id),
  CONSTRAINT fk_user_app_pref_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_app_pref_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE webhooks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  url VARCHAR(2048) NOT NULL,
  secret_hash VARCHAR(255) NULL,
  events_json JSON NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_webhook_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE event_outbox (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_uuid CHAR(36) NOT NULL UNIQUE,
  organization_id BIGINT UNSIGNED NULL,
  event_type VARCHAR(120) NOT NULL,
  payload_json JSON NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  published_at DATETIME NULL,
  CONSTRAINT fk_event_outbox_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
  INDEX idx_event_outbox_pending(published_at,created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE security_integrations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  integration_type ENUM('syslog','splunk','graylog','elastic','sentinel','webhook','email') NOT NULL,
  name VARCHAR(190) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  config_json JSON NOT NULL,
  secrets_encrypted MEDIUMTEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_security_integration_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE legal_documents (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  organization_id BIGINT UNSIGNED NULL,
  document_type ENUM('terms','privacy') NOT NULL,
  version VARCHAR(64) NOT NULL,
  content MEDIUMTEXT NOT NULL,
  required TINYINT(1) NOT NULL DEFAULT 1,
  effective_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_legal_doc_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  UNIQUE KEY uq_legal_version(organization_id,document_type,version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_legal_acceptances (
  user_id BIGINT UNSIGNED NOT NULL,
  legal_document_id BIGINT UNSIGNED NOT NULL,
  accepted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ip_address VARCHAR(64) NULL,
  PRIMARY KEY(user_id,legal_document_id),
  CONSTRAINT fk_legal_accept_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_legal_accept_doc FOREIGN KEY(legal_document_id) REFERENCES legal_documents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE required_actions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  action_type ENUM('change_password','setup_mfa','accept_terms','accept_privacy','verify_email','admin_review') NOT NULL,
  status ENUM('pending','completed','waived') NOT NULL DEFAULT 'pending',
  payload_json JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  CONSTRAINT fk_required_action_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_required_action_user(user_id,status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE audit_log
  ADD COLUMN organization_id BIGINT UNSIGNED NULL AFTER application_id,
  ADD COLUMN previous_hash CHAR(64) NULL AFTER metadata_json,
  ADD COLUMN entry_hash CHAR(64) NULL AFTER previous_hash,
  ADD CONSTRAINT fk_audit_org FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
  ADD INDEX idx_audit_org(organization_id,created_at),
  ADD INDEX idx_audit_hash(entry_hash);

SET FOREIGN_KEY_CHECKS=1;
