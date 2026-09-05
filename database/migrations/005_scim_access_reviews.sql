CREATE TABLE scim_group_mappings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scim_connector_id BIGINT UNSIGNED NOT NULL,
  external_group_id VARCHAR(512) NOT NULL,
  display_name VARCHAR(190) NOT NULL,
  app_role_id BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_scim_group_connector FOREIGN KEY(scim_connector_id) REFERENCES scim_connectors(id) ON DELETE CASCADE,
  CONSTRAINT fk_scim_group_role FOREIGN KEY(app_role_id) REFERENCES app_roles(id) ON DELETE SET NULL,
  UNIQUE KEY uq_scim_group_external(scim_connector_id,external_group_id(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE access_reviews
  ADD COLUMN created_by BIGINT UNSIGNED NULL AFTER reviewer_user_id,
  ADD CONSTRAINT fk_access_review_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL;
