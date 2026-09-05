ALTER TABLE oauth_access_tokens DROP FOREIGN KEY fk_at_user;
ALTER TABLE oauth_access_tokens MODIFY user_id BIGINT UNSIGNED NULL;
ALTER TABLE oauth_access_tokens ADD CONSTRAINT fk_at_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL;
