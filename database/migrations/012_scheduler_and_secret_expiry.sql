SET FOREIGN_KEY_CHECKS=0;

ALTER TABLE scheduled_jobs
  ADD COLUMN job_key VARCHAR(190) NULL AFTER id,
  ADD COLUMN last_result_json JSON NULL AFTER last_error;

UPDATE scheduled_jobs SET job_key=CONCAT('legacy:',id) WHERE job_key IS NULL;
ALTER TABLE scheduled_jobs
  MODIFY job_key VARCHAR(190) NOT NULL,
  ADD UNIQUE KEY uq_scheduled_job_key(job_key);

CREATE TABLE client_secret_expiry_notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  client_secret_id BIGINT UNSIGNED NOT NULL,
  days_before SMALLINT UNSIGNED NOT NULL,
  queued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_secret_expiry_secret FOREIGN KEY(client_secret_id) REFERENCES client_secrets(id) ON DELETE CASCADE,
  UNIQUE KEY uq_secret_expiry_threshold(client_secret_id,days_before)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO scheduled_jobs(job_key,job_type,schedule_expression,enabled,next_run_at) VALUES
 ('system:secret-expiry','secret_expiry','every:86400',1,NOW()),
 ('system:housekeeping','housekeeping','every:3600',1,NOW()),
 ('system:delivery','delivery','every:60',1,NOW()),
 ('system:mail','mail','every:60',1,NOW()),
 ('system:signing-key-rotation','signing_key_rotation','every:7776000',1,DATE_ADD(NOW(),INTERVAL 90 DAY));

SET FOREIGN_KEY_CHECKS=1;
