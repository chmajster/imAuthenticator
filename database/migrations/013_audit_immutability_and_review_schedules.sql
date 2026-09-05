SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE access_review_schedules (
  application_id BIGINT UNSIGNED PRIMARY KEY,
  reviewer_user_id BIGINT UNSIGNED NOT NULL,
  interval_days SMALLINT UNSIGNED NOT NULL DEFAULT 90,
  due_days SMALLINT UNSIGNED NOT NULL DEFAULT 14,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_review_id BIGINT UNSIGNED NULL,
  last_run_at DATETIME NULL,
  next_run_at DATETIME NOT NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_review_schedule_app FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE,
  CONSTRAINT fk_review_schedule_reviewer FOREIGN KEY(reviewer_user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_review_schedule_review FOREIGN KEY(last_review_id) REFERENCES access_reviews(id) ON DELETE SET NULL,
  CONSTRAINT fk_review_schedule_creator FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_review_schedule_due(enabled,next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

DROP TRIGGER IF EXISTS trg_audit_log_no_update;
DROP TRIGGER IF EXISTS trg_audit_log_no_delete;

DELIMITER //
CREATE TRIGGER trg_audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit_log entries are immutable';
END//

CREATE TRIGGER trg_audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
  IF COALESCE(@imauth_allow_audit_delete,0) <> 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit_log deletion is allowed only by retention housekeeping';
  END IF;
END//
DELIMITER ;

SET FOREIGN_KEY_CHECKS=1;
