<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AuditLog
{
    public function __construct(private Database $db) {}

    public function write(
        string $action,
        string $result = 'success',
        ?int $actorUserId = null,
        ?int $subjectUserId = null,
        ?int $applicationId = null,
        ?string $reason = null,
        array $metadata = []
    ): void {
        $this->db->execute(
            'INSERT INTO audit_log(actor_user_id,subject_user_id,application_id,action,result,reason,ip_address,user_agent,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)',
            [
                $actorUserId,
                $subjectUserId,
                $applicationId,
                $action,
                $result,
                $reason,
                substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 64),
                substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 500),
                $metadata === [] ? null : json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ]
        );
    }
}
