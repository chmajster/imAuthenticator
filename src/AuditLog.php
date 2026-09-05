<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AuditLog
{
    public function __construct(private Database $db) {}

    public function write(string $action, string $result = 'success', ?int $actorUserId = null, ?int $subjectUserId = null, ?int $applicationId = null, ?string $reason = null, array $metadata = []): void
    {
        $ip = Security::currentIp();
        $ua = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 500);
        $organizationId = null;
        if ($applicationId !== null) {
            $app = $this->db->one('SELECT organization_id FROM applications WHERE id=?', [$applicationId]);
            $organizationId = $app && $app['organization_id'] !== null ? (int)$app['organization_id'] : null;
        }
        $createdAt = gmdate('Y-m-d H:i:s');
        $metadataJson = $metadata === [] ? null : json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $lock = $this->db->one("SELECT GET_LOCK('imauthenticator_audit_chain',5) AS l");
        try {
            $previous = $this->db->one('SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1');
            $previousHash = $previous['entry_hash'] ?? null;
            $payload = json_encode([$action,$result,$actorUserId,$subjectUserId,$applicationId,$organizationId,$reason,$ip,$ua,$metadataJson,$createdAt,$previousHash], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $entryHash = hash('sha256', $payload);
            $this->db->execute('INSERT INTO audit_log(actor_user_id,subject_user_id,application_id,organization_id,action,result,reason,ip_address,user_agent,metadata_json,previous_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', [$actorUserId,$subjectUserId,$applicationId,$organizationId,$action,$result,$reason,$ip,$ua,$metadataJson,$previousHash,$entryHash,$createdAt]);
        } finally {
            if ((int)($lock['l'] ?? 0) === 1) $this->db->one("SELECT RELEASE_LOCK('imauthenticator_audit_chain') AS l");
        }
    }
}
