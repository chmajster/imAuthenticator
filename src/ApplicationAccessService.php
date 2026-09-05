<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ApplicationAccessService
{
    public function __construct(private Database $db, private AuditLog $audit) {}

    public function hasAccess(int $userId, array|int $application): bool
    {
        $app = is_array($application)
            ? $application
            : $this->db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$application]);

        if (!$app || !(bool)$app['enabled']) return false;

        $user = $this->db->one('SELECT id,enabled FROM users WHERE id=?', [$userId]);
        if (!$user || !(bool)$user['enabled']) return false;

        return match ($app['access_policy']) {
            'all' => true,
            'users' => $this->directUserAccess($userId, (int)$app['id']),
            'groups' => $this->groupAccess($userId, (int)$app['id']),
            'roles' => $this->systemRoleAccess($userId, (int)$app['id']),
            'mixed' => $this->directUserAccess($userId, (int)$app['id']) || $this->groupAccess($userId, (int)$app['id']) || $this->systemRoleAccess($userId, (int)$app['id']),
            default => false,
        };
    }

    public function directUserAccess(int $userId, int $applicationId): bool
    {
        return $this->db->one('SELECT 1 FROM application_users WHERE application_id=? AND user_id=? AND enabled=1', [$applicationId, $userId]) !== null;
    }

    private function groupAccess(int $userId, int $applicationId): bool
    {
        return $this->db->one('SELECT 1 FROM application_groups ag JOIN group_members gm ON gm.group_id=ag.group_id WHERE ag.application_id=? AND gm.user_id=? LIMIT 1', [$applicationId, $userId]) !== null;
    }

    private function systemRoleAccess(int $userId, int $applicationId): bool
    {
        return $this->db->one('SELECT 1 FROM application_system_roles ar JOIN user_system_roles ur ON ur.role_id=ar.role_id WHERE ar.application_id=? AND ur.user_id=? LIMIT 1', [$applicationId, $userId]) !== null;
    }

    public function rolesForUser(int $userId, int $applicationId): array
    {
        $rows = $this->db->all('SELECT r.name FROM app_user_roles ur JOIN app_roles r ON r.id=ur.app_role_id AND r.application_id=ur.application_id WHERE ur.application_id=? AND ur.user_id=? ORDER BY r.name', [$applicationId, $userId]);
        return array_column($rows, 'name');
    }

    public function grantUser(int $applicationId, int $userId, int $actorUserId): void
    {
        $this->db->execute('INSERT INTO application_users(application_id,user_id,enabled,created_by) VALUES(?,?,1,?) ON DUPLICATE KEY UPDATE enabled=1,created_by=VALUES(created_by),created_at=CURRENT_TIMESTAMP', [$applicationId, $userId, $actorUserId]);
        $this->audit->write('application.user.granted', 'success', $actorUserId, $userId, $applicationId);
    }

    public function revokeUser(int $applicationId, int $userId, int $actorUserId): void
    {
        $this->db->transaction(function (Database $db) use ($applicationId, $userId): void {
            $db->execute('UPDATE application_users SET enabled=0 WHERE application_id=? AND user_id=?', [$applicationId, $userId]);
            $db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?', [$applicationId, $userId]);
            $db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?', [$applicationId, $userId]);
            $db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?', [$applicationId, $userId]);
        });
        $this->audit->write('application.user.revoked', 'success', $actorUserId, $userId, $applicationId);
    }

    public function revokeApplication(int $applicationId, int $actorUserId, string $reason = 'application disabled'): void
    {
        $this->db->transaction(function (Database $db) use ($applicationId): void {
            $db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?', [$applicationId]);
            $db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?', [$applicationId]);
            $db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?', [$applicationId]);
        });
        $this->audit->write('application.tokens.revoked', 'success', $actorUserId, null, $applicationId, $reason);
    }
}
