<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class SessionService
{
    public function __construct(private Database $db, private AuditLog $audit, private EventService $events) {}

    public function globalLogout(int $userId, int $actorUserId, string $reason = 'global logout'): void
    {
        $this->db->transaction(function (Database $db) use ($userId): void {
            $db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,NOW()) WHERE user_id=?', [$userId]);
            $db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,NOW()) WHERE user_id=?', [$userId]);
            $db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,NOW()) WHERE user_id=?', [$userId]);
        });
        $this->audit->write('session.global_logout', 'success', $actorUserId, $userId, null, $reason);
        $this->events->emit('session.global_logout', ['user_id'=>$userId,'actor_user_id'=>$actorUserId,'reason'=>$reason]);
    }

    public function revokeDevice(int $deviceId, int $userId, int $actorUserId): void
    {
        $this->db->execute('UPDATE user_devices SET revoked_at=NOW(),trusted=0,trusted_until=NULL WHERE id=? AND user_id=?', [$deviceId,$userId]);
        $this->audit->write('device.revoked', 'success', $actorUserId, $userId, null, null, ['device_id'=>$deviceId]);
        $this->events->emit('device.revoked', ['user_id'=>$userId,'device_id'=>$deviceId]);
    }
}
