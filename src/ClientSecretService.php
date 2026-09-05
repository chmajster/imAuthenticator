<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class ClientSecretService
{
    public function __construct(private Database $db, private ApplicationAdminService $admins, private AuditLog $audit, private EventService $events) {}

    public function rotate(int $applicationId, int $actorUserId, int $validDays = 365, int $overlapDays = 7): string
    {
        if (!$this->admins->canManage($actorUserId,$applicationId,'manage_secrets')) throw new RuntimeException('forbidden');
        $app = $this->db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$applicationId]);
        if (!$app || $app['client_type'] !== 'confidential') throw new RuntimeException('invalid_client_type');
        $validDays = max(1,min($validDays,730));
        $overlapDays = max(0,min($overlapDays,90));
        $secret = Security::clientSecret();
        $newHash = Security::secretHash($secret);
        $hint = substr($secret,0,12);
        $overlapUntil = date('Y-m-d H:i:s', time()+$overlapDays*86400);
        $newUntil = date('Y-m-d H:i:s', time()+$validDays*86400);
        $this->db->transaction(function () use ($app,$applicationId,$actorUserId,$newHash,$hint,$overlapUntil,$newUntil): void {
            if (!empty($app['client_secret_hash'])) {
                $this->db->execute('INSERT INTO client_secrets(application_id,secret_hash,secret_hint,valid_until,created_by) VALUES(?,?,?,?,?)', [$applicationId,$app['client_secret_hash'],'legacy',$overlapUntil,$actorUserId]);
            }
            $this->db->execute('UPDATE client_secrets SET valid_until=CASE WHEN valid_until IS NULL OR valid_until>? THEN ? ELSE valid_until END WHERE application_id=? AND revoked_at IS NULL', [$overlapUntil,$overlapUntil,$applicationId]);
            $this->db->execute('INSERT INTO client_secrets(application_id,secret_hash,secret_hint,valid_until,created_by) VALUES(?,?,?,?,?)', [$applicationId,$newHash,$hint,$newUntil,$actorUserId]);
            $this->db->execute('UPDATE applications SET client_secret_hash=NULL WHERE id=?', [$applicationId]);
        });
        $this->audit->write('application.secret.rotated','success',$actorUserId,null,$applicationId,null,['valid_until'=>$newUntil,'overlap_until'=>$overlapUntil,'hint'=>$hint]);
        $this->events->emit('application.secret.rotated',['application_id'=>$applicationId,'valid_until'=>$newUntil,'overlap_until'=>$overlapUntil]);
        return $secret;
    }
}
