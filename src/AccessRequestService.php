<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class AccessRequestService
{
    public function __construct(private Database $db, private ApplicationAccessService $access, private ApplicationAdminService $admins, private AuditLog $audit, private EventService $events) {}

    public function request(int $applicationId, int $userId, ?int $roleId, ?int $durationSeconds, string $justification): int
    {
        $app = $this->db->one('SELECT id,organization_id,enabled,deleted_at FROM applications WHERE id=?', [$applicationId]);
        if (!$app || !(bool)$app['enabled'] || $app['deleted_at'] !== null) throw new RuntimeException('application_unavailable');
        if ($this->db->one("SELECT 1 FROM access_requests WHERE application_id=? AND user_id=? AND status='pending'", [$applicationId,$userId])) throw new RuntimeException('request_already_pending');
        if ($roleId !== null && !$this->db->one('SELECT 1 FROM app_roles WHERE id=? AND application_id=?', [$roleId,$applicationId])) throw new RuntimeException('invalid_role');
        $durationSeconds = $durationSeconds === null ? null : max(300, min($durationSeconds, 31536000));
        $this->db->execute('INSERT INTO access_requests(uuid,application_id,user_id,requested_role_id,justification,requested_duration_seconds) VALUES(?,?,?,?,?,?)', [Security::uuidV4(),$applicationId,$userId,$roleId,$justification,$durationSeconds]);
        $id = $this->db->lastInsertId();
        $this->audit->write('access.request.created', 'success', $userId, $userId, $applicationId, null, ['request_id'=>$id]);
        $this->events->emit('access.requested', ['request_id'=>$id,'application_id'=>$applicationId,'user_id'=>$userId], $app['organization_id'] !== null ? (int)$app['organization_id'] : null);
        return $id;
    }

    public function approve(int $requestId, int $actorUserId, ?string $reason = null): void
    {
        $request = $this->db->one("SELECT ar.*,a.organization_id FROM access_requests ar JOIN applications a ON a.id=ar.application_id WHERE ar.id=?", [$requestId]);
        if (!$request || $request['status'] !== 'pending') throw new RuntimeException('request_not_pending');
        if (!$this->admins->canManage($actorUserId, (int)$request['application_id'], 'approve_access')) throw new RuntimeException('forbidden');
        $validUntil = null;
        if ($request['requested_duration_seconds'] !== null) $validUntil = date('Y-m-d H:i:s', time() + (int)$request['requested_duration_seconds']);
        $this->db->transaction(function () use ($request,$actorUserId,$reason,$validUntil): void {
            $this->access->grantUser((int)$request['application_id'], (int)$request['user_id'], $actorUserId, null, $validUntil, 'request');
            if ($request['requested_role_id'] !== null) $this->db->execute('INSERT IGNORE INTO app_user_roles(application_id,user_id,app_role_id,created_by) VALUES(?,?,?,?)', [(int)$request['application_id'],(int)$request['user_id'],(int)$request['requested_role_id'],$actorUserId]);
            $this->db->execute("UPDATE access_requests SET status='approved',decided_by=?,decision_reason=?,decided_at=NOW() WHERE id=?", [$actorUserId,$reason,(int)$request['id']]);
        });
        $this->audit->write('access.request.approved', 'success', $actorUserId, (int)$request['user_id'], (int)$request['application_id'], $reason, ['request_id'=>$requestId,'valid_until'=>$validUntil]);
        $this->events->emit('access.granted', ['request_id'=>$requestId,'application_id'=>(int)$request['application_id'],'user_id'=>(int)$request['user_id'],'valid_until'=>$validUntil], $request['organization_id'] !== null ? (int)$request['organization_id'] : null);
    }

    public function deny(int $requestId, int $actorUserId, ?string $reason = null): void
    {
        $request = $this->db->one("SELECT ar.*,a.organization_id FROM access_requests ar JOIN applications a ON a.id=ar.application_id WHERE ar.id=?", [$requestId]);
        if (!$request || $request['status'] !== 'pending') throw new RuntimeException('request_not_pending');
        if (!$this->admins->canManage($actorUserId, (int)$request['application_id'], 'approve_access')) throw new RuntimeException('forbidden');
        $this->db->execute("UPDATE access_requests SET status='denied',decided_by=?,decision_reason=?,decided_at=NOW() WHERE id=?", [$actorUserId,$reason,$requestId]);
        $this->audit->write('access.request.denied', 'denied', $actorUserId, (int)$request['user_id'], (int)$request['application_id'], $reason, ['request_id'=>$requestId]);
        $this->events->emit('access.denied', ['request_id'=>$requestId,'application_id'=>(int)$request['application_id'],'user_id'=>(int)$request['user_id']], $request['organization_id'] !== null ? (int)$request['organization_id'] : null);
    }
}
