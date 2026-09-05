<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class AccessReviewService
{
    public function __construct(
        private Database $db,
        private ApplicationAccessService $access,
        private ApplicationAdminService $admins,
        private AuditLog $audit,
        private EventService $events
    ) {}

    public function create(int $applicationId, int $reviewerUserId, int $actorUserId, string $name, ?string $dueAt = null): int
    {
        if (!$this->admins->canManage($actorUserId, $applicationId, 'access_reviews')) throw new RuntimeException('forbidden');
        $name = trim($name);
        if ($name === '') throw new RuntimeException('name_required');
        if ($dueAt !== null && $dueAt !== '') {
            $timestamp = strtotime(str_replace('T', ' ', $dueAt));
            if ($timestamp === false) throw new RuntimeException('invalid_due_at');
            $dueAt = date('Y-m-d H:i:s', $timestamp);
        } else {
            $dueAt = null;
        }
        $reviewer = $this->db->one("SELECT 1 FROM users WHERE id=? AND enabled=1 AND lifecycle_status='active'", [$reviewerUserId]);
        if (!$reviewer) throw new RuntimeException('invalid_reviewer');

        return $this->db->transaction(function () use ($applicationId, $reviewerUserId, $actorUserId, $name, $dueAt): int {
            $this->db->execute(
                "INSERT INTO access_reviews(application_id,name,reviewer_user_id,created_by,status,due_at) VALUES(?,?,?,?, 'active',?)",
                [$applicationId, $name, $reviewerUserId, $actorUserId, $dueAt]
            );
            $id = $this->db->lastInsertId();
            $users = $this->db->all(
                'SELECT user_id FROM application_users WHERE application_id=? AND enabled=1 AND revoked_at IS NULL AND (valid_from IS NULL OR valid_from<=NOW()) AND (valid_until IS NULL OR valid_until>NOW())',
                [$applicationId]
            );
            foreach ($users as $u) {
                $this->db->execute('INSERT IGNORE INTO access_review_items(access_review_id,user_id) VALUES(?,?)', [$id, (int)$u['user_id']]);
            }
            $this->audit->write('access_review.created', 'success', $actorUserId, null, $applicationId, null, ['review_id'=>$id,'items'=>count($users),'due_at'=>$dueAt]);
            return $id;
        });
    }

    public function decide(int $reviewId, int $userId, string $decision, int $actorUserId, ?string $note = null): void
    {
        if (!in_array($decision, ['keep','revoke'], true)) throw new RuntimeException('invalid_decision');
        $review = $this->db->one('SELECT * FROM access_reviews WHERE id=?', [$reviewId]);
        if (!$review || $review['status'] !== 'active') throw new RuntimeException('review_not_active');
        if ((int)$review['reviewer_user_id'] !== $actorUserId && !$this->admins->canManage($actorUserId, (int)$review['application_id'], 'access_reviews')) throw new RuntimeException('forbidden');
        if (!$this->db->one('SELECT 1 FROM access_review_items WHERE access_review_id=? AND user_id=?', [$reviewId,$userId])) throw new RuntimeException('item_not_found');

        $this->db->transaction(function () use ($reviewId,$userId,$decision,$actorUserId,$note,$review): void {
            $this->db->execute('UPDATE access_review_items SET decision=?,decided_by=?,decided_at=NOW(),note=? WHERE access_review_id=? AND user_id=?', [$decision,$actorUserId,$note,$reviewId,$userId]);
            if ($decision === 'revoke') $this->access->revokeUser((int)$review['application_id'], $userId, $actorUserId, 'access review revoked');
        });
        $this->audit->write('access_review.item.decided', 'success', $actorUserId, $userId, (int)$review['application_id'], null, ['review_id'=>$reviewId,'decision'=>$decision]);
    }

    public function complete(int $reviewId, int $actorUserId): void
    {
        $review = $this->db->one('SELECT * FROM access_reviews WHERE id=?', [$reviewId]);
        if (!$review) throw new RuntimeException('not_found');
        if ($review['status'] !== 'active') throw new RuntimeException('review_not_active');
        if ((int)$review['reviewer_user_id'] !== $actorUserId && !$this->admins->canManage($actorUserId, (int)$review['application_id'], 'access_reviews')) throw new RuntimeException('forbidden');
        $pending = $this->db->one("SELECT COUNT(*) AS c FROM access_review_items WHERE access_review_id=? AND decision='pending'", [$reviewId]);
        if ((int)($pending['c'] ?? 0) > 0) throw new RuntimeException('pending_items');
        $this->db->execute("UPDATE access_reviews SET status='completed',completed_at=NOW() WHERE id=?", [$reviewId]);
        $this->audit->write('access_review.completed', 'success', $actorUserId, null, (int)$review['application_id'], null, ['review_id'=>$reviewId]);
        $this->events->emit('access_review.completed', ['review_id'=>$reviewId,'application_id'=>(int)$review['application_id']]);
    }
}
