<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class HousekeepingService
{
    public function __construct(private Database $db,private SystemSettingsService $settings,private AuditLog $audit,private SessionService $sessions) {}

    public function run(int $actorUserId): array
    {
        $inactive=$this->disableInactive($actorUserId);$retention=$this->applyAuditRetention();$expired=$this->expireAccounts($actorUserId);return ['inactive_disabled'=>$inactive,'expired_accounts'=>$expired,'audit_deleted'=>$retention];
    }

    private function disableInactive(int $actorUserId): int
    {
        $days=$this->settings->inactiveDays();if($days<=0)return 0;$cutoff=date('Y-m-d H:i:s',time()-$days*86400);
        $rows=$this->db->all("SELECT id FROM users WHERE enabled=1 AND lifecycle_status='active' AND is_admin=0 AND break_glass=0 AND inactive_lock_exempt=0 AND last_login_at IS NOT NULL AND last_login_at<?",[$cutoff]);
        foreach($rows as $row){$id=(int)$row['id'];$this->db->execute("UPDATE users SET lifecycle_status='suspended' WHERE id=?",[$id]);$this->sessions->globalLogout($id,$actorUserId,'inactive account auto-lock');$this->audit->write('account.auto_suspended','success',$actorUserId,$id,null,'inactive account');}
        return count($rows);
    }

    private function expireAccounts(int $actorUserId): int
    {
        $rows=$this->db->all("SELECT id FROM users WHERE enabled=1 AND lifecycle_status IN ('active','pending','suspended') AND account_ends_at IS NOT NULL AND account_ends_at<=NOW()");foreach($rows as $row){$id=(int)$row['id'];$this->db->execute("UPDATE users SET lifecycle_status='expired' WHERE id=?",[$id]);$this->sessions->globalLogout($id,$actorUserId,'account expired');}$count=count($rows);if($count)$this->audit->write('account.expiration.batch','success',$actorUserId,null,null,null,['count'=>$count]);return $count;
    }

    private function applyAuditRetention(): int
    {
        $days=$this->settings->auditRetentionDays();if($days<=0)return 0;$cutoff=date('Y-m-d H:i:s',time()-$days*86400);$last=$this->db->one('SELECT id,entry_hash FROM audit_log WHERE created_at<? ORDER BY id DESC LIMIT 1',[$cutoff]);if(!$last)return 0;$first=$this->db->one('SELECT id,previous_hash FROM audit_log WHERE id>? ORDER BY id LIMIT 1',[(int)$last['id']]);$count=$this->db->one('SELECT COUNT(*) AS c FROM audit_log WHERE id<=?',[(int)$last['id']]);$this->db->execute('INSERT INTO audit_retention_checkpoints(deleted_through_id,deleted_count,chain_head_hash,retained_first_previous_hash) VALUES(?,?,?,?)',[(int)$last['id'],(int)($count['c']??0),$last['entry_hash'],$first['previous_hash']??null]);return $this->db->execute('DELETE FROM audit_log WHERE id<=?',[(int)$last['id']]);
    }
}
