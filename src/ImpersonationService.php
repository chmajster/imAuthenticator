<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ImpersonationService
{
    public function __construct(private Database $db,private AuditLog $audit) {}

    public function start(int $actorId,int $targetId,string $reason): array
    {
        $reason=trim($reason);if($reason==='')throw new \RuntimeException('reason_required');$actor=$this->db->one('SELECT is_admin,break_glass FROM users WHERE id=?',[$actorId]);$target=$this->db->one('SELECT id,is_admin,break_glass,enabled,lifecycle_status FROM users WHERE id=?',[$targetId]);if(!$actor||!(bool)$actor['is_admin']||!$target)throw new \RuntimeException('forbidden');if((bool)$target['break_glass']||(bool)$target['is_admin'])throw new \RuntimeException('privileged_impersonation_forbidden');if(!(bool)$target['enabled']||$target['lifecycle_status']!=='active')throw new \RuntimeException('target_not_active');
        $uuid=Security::uuidV4();$this->db->execute('INSERT INTO impersonation_sessions(uuid,actor_user_id,target_user_id,reason,ip_address) VALUES(?,?,?,?,?)',[$uuid,$actorId,$targetId,$reason,Security::currentIp()]);$id=$this->db->lastInsertId();$this->audit->write('impersonation.started','success',$actorId,$targetId,null,$reason,['impersonation_id'=>$id]);return ['id'=>$id,'uuid'=>$uuid,'target_user_id'=>$targetId];
    }

    public function end(int $id,int $actorId): void{$row=$this->db->one('SELECT * FROM impersonation_sessions WHERE id=? AND actor_user_id=? AND ended_at IS NULL',[$id,$actorId]);if(!$row)throw new \RuntimeException('not_found');$this->db->execute('UPDATE impersonation_sessions SET ended_at=NOW() WHERE id=?',[$id]);$this->audit->write('impersonation.ended','success',$actorId,(int)$row['target_user_id'],null,null,['impersonation_id'=>$id]);}
}
