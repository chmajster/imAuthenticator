<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class RequiredActionService
{
    public function __construct(private Database $db,private AuditLog $audit) {}

    public function synchronize(int $userId): void
    {
        $docs=$this->db->all('SELECT ld.* FROM legal_documents ld WHERE ld.required=1 AND ld.effective_at<=NOW() AND ld.id=(SELECT ld2.id FROM legal_documents ld2 WHERE ld2.document_type=ld.document_type AND (ld2.organization_id<=>ld.organization_id) AND ld2.required=1 AND ld2.effective_at<=NOW() ORDER BY ld2.effective_at DESC,ld2.id DESC LIMIT 1)');
        foreach($docs as $doc){
            $accepted=$this->db->one('SELECT 1 FROM user_legal_acceptances WHERE user_id=? AND legal_document_id=?',[$userId,(int)$doc['id']]);if($accepted)continue;
            $type=$doc['document_type']==='terms'?'accept_terms':'accept_privacy';
            $existing=$this->db->one("SELECT 1 FROM required_actions WHERE user_id=? AND action_type=? AND status='pending' AND JSON_EXTRACT(payload_json,'$.legal_document_id')=?",[$userId,$type,(int)$doc['id']]);
            if(!$existing)$this->db->execute("INSERT INTO required_actions(user_id,action_type,payload_json) VALUES(?,?,?)",[$userId,$type,json_encode(['legal_document_id'=>(int)$doc['id'],'version'=>$doc['version']],JSON_THROW_ON_ERROR)]);
        }
    }

    public function pending(int $userId): array
    {
        $this->synchronize($userId);
        return $this->db->all("SELECT * FROM required_actions WHERE user_id=? AND status='pending' ORDER BY id",[$userId]);
    }

    public function acceptLegal(int $actionId,int $userId): void
    {
        $action=$this->db->one("SELECT * FROM required_actions WHERE id=? AND user_id=? AND status='pending'",[$actionId,$userId]);if(!$action||!in_array($action['action_type'],['accept_terms','accept_privacy'],true))throw new \RuntimeException('invalid_action');
        $payload=json_decode((string)$action['payload_json'],true);$docId=(int)($payload['legal_document_id']??0);if($docId<1)throw new \RuntimeException('invalid_action');
        $this->db->transaction(function()use($docId,$userId,$actionId):void{$this->db->execute('INSERT IGNORE INTO user_legal_acceptances(user_id,legal_document_id,ip_address) VALUES(?,?,?)',[$userId,$docId,Security::currentIp()]);$this->db->execute("UPDATE required_actions SET status='completed',completed_at=NOW() WHERE id=?",[$actionId]);});
        $this->audit->write('required_action.completed','success',$userId,$userId,null,null,['action_id'=>$actionId,'type'=>$action['action_type']]);
    }

    public function completePasswordChange(int $actionId,int $userId,string $newPassword): void
    {
        if(strlen($newPassword)<12)throw new \RuntimeException('password_too_short');$action=$this->db->one("SELECT 1 FROM required_actions WHERE id=? AND user_id=? AND action_type='change_password' AND status='pending'",[$actionId,$userId]);if(!$action)throw new \RuntimeException('invalid_action');
        $this->db->transaction(function()use($actionId,$userId,$newPassword):void{$this->db->execute('UPDATE users SET password_hash=? WHERE id=?',[password_hash($newPassword,PASSWORD_ARGON2ID),$userId]);$this->db->execute("UPDATE required_actions SET status='completed',completed_at=NOW() WHERE id=?",[$actionId]);});
        $this->audit->write('password.changed.required_action','success',$userId,$userId);
    }

    public function refreshAutomaticCompletions(int $userId): void
    {
        if($this->db->one('SELECT 1 FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL LIMIT 1',[$userId])||$this->db->one('SELECT 1 FROM mfa_methods WHERE user_id=? AND enabled=1 LIMIT 1',[$userId]))$this->db->execute("UPDATE required_actions SET status='completed',completed_at=NOW() WHERE user_id=? AND action_type='setup_mfa' AND status='pending'",[$userId]);
        if($this->db->one('SELECT 1 FROM user_emails WHERE user_id=? AND is_primary=1 AND verified_at IS NOT NULL',[$userId]))$this->db->execute("UPDATE required_actions SET status='completed',completed_at=NOW() WHERE user_id=? AND action_type='verify_email' AND status='pending'",[$userId]);
    }
}
