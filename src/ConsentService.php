<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ConsentService
{
    public function __construct(private Database $db,private AuditLog $audit) {}

    public function required(array $app): bool { return (bool)($app['require_user_consent']??false); }

    public function hasConsent(int $userId,int $applicationId,array $scopes): bool
    {
        $row=$this->db->one('SELECT scopes_json FROM user_application_consents WHERE user_id=? AND application_id=? AND revoked_at IS NULL',[$userId,$applicationId]);
        if(!$row)return false;$granted=json_decode((string)$row['scopes_json'],true);if(!is_array($granted))return false;
        return array_diff(array_values(array_unique($scopes)),array_map('strval',$granted))===[];
    }

    public function grant(int $userId,int $applicationId,array $scopes): void
    {
        $scopes=array_values(array_unique(array_map('strval',$scopes)));$json=json_encode($scopes,JSON_THROW_ON_ERROR);
        $this->db->execute('INSERT INTO user_application_consents(user_id,application_id,scopes_json,granted_at,revoked_at,last_used_at) VALUES(?,?,?,NOW(),NULL,NOW()) ON DUPLICATE KEY UPDATE scopes_json=VALUES(scopes_json),granted_at=NOW(),revoked_at=NULL,last_used_at=NOW()',[$userId,$applicationId,$json]);
        $this->audit->write('consent.granted','success',$userId,$userId,$applicationId,null,['scopes'=>$scopes]);
    }

    public function touch(int $userId,int $applicationId): void{$this->db->execute('UPDATE user_application_consents SET last_used_at=NOW() WHERE user_id=? AND application_id=? AND revoked_at IS NULL',[$userId,$applicationId]);}

    public function revoke(int $userId,int $applicationId): void
    {
        $this->db->execute('UPDATE user_application_consents SET revoked_at=NOW() WHERE user_id=? AND application_id=? AND revoked_at IS NULL',[$userId,$applicationId]);
        $this->audit->write('consent.revoked','success',$userId,$userId,$applicationId);
    }

    public function history(int $userId): array
    {
        return $this->db->all('SELECT c.*,a.name AS application_name FROM user_application_consents c JOIN applications a ON a.id=c.application_id WHERE c.user_id=? ORDER BY c.granted_at DESC',[$userId]);
    }
}
