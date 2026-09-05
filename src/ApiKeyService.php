<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class ApiKeyService
{
    public function __construct(private Database $db,private AuditLog $audit) {}

    public function createServiceAccount(string $name,?string $description,int $actorUserId,?int $organizationId=null): int
    {
        $name=trim($name);if($name==='')throw new RuntimeException('name_required');
        $this->db->execute('INSERT INTO service_accounts(organization_id,uuid,name,description,enabled,created_by) VALUES(?,?,?,?,1,?)',[$organizationId,Security::uuidV4(),$name,$description?:null,$actorUserId]);$id=$this->db->lastInsertId();$this->audit->write('service_account.created','success',$actorUserId,null,null,null,['service_account_id'=>$id,'organization_id'=>$organizationId]);return $id;
    }

    public function createKey(int $serviceAccountId,array $scopes,int $actorUserId,?string $validUntil=null): string
    {
        $account=$this->db->one('SELECT id,enabled FROM service_accounts WHERE id=?',[$serviceAccountId]);if(!$account||(bool)$account['enabled']!==true)throw new RuntimeException('service_account_not_active');
        $scopes=array_values(array_unique(array_filter(array_map('strval',$scopes))));$allowed=['events.read','audit.read','users.read','applications.read','webhooks.manage'];foreach($scopes as $scope)if(!in_array($scope,$allowed,true))throw new RuntimeException('invalid_scope');if($scopes===[])throw new RuntimeException('scope_required');
        $raw='imak_'.Security::randomToken(48);$prefix=substr($raw,0,16);$this->db->execute('INSERT INTO api_keys(service_account_id,key_hash,key_prefix,scopes_json,valid_until) VALUES(?,?,?,?,?)',[$serviceAccountId,Security::tokenHash($raw),$prefix,json_encode($scopes,JSON_THROW_ON_ERROR),$validUntil]);$this->audit->write('api_key.created','success',$actorUserId,null,null,null,['service_account_id'=>$serviceAccountId,'key_prefix'=>$prefix,'scopes'=>$scopes,'valid_until'=>$validUntil]);return $raw;
    }

    public function authenticate(string $raw,string $requiredScope): array
    {
        if($raw==='')throw new RuntimeException('invalid_api_key');$row=$this->db->one('SELECT k.*,s.organization_id,s.name AS service_account_name,s.enabled AS service_account_enabled FROM api_keys k JOIN service_accounts s ON s.id=k.service_account_id WHERE k.key_hash=?',[Security::tokenHash($raw)]);if(!$row||$row['revoked_at']!==null||!(bool)$row['service_account_enabled']||($row['valid_until']&&strtotime((string)$row['valid_until'])<=time()))throw new RuntimeException('invalid_api_key');$scopes=json_decode((string)($row['scopes_json']??'[]'),true);if(!is_array($scopes)||!in_array($requiredScope,$scopes,true))throw new RuntimeException('insufficient_scope');$this->db->execute('UPDATE api_keys SET last_used_at=NOW() WHERE id=?',[(int)$row['id']]);return $row;
    }

    public function revokeKey(int $keyId,int $actorUserId): void
    {
        $row=$this->db->one('SELECT id,service_account_id,key_prefix FROM api_keys WHERE id=?',[$keyId]);if(!$row)throw new RuntimeException('not_found');$this->db->execute('UPDATE api_keys SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=?',[$keyId]);$this->audit->write('api_key.revoked','success',$actorUserId,null,null,null,['service_account_id'=>(int)$row['service_account_id'],'key_prefix'=>$row['key_prefix']]);
    }
}
