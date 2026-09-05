<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class ScimService
{
    public function __construct(private Database $db,private ApplicationAccessService $access,private AuditLog $audit,private EventService $events) {}

    public function authenticate(int $connectorId,string $bearer): array
    {
        $row=$this->db->one("SELECT sc.*,a.organization_id FROM scim_connectors sc JOIN applications a ON a.id=sc.application_id WHERE sc.id=? AND sc.enabled=1 AND sc.direction='inbound' AND a.enabled=1 AND a.deleted_at IS NULL",[$connectorId]);
        if(!$row||$bearer===''||empty($row['bearer_token_hash'])) throw new RuntimeException('unauthorized');
        $expected=(string)$row['bearer_token_hash'];$ok=str_starts_with($expected,'$')?password_verify($bearer,$expected):hash_equals($expected,hash('sha256',$bearer));
        if(!$ok)throw new RuntimeException('unauthorized'); return $row;
    }

    public function listUsers(array $connector,?string $filter=null): array
    {
        $params=[(int)$connector['application_id']];$where='au.application_id=?';
        if($filter&&preg_match('/^userName\s+eq\s+"([^"]+)"$/i',$filter,$m)){ $where.=' AND (u.username=? OR u.email=?)';$params[]=$m[1];$params[]=$m[1]; }
        $rows=$this->db->all("SELECT u.id,u.uuid,u.username,u.name,u.email,u.lifecycle_status,au.enabled,au.revoked_at FROM users u JOIN application_users au ON au.user_id=u.id WHERE {$where} ORDER BY u.id",$params);
        return array_map(fn(array $r)=>$this->userResource($r,(int)$connector['id']),$rows);
    }

    public function getUser(array $connector,string $id): array
    {
        $row=$this->db->one('SELECT u.id,u.uuid,u.username,u.name,u.email,u.lifecycle_status,au.enabled,au.revoked_at FROM users u JOIN application_users au ON au.user_id=u.id AND au.application_id=? WHERE u.uuid=?',[(int)$connector['application_id'],$id]);
        if(!$row)throw new RuntimeException('not_found'); return $this->userResource($row,(int)$connector['id']);
    }

    public function createUser(array $connector,array $payload): array
    {
        $username=trim((string)($payload['userName']??''));$email=$this->emailFromPayload($payload);$display=trim((string)($payload['displayName']??($payload['name']['formatted']??$username)));
        if($username===''||$email===''||!filter_var($email,FILTER_VALIDATE_EMAIL))throw new RuntimeException('invalidValue');
        $user=$this->db->one('SELECT * FROM users WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?) LIMIT 1',[$username,$email]);
        if(!$user){$this->db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),$display!==''?$display:$username,$username,strtolower($email),password_hash(Security::randomToken(48),PASSWORD_ARGON2ID)]);$userId=$this->db->lastInsertId();}
        else{$userId=(int)$user['id'];$this->db->execute("UPDATE users SET name=?,username=COALESCE(username,?),lifecycle_status=CASE WHEN lifecycle_status='disabled' THEN 'active' ELSE lifecycle_status END WHERE id=?",[$display!==''?$display:$username,$username,$userId]);}
        $this->access->grantUser((int)$connector['application_id'],$userId,null,null,null,'scim');
        if(isset($payload['externalId']))$this->setExternalId($userId,(int)$connector['id'],(string)$payload['externalId']);
        $this->audit->write('scim.user.provisioned','success',null,$userId,(int)$connector['application_id'],null,['connector_id'=>(int)$connector['id']]);
        $this->events->emit('scim.user.provisioned',['connector_id'=>(int)$connector['id'],'application_id'=>(int)$connector['application_id'],'user_id'=>$userId],$connector['organization_id']!==null?(int)$connector['organization_id']:null);
        $row=$this->db->one('SELECT u.id,u.uuid,u.username,u.name,u.email,u.lifecycle_status,au.enabled,au.revoked_at FROM users u JOIN application_users au ON au.user_id=u.id AND au.application_id=? WHERE u.id=?',[(int)$connector['application_id'],$userId]);
        return $this->userResource($row,(int)$connector['id']);
    }

    public function patchUser(array $connector,string $uuid,array $payload): array
    {
        $user=$this->db->one('SELECT id FROM users WHERE uuid=?',[$uuid]);if(!$user)throw new RuntimeException('not_found');$userId=(int)$user['id'];
        foreach((array)($payload['Operations']??[]) as $op){if(!is_array($op))continue;$operation=strtolower((string)($op['op']??''));$path=strtolower((string)($op['path']??''));$value=$op['value']??null;
            if($operation==='replace'&&$path==='active'){if((bool)$value)$this->access->grantUser((int)$connector['application_id'],$userId,null,null,null,'scim');else$this->access->revokeUser((int)$connector['application_id'],$userId,null,'SCIM deprovisioning');}
            if($operation==='replace'&&$path==='displayname')$this->db->execute('UPDATE users SET name=? WHERE id=?',[trim((string)$value),$userId]);
            if($operation==='replace'&&$path==='username')$this->db->execute('UPDATE users SET username=? WHERE id=?',[trim((string)$value),$userId]);
        }
        $this->audit->write('scim.user.updated','success',null,$userId,(int)$connector['application_id'],null,['connector_id'=>(int)$connector['id']]);
        return $this->getUser($connector,$uuid);
    }

    public function deleteUser(array $connector,string $uuid): void
    {
        $user=$this->db->one('SELECT id FROM users WHERE uuid=?',[$uuid]);if(!$user)throw new RuntimeException('not_found');$this->access->revokeUser((int)$connector['application_id'],(int)$user['id'],null,'SCIM deprovisioning');$this->audit->write('scim.user.deprovisioned','success',null,(int)$user['id'],(int)$connector['application_id'],null,['connector_id'=>(int)$connector['id']]);
    }

    public function listGroups(array $connector): array
    {
        $groups=$this->db->all('SELECT * FROM scim_group_mappings WHERE scim_connector_id=? ORDER BY id',[(int)$connector['id']]);$result=[];foreach($groups as $g){$members=[];if($g['app_role_id']!==null){foreach($this->db->all('SELECT u.uuid FROM app_user_roles aur JOIN users u ON u.id=aur.user_id WHERE aur.application_id=? AND aur.app_role_id=?',[(int)$connector['application_id'],(int)$g['app_role_id']]) as $m)$members[]=['value'=>$m['uuid']];}$result[]=['schemas'=>['urn:ietf:params:scim:schemas:core:2.0:Group'],'id'=>(string)$g['id'],'externalId'=>$g['external_group_id'],'displayName'=>$g['display_name'],'members'=>$members];}return $result;
    }

    private function userResource(array $row,int $connectorId): array
    {
        $ext=$this->db->one('SELECT attribute_value FROM user_attributes WHERE user_id=? AND attribute_key=?',[(int)$row['id'],'scim.'.$connectorId.'.externalId']);
        return ['schemas'=>['urn:ietf:params:scim:schemas:core:2.0:User'],'id'=>$row['uuid'],'externalId'=>$ext['attribute_value']??null,'userName'=>$row['username']?:$row['email'],'displayName'=>$row['name'],'active'=>(bool)$row['enabled']&&$row['revoked_at']===null,'emails'=>[['value'=>$row['email'],'primary'=>true]],'meta'=>['resourceType'=>'User']];
    }
    private function emailFromPayload(array $payload): string { foreach((array)($payload['emails']??[]) as $e)if(is_array($e)&&!empty($e['value']))return strtolower(trim((string)$e['value']));return strtolower(trim((string)($payload['userName']??''))); }
    private function setExternalId(int $userId,int $connectorId,string $externalId): void { $this->db->execute('INSERT INTO user_attributes(user_id,attribute_key,attribute_value,source) VALUES(?,?,?,\'scim\') ON DUPLICATE KEY UPDATE attribute_value=VALUES(attribute_value),source=\'scim\'',[$userId,'scim.'.$connectorId.'.externalId',$externalId]); }
}
