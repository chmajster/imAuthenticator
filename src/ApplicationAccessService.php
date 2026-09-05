<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class ApplicationAccessService
{
    public function __construct(private Database $db, private AuditLog $audit, private ?OrganizationService $organizations = null) {}

    public function hasAccess(int $userId, array|int $application, array $context=[]): bool
    {
        $app=is_array($application)?$application:$this->db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL',[$application]);
        if(!$app||!(bool)$app['enabled'])return false;
        $user=$this->db->one('SELECT id,enabled,lifecycle_status,account_starts_at,account_ends_at FROM users WHERE id=?',[$userId]);
        if(!$this->userIsActive($user))return false;
        if($app['organization_id']!==null&&!$this->tenantMembershipActive($userId,(int)$app['organization_id']))return false;
        $direct=$this->directUserOverride($userId,(int)$app['id']);if($direct===false)return false;
        $allowed=$direct===true||match($app['access_policy']){'all'=>true,'groups'=>$this->groupAccess($userId,(int)$app['id']),'roles'=>$this->systemRoleAccess($userId,(int)$app['id']),'mixed'=>$this->groupAccess($userId,(int)$app['id'])||$this->systemRoleAccess($userId,(int)$app['id']),default=>false};
        foreach($this->matchingDynamicRules($userId,(int)$app['id'],$context)as$rule){if($rule['effect']==='deny')return false;if($rule['effect']==='allow')$allowed=true;}
        return $allowed;
    }

    public function directUserAccess(int $userId,int $appId):bool{return $this->directUserOverride($userId,$appId)===true;}
    public function matchingDynamicEffects(int $userId,int $appId,array $context=[]):array{return array_values(array_unique(array_column($this->matchingDynamicRules($userId,$appId,$context),'effect')));}
    public function rolesForUser(int $userId,int $appId):array{return array_column($this->db->all('SELECT r.name FROM app_user_roles ur JOIN app_roles r ON r.id=ur.app_role_id AND r.application_id=ur.application_id WHERE ur.application_id=? AND ur.user_id=? ORDER BY r.name',[$appId,$userId]),'name');}

    public function grantUser(int $appId,int $userId,?int $actor,?string $from=null,?string $until=null,string $source='manual'):void
    {
        $allowed=['manual','request','dynamic','scim','sync','system'];if(!in_array($source,$allowed,true))$source='manual';
        if(in_array($source,['scim','sync'],true)){$app=$this->db->one('SELECT organization_id FROM applications WHERE id=? AND deleted_at IS NULL',[$appId]);if($app&&$app['organization_id']!==null){if($this->organizations)$this->organizations->ensureMember((int)$app['organization_id'],$userId,$actor,'member');else$this->db->execute("INSERT IGNORE INTO organization_memberships(organization_id,user_id,role,status,created_by) VALUES(?,?,'member','active',?)",[(int)$app['organization_id'],$userId,$actor]);}}
        $this->db->execute('INSERT INTO application_users(application_id,user_id,enabled,valid_from,valid_until,grant_source,created_by) VALUES(?,?,1,?,?,?,?) ON DUPLICATE KEY UPDATE enabled=1,valid_from=VALUES(valid_from),valid_until=VALUES(valid_until),grant_source=VALUES(grant_source),revoked_at=NULL,revoke_reason=NULL,created_by=VALUES(created_by),created_at=CURRENT_TIMESTAMP',[$appId,$userId,$from,$until,$source,$actor]);
        $this->audit->write('application.user.granted','success',$actor,$userId,$appId,null,['valid_from'=>$from,'valid_until'=>$until,'source'=>$source]);
    }

    public function revokeUser(int $appId,int $userId,?int $actor,string $reason='explicit deny override'):void
    {
        $this->db->transaction(function(Database $db)use($appId,$userId,$actor,$reason):void{$db->execute("INSERT INTO application_users(application_id,user_id,enabled,grant_source,revoked_at,revoke_reason,created_by) VALUES(?,?,0,'manual',NOW(),?,?) ON DUPLICATE KEY UPDATE enabled=0,revoked_at=NOW(),revoke_reason=VALUES(revoke_reason),created_by=VALUES(created_by),created_at=CURRENT_TIMESTAMP",[$appId,$userId,$reason,$actor]);$db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$appId,$userId]);$db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$appId,$userId]);$db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$appId,$userId]);});
        $this->audit->write('application.user.revoked','success',$actor,$userId,$appId,$reason);
    }

    public function revokeApplication(int $appId,int $actor,string $reason='application disabled'):void
    {
        $this->db->transaction(function(Database$db)use($appId):void{$db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$appId]);$db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$appId]);$db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$appId]);});
        $this->audit->write('application.tokens.revoked','success',$actor,null,$appId,$reason);
    }

    private function tenantMembershipActive(int$userId,int$orgId):bool{return $this->db->one("SELECT 1 FROM organization_memberships om JOIN organizations o ON o.id=om.organization_id WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND (om.valid_from IS NULL OR om.valid_from<=NOW()) AND (om.valid_until IS NULL OR om.valid_until>NOW())",[$orgId,$userId])!==null;}
    private function userIsActive(?array$u):bool{if(!$u||!(bool)$u['enabled']||$u['lifecycle_status']!=='active')return false;$now=time();if(!empty($u['account_starts_at'])&&strtotime((string)$u['account_starts_at'])>$now)return false;if(!empty($u['account_ends_at'])&&strtotime((string)$u['account_ends_at'])<=$now)return false;return true;}
    private function directUserOverride(int$userId,int$appId):?bool{$r=$this->db->one('SELECT enabled,valid_from,valid_until,revoked_at FROM application_users WHERE application_id=? AND user_id=?',[$appId,$userId]);if($r===null)return null;if(!(bool)$r['enabled']||$r['revoked_at']!==null)return false;$now=time();if(!empty($r['valid_from'])&&strtotime((string)$r['valid_from'])>$now)return false;if(!empty($r['valid_until'])&&strtotime((string)$r['valid_until'])<=$now)return false;return true;}
    private function groupAccess(int$u,int$a):bool{return $this->db->one('SELECT 1 FROM application_groups ag JOIN group_members gm ON gm.group_id=ag.group_id WHERE ag.application_id=? AND gm.user_id=? LIMIT 1',[$a,$u])!==null;}
    private function systemRoleAccess(int$u,int$a):bool{return $this->db->one('SELECT 1 FROM application_system_roles ar JOIN user_system_roles ur ON ur.role_id=ar.role_id WHERE ar.application_id=? AND ur.user_id=? LIMIT 1',[$a,$u])!==null;}
    private function matchingDynamicRules(int$userId,int$appId,array$context):array{$rules=$this->db->all('SELECT id,rule_type,effect,condition_json FROM dynamic_access_rules WHERE application_id=? AND enabled=1 ORDER BY priority,id',[$appId]);$matched=[];foreach($rules as$r){$c=json_decode((string)$r['condition_json'],true);if(is_array($c)&&$this->matchesCondition($userId,(string)$r['rule_type'],$c,$context))$matched[]=$r;}return $matched;}
    private function matchesCondition(int$userId,string$type,array$c,array$ctx):bool{return match($type){'group'=>isset($c['group_id'])&&$this->db->one('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',[(int)$c['group_id'],$userId])!==null,'system_role'=>isset($c['role_id'])&&$this->db->one('SELECT 1 FROM user_system_roles WHERE role_id=? AND user_id=?',[(int)$c['role_id'],$userId])!==null,'attribute'=>$this->matchesAttribute($userId,$c),'ip','network_zone'=>$this->matchesIp((string)($ctx['ip']??Security::currentIp()),$c),'country'=>$this->matchesCountry((string)($ctx['country_code']??''),$c),'time'=>$this->matchesTime($c),'compound'=>$this->matchesCompound($userId,$c,$ctx),default=>false};}
    private function matchesAttribute(int$userId,array$c):bool{$key=(string)($c['key']??'');if($key==='')return false;$r=$this->db->one('SELECT attribute_value FROM user_attributes WHERE user_id=? AND attribute_key=?',[$userId,$key]);$op=(string)($c['operator']??'equals');if($op==='exists')return$r!==null;if(!$r)return false;$actual=(string)$r['attribute_value'];$expected=$c['value']??null;return match($op){'equals'=>$actual===(string)$expected,'not_equals'=>$actual!==(string)$expected,'contains'=>str_contains(mb_strtolower($actual),mb_strtolower((string)$expected)),'in'=>is_array($expected)&&in_array($actual,array_map('strval',$expected),true),default=>false};}
    private function matchesIp(string$ip,array$c):bool{if($ip==='')return false;$cidrs=$c['cidrs']??($c['cidr']??[]);if(is_string($cidrs))$cidrs=[$cidrs];if(!is_array($cidrs))return false;foreach($cidrs as$cidr)if(Security::ipInCidr($ip,(string)$cidr))return true;return false;}
    private function matchesCountry(string$country,array$c):bool{$countries=$c['countries']??[];return$country!==''&&is_array($countries)&&in_array(strtoupper($country),array_map(static fn($v)=>strtoupper((string)$v),$countries),true);}
    private function matchesTime(array$c):bool{try{$tz=new \DateTimeZone((string)($c['timezone']??'UTC'));}catch(\Throwable){return false;}$now=new \DateTimeImmutable('now',$tz);$days=$c['days']??[];if(is_array($days)&&$days!==[]&&!in_array((int)$now->format('N'),array_map('intval',$days),true))return false;$start=(string)($c['start']??'00:00');$end=(string)($c['end']??'23:59');$current=$now->format('H:i');return$start<=$end?($current>=$start&&$current<=$end):($current>=$start||$current<=$end);}
    private function matchesCompound(int$u,array$c,array$ctx):bool{$rules=$c['rules']??[];if(!is_array($rules)||$rules===[])return false;$results=[];foreach($rules as$r)if(is_array($r))$results[]=$this->matchesCondition($u,(string)($r['type']??''),(array)($r['condition']??[]),$ctx);if($results===[])return false;return(string)($c['operator']??'and')==='or'?in_array(true,$results,true):!in_array(false,$results,true);}
}
