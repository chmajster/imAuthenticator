<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ApplicationAccessService
{
    public function __construct(private Database $db, private AuditLog $audit) {}

    public function hasAccess(int $userId, array|int $application, array $context = []): bool
    {
        $app = is_array($application) ? $application : $this->db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$application]);
        if (!$app || !(bool)$app['enabled']) return false;
        $user = $this->db->one('SELECT id,enabled,lifecycle_status,account_starts_at,account_ends_at FROM users WHERE id=?', [$userId]);
        if (!$this->userIsActive($user)) return false;
        $direct = $this->directUserOverride($userId, (int)$app['id']);
        if ($direct === false) return false;
        $allowed = $direct === true || match ($app['access_policy']) {
            'all' => true,
            'groups' => $this->groupAccess($userId, (int)$app['id']),
            'roles' => $this->systemRoleAccess($userId, (int)$app['id']),
            'mixed' => $this->groupAccess($userId, (int)$app['id']) || $this->systemRoleAccess($userId, (int)$app['id']),
            default => false,
        };
        foreach ($this->matchingDynamicRules($userId, (int)$app['id'], $context) as $rule) {
            if ($rule['effect'] === 'deny') return false;
            if ($rule['effect'] === 'allow') $allowed = true;
        }
        return $allowed;
    }

    public function directUserAccess(int $userId, int $applicationId): bool { return $this->directUserOverride($userId, $applicationId) === true; }
    public function matchingDynamicEffects(int $userId, int $applicationId, array $context = []): array { return array_values(array_unique(array_column($this->matchingDynamicRules($userId,$applicationId,$context),'effect'))); }

    private function userIsActive(?array $user): bool
    {
        if (!$user || !(bool)$user['enabled'] || $user['lifecycle_status'] !== 'active') return false;
        $now=time();
        if (!empty($user['account_starts_at']) && strtotime((string)$user['account_starts_at'])>$now) return false;
        if (!empty($user['account_ends_at']) && strtotime((string)$user['account_ends_at'])<=$now) return false;
        return true;
    }

    private function directUserOverride(int $userId,int $applicationId): ?bool
    {
        $row=$this->db->one('SELECT enabled,valid_from,valid_until,revoked_at FROM application_users WHERE application_id=? AND user_id=?',[$applicationId,$userId]);
        if($row===null) return null;
        if(!(bool)$row['enabled']||$row['revoked_at']!==null) return false;
        $now=time();
        if(!empty($row['valid_from'])&&strtotime((string)$row['valid_from'])>$now) return false;
        if(!empty($row['valid_until'])&&strtotime((string)$row['valid_until'])<=$now) return false;
        return true;
    }
    private function groupAccess(int $userId,int $applicationId): bool { return $this->db->one('SELECT 1 FROM application_groups ag JOIN group_members gm ON gm.group_id=ag.group_id WHERE ag.application_id=? AND gm.user_id=? LIMIT 1',[$applicationId,$userId])!==null; }
    private function systemRoleAccess(int $userId,int $applicationId): bool { return $this->db->one('SELECT 1 FROM application_system_roles ar JOIN user_system_roles ur ON ur.role_id=ar.role_id WHERE ar.application_id=? AND ur.user_id=? LIMIT 1',[$applicationId,$userId])!==null; }

    private function matchingDynamicRules(int $userId,int $applicationId,array $context): array
    {
        $rules=$this->db->all('SELECT id,rule_type,effect,condition_json FROM dynamic_access_rules WHERE application_id=? AND enabled=1 ORDER BY priority,id',[$applicationId]); $matched=[];
        foreach($rules as $rule){$condition=json_decode((string)$rule['condition_json'],true);if(is_array($condition)&&$this->matchesCondition($userId,(string)$rule['rule_type'],$condition,$context))$matched[]=$rule;} return $matched;
    }
    private function matchesCondition(int $userId,string $type,array $condition,array $context): bool
    {
        return match($type){
            'group'=>isset($condition['group_id'])&&$this->db->one('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',[(int)$condition['group_id'],$userId])!==null,
            'system_role'=>isset($condition['role_id'])&&$this->db->one('SELECT 1 FROM user_system_roles WHERE role_id=? AND user_id=?',[(int)$condition['role_id'],$userId])!==null,
            'attribute'=>$this->matchesAttribute($userId,$condition),
            'ip','network_zone'=>$this->matchesIp((string)($context['ip']??Security::currentIp()),$condition),
            'country'=>$this->matchesCountry((string)($context['country_code']??''),$condition),
            'time'=>$this->matchesTime($condition),
            'compound'=>$this->matchesCompound($userId,$condition,$context),
            default=>false,
        };
    }
    private function matchesAttribute(int $userId,array $condition): bool
    {
        $key=(string)($condition['key']??'');if($key==='')return false;$row=$this->db->one('SELECT attribute_value FROM user_attributes WHERE user_id=? AND attribute_key=?',[$userId,$key]);$operator=(string)($condition['operator']??'equals');if($operator==='exists')return $row!==null;if(!$row)return false;$actual=(string)$row['attribute_value'];$expected=$condition['value']??null;
        return match($operator){'equals'=>$actual===(string)$expected,'not_equals'=>$actual!==(string)$expected,'contains'=>str_contains(mb_strtolower($actual),mb_strtolower((string)$expected)),'in'=>is_array($expected)&&in_array($actual,array_map('strval',$expected),true),default=>false};
    }
    private function matchesIp(string $ip,array $condition): bool { if($ip==='')return false;$cidrs=$condition['cidrs']??($condition['cidr']??[]);if(is_string($cidrs))$cidrs=[$cidrs];if(!is_array($cidrs))return false;foreach($cidrs as $cidr)if(Security::ipInCidr($ip,(string)$cidr))return true;return false; }
    private function matchesCountry(string $country,array $condition): bool { $countries=$condition['countries']??[];return $country!==''&&is_array($countries)&&in_array(strtoupper($country),array_map(static fn($v)=>strtoupper((string)$v),$countries),true); }
    private function matchesTime(array $condition): bool { try{$tz=new \DateTimeZone((string)($condition['timezone']??'UTC'));}catch(\Throwable){return false;}$now=new \DateTimeImmutable('now',$tz);$days=$condition['days']??[];if(is_array($days)&&$days!==[]&&!in_array((int)$now->format('N'),array_map('intval',$days),true))return false;$start=(string)($condition['start']??'00:00');$end=(string)($condition['end']??'23:59');$current=$now->format('H:i');return $start<=$end?($current>=$start&&$current<=$end):($current>=$start||$current<=$end); }
    private function matchesCompound(int $userId,array $condition,array $context): bool { $rules=$condition['rules']??[];if(!is_array($rules)||$rules===[])return false;$results=[];foreach($rules as $rule){if(!is_array($rule))continue;$results[]=$this->matchesCondition($userId,(string)($rule['type']??''),(array)($rule['condition']??[]),$context);}if($results===[])return false;return (string)($condition['operator']??'and')==='or'?in_array(true,$results,true):!in_array(false,$results,true); }

    public function rolesForUser(int $userId,int $applicationId): array { return array_column($this->db->all('SELECT r.name FROM app_user_roles ur JOIN app_roles r ON r.id=ur.app_role_id AND r.application_id=ur.application_id WHERE ur.application_id=? AND ur.user_id=? ORDER BY r.name',[$applicationId,$userId]),'name'); }

    public function grantUser(int $applicationId,int $userId,?int $actorUserId,?string $validFrom=null,?string $validUntil=null,string $source='manual'): void
    {
        $allowedSources=['manual','request','dynamic','scim','sync','system'];if(!in_array($source,$allowedSources,true))$source='manual';
        $this->db->execute('INSERT INTO application_users(application_id,user_id,enabled,valid_from,valid_until,grant_source,created_by) VALUES(?,?,1,?,?,?,?) ON DUPLICATE KEY UPDATE enabled=1,valid_from=VALUES(valid_from),valid_until=VALUES(valid_until),grant_source=VALUES(grant_source),revoked_at=NULL,revoke_reason=NULL,created_by=VALUES(created_by),created_at=CURRENT_TIMESTAMP',[$applicationId,$userId,$validFrom,$validUntil,$source,$actorUserId]);
        $this->audit->write('application.user.granted','success',$actorUserId,$userId,$applicationId,null,['valid_from'=>$validFrom,'valid_until'=>$validUntil,'source'=>$source]);
    }
    public function revokeUser(int $applicationId,int $userId,?int $actorUserId,string $reason='explicit deny override'): void
    {
        $this->db->transaction(function(Database $db)use($applicationId,$userId,$actorUserId,$reason):void{$db->execute('INSERT INTO application_users(application_id,user_id,enabled,grant_source,revoked_at,revoke_reason,created_by) VALUES(?,?,0,\'manual\',NOW(),?,?) ON DUPLICATE KEY UPDATE enabled=0,revoked_at=NOW(),revoke_reason=VALUES(revoke_reason),created_by=VALUES(created_by),created_at=CURRENT_TIMESTAMP',[$applicationId,$userId,$reason,$actorUserId]);$db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$applicationId,$userId]);$db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$applicationId,$userId]);$db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=? AND user_id=?',[$applicationId,$userId]);});
        $this->audit->write('application.user.revoked','success',$actorUserId,$userId,$applicationId,$reason);
    }
    public function revokeApplication(int $applicationId,int $actorUserId,string $reason='application disabled'): void { $this->db->transaction(function(Database $db)use($applicationId):void{$db->execute('UPDATE oauth_refresh_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$applicationId]);$db->execute('UPDATE oauth_access_tokens SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$applicationId]);$db->execute('UPDATE oidc_sessions SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) WHERE application_id=?',[$applicationId]);});$this->audit->write('application.tokens.revoked','success',$actorUserId,null,$applicationId,$reason); }
}
