<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'ImAuthenticator\\';
    if (!str_starts_with($class, $prefix)) return;
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) require $path;
});

use ImAuthenticator\AccessRequestService;
use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\ApplicationAdminService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\ConditionalAccessService;
use ImAuthenticator\Database;
use ImAuthenticator\EventService;
use ImAuthenticator\Security;

function checkEnterprise(bool $condition, string $message): void
{
    if (!$condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    fwrite(STDOUT, "OK: {$message}\n");
}

$env = static function (string $name, string $default): string {
    $value = getenv($name);
    return $value === false ? $default : $value;
};
$db = new Database(['dsn'=>$env('TEST_DB_DSN','mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4'),'user'=>$env('TEST_DB_USER','root'),'pass'=>$env('TEST_DB_PASS','')]);
$audit = new AuditLog($db);
$events = new EventService($db);
$access = new ApplicationAccessService($db,$audit);
$admins = new ApplicationAdminService($db);
$conditional = new ConditionalAccessService($db,$access);
$requests = new AccessRequestService($db,$access,$admins,$audit,$events);

$suffix = bin2hex(random_bytes(4));
$hash = password_hash('enterprise-test-password', PASSWORD_ARGON2ID);
$db->execute('INSERT INTO users(uuid,name,username,email,password_hash,is_admin,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,1,\'active\')', [Security::uuidV4(),'Enterprise Admin','admin-'.$suffix,'admin-'.$suffix.'@example.test',$hash]);
$adminId = $db->lastInsertId();
$db->execute('INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,\'active\')', [Security::uuidV4(),'Enterprise User','user-'.$suffix,'user-'.$suffix.'@example.test',$hash]);
$userId = $db->lastInsertId();
$db->execute("INSERT INTO applications(uuid,name,slug,url,client_id,client_type,access_policy,enabled) VALUES(?,?,?,?,?,'confidential','none',1)", [Security::uuidV4(),'Enterprise App','enterprise-'.$suffix,'https://enterprise.example.test','ima_ent_'.$suffix]);
$appId = $db->lastInsertId();
$app = $db->one('SELECT * FROM applications WHERE id=?', [$appId]);

checkEnterprise(!$access->hasAccess($userId,$app), 'default policy denies user');
$access->grantUser($appId,$userId,$adminId,null,date('Y-m-d H:i:s', time()-60));
checkEnterprise(!$access->hasAccess($userId,$app), 'expired temporal grant is denied');
$access->grantUser($appId,$userId,$adminId,null,date('Y-m-d H:i:s', time()+3600));
checkEnterprise($access->hasAccess($userId,$app), 'active temporal grant is allowed');

$db->execute('DELETE FROM application_users WHERE application_id=? AND user_id=?', [$appId,$userId]);
$db->execute("INSERT INTO user_attributes(user_id,attribute_key,attribute_value) VALUES(?,'department','IT')", [$userId]);
$db->execute("INSERT INTO dynamic_access_rules(application_id,name,rule_type,effect,priority,condition_json) VALUES(?,'IT department','attribute','allow',10,?)", [$appId,json_encode(['key'=>'department','operator'=>'equals','value'=>'IT'])]);
checkEnterprise($access->hasAccess($userId,$app), 'ABAC attribute rule grants access');
$db->execute("INSERT INTO dynamic_access_rules(application_id,name,rule_type,effect,priority,condition_json) VALUES(?,'blocked network','ip','deny',1,?)", [$appId,json_encode(['cidrs'=>['203.0.113.0/24']])]);
checkEnterprise(!$access->hasAccess($userId,$app,['ip'=>'203.0.113.7']), 'dynamic deny overrides ABAC allow');
checkEnterprise($access->hasAccess($userId,$app,['ip'=>'198.51.100.7']), 'dynamic deny does not affect other networks');

$db->execute('INSERT INTO application_security_policies(application_id,require_mfa,minimum_auth_level,risk_threshold) VALUES(?,1,1,70)', [$appId]);
$decision = $conditional->evaluate($userId,$app,['auth_level'=>1,'auth_time'=>time(),'ip'=>'198.51.100.7','risk_score'=>0]);
checkEnterprise(!$decision['allowed'] && $decision['action']==='mfa', 'application MFA policy requires level 2');
$decision = $conditional->evaluate($userId,$app,['auth_level'=>2,'auth_time'=>time(),'ip'=>'198.51.100.7','risk_score'=>0]);
checkEnterprise($decision['allowed'], 'MFA-authenticated session satisfies policy');
$decision = $conditional->evaluate($userId,$app,['auth_level'=>2,'auth_time'=>time(),'ip'=>'198.51.100.7','risk_score'=>90]);
checkEnterprise(!$decision['allowed'] && $decision['action']==='deny', 'risk threshold blocks high-risk authentication');

$db->execute('DELETE FROM dynamic_access_rules WHERE application_id=?', [$appId]);
$requestId = $requests->request($appId,$userId,null,3600,'Temporary project access');
$requests->approve($requestId,$adminId,'Approved for project window');
$grant = $db->one('SELECT enabled,grant_source,valid_until FROM application_users WHERE application_id=? AND user_id=?', [$appId,$userId]);
checkEnterprise((bool)$grant['enabled'] && $grant['grant_source']==='request' && $grant['valid_until']!==null, 'approved request creates expiring grant');

$db->execute("UPDATE users SET lifecycle_status='suspended' WHERE id=?", [$userId]);
checkEnterprise(!$access->hasAccess($userId,$app), 'suspended lifecycle account cannot access application');

$latestAudit = $db->one('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1');
checkEnterprise(!empty($latestAudit['entry_hash']), 'audit log contains tamper-evident hash');
$outbox = $db->one("SELECT 1 FROM event_outbox WHERE event_type='access.granted' ORDER BY id DESC LIMIT 1");
checkEnterprise($outbox !== null, 'access approval emits security event');

fwrite(STDOUT, "Enterprise security smoke test passed.\n");
