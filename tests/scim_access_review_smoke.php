<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'ImAuthenticator\\';
    if (!str_starts_with($class, $prefix)) return;
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) require $path;
});

use ImAuthenticator\AccessReviewService;
use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\ApplicationAdminService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\Database;
use ImAuthenticator\EventService;
use ImAuthenticator\ScimService;
use ImAuthenticator\Security;

function checkScim(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    fwrite(STDOUT, "OK: {$message}\n");
}

$env = static function (string $name, string $default): string {
    $value = getenv($name);
    return $value === false ? $default : $value;
};

$db = new Database([
    'dsn' => $env('TEST_DB_DSN', 'mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4'),
    'user' => $env('TEST_DB_USER', 'root'),
    'pass' => $env('TEST_DB_PASS', ''),
]);
$audit = new AuditLog($db);
$events = new EventService($db);
$access = new ApplicationAccessService($db, $audit);
$admins = new ApplicationAdminService($db);
$scim = new ScimService($db, $access, $audit, $events);
$reviews = new AccessReviewService($db, $access, $admins, $audit, $events);

$suffix = bin2hex(random_bytes(4));
$password = password_hash(Security::randomToken(32), PASSWORD_ARGON2ID);
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,is_admin,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,1,'active')", [Security::uuidV4(),'SCIM Admin','scim-admin-'.$suffix,'scim-admin-'.$suffix.'@example.test',$password]);
$adminId = $db->lastInsertId();
$db->execute("INSERT INTO applications(uuid,name,slug,url,client_id,client_type,access_policy,enabled) VALUES(?,?,?,?,?,'confidential','none',1)", [Security::uuidV4(),'SCIM App','scim-app-'.$suffix,'https://scim.example.test','ima_scim_'.$suffix]);
$appId = $db->lastInsertId();
$token = 'scim_test_'.Security::randomToken(24);
$db->execute("INSERT INTO scim_connectors(application_id,enabled,direction,bearer_token_hash,mapping_json) VALUES(?,1,'inbound',?,?)", [$appId,hash('sha256',$token),'{}']);
$connectorId = $db->lastInsertId();

$connector = $scim->authenticate($connectorId, $token);
checkScim((int)$connector['application_id'] === $appId, 'SCIM bearer token authenticates connector');
$unauthorized = false;
try { $scim->authenticate($connectorId, 'wrong-token'); } catch (RuntimeException) { $unauthorized = true; }
checkScim($unauthorized, 'invalid SCIM token is rejected');

$resource = $scim->createUser($connector, [
    'userName' => 'provisioned-'.$suffix,
    'displayName' => 'Provisioned User',
    'externalId' => 'ext-'.$suffix,
    'emails' => [['value'=>'provisioned-'.$suffix.'@example.test','primary'=>true]],
]);
checkScim(!empty($resource['id']) && $resource['active'] === true, 'SCIM creates and provisions user');
$user = $db->one('SELECT id FROM users WHERE uuid=?', [$resource['id']]);
$userId = (int)$user['id'];
$app = $db->one('SELECT * FROM applications WHERE id=?', [$appId]);
checkScim($access->hasAccess($userId, $app), 'SCIM provisioning grants application access');

$scim->patchUser($connector, $resource['id'], ['Operations'=>[['op'=>'replace','path'=>'active','value'=>false]]]);
checkScim(!$access->hasAccess($userId, $app), 'SCIM active=false immediately revokes access');
$scim->patchUser($connector, $resource['id'], ['Operations'=>[['op'=>'replace','path'=>'active','value'=>true]]]);
checkScim($access->hasAccess($userId, $app), 'SCIM active=true restores access');

$reviewId = $reviews->create($appId, $adminId, $adminId, 'SCIM quarterly review', date('Y-m-d\TH:i', time()+86400));
$item = $db->one('SELECT * FROM access_review_items WHERE access_review_id=? AND user_id=?', [$reviewId,$userId]);
checkScim($item !== null, 'access review snapshots current application access');
$reviews->decide($reviewId, $userId, 'revoke', $adminId, 'No longer needed');
checkScim(!$access->hasAccess($userId, $app), 'access review revoke removes access immediately');
$reviews->complete($reviewId, $adminId);
$review = $db->one('SELECT status FROM access_reviews WHERE id=?', [$reviewId]);
checkScim(($review['status'] ?? '') === 'completed', 'access review completes after all decisions');

fwrite(STDOUT, "SCIM and access review smoke test passed.\n");
