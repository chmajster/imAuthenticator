<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'ImAuthenticator\\';
    if (!str_starts_with($class, $prefix)) return;
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) require $path;
});

use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\Database;
use ImAuthenticator\Security;

function check(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    fwrite(STDOUT, "OK: {$message}\n");
}

$testDbDsn = getenv('TEST_DB_DSN');
$testDbUser = getenv('TEST_DB_USER');
$testDbPass = getenv('TEST_DB_PASS');
$db = new Database([
    'dsn' => $testDbDsn === false ? 'mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4' : $testDbDsn,
    'user' => $testDbUser === false ? 'root' : $testDbUser,
    'pass' => $testDbPass === false ? 'root' : $testDbPass,
]);
$audit = new AuditLog($db);
$access = new ApplicationAccessService($db, $audit);

$db->execute('DELETE FROM audit_log');
$db->execute('DELETE FROM oauth_refresh_tokens');
$db->execute('DELETE FROM oauth_access_tokens');
$db->execute('DELETE FROM application_users');
$db->execute('DELETE FROM applications');
$db->execute('DELETE FROM users');

$pwd = password_hash('test-password-not-used', PASSWORD_ARGON2ID);
$db->execute('INSERT INTO users(uuid,name,email,password_hash,enabled) VALUES(?,?,?,?,1)', [Security::uuidV4(),'User One','one@example.test',$pwd]);
$user1 = $db->lastInsertId();
$db->execute('INSERT INTO users(uuid,name,email,password_hash,enabled) VALUES(?,?,?,?,1)', [Security::uuidV4(),'User Two','two@example.test',$pwd]);
$user2 = $db->lastInsertId();
$db->execute("INSERT INTO applications(uuid,name,slug,url,client_id,client_type,access_policy,enabled) VALUES(?,?,?,?,?,'confidential','none',1)", [Security::uuidV4(),'Test App','test-app','https://app.example.test','ima_test_client']);
$appId = $db->lastInsertId();
$app = $db->one('SELECT * FROM applications WHERE id=?', [$appId]);

check(!$access->hasAccess($user1, $app), 'new application denies access by default');
$access->grantUser($appId, $user1, $user2);
check($access->hasAccess($user1, $app), 'explicit user grant works while policy is none');

$db->execute("UPDATE applications SET access_policy='all' WHERE id=?", [$appId]);
$app = $db->one('SELECT * FROM applications WHERE id=?', [$appId]);
check($access->hasAccess($user2, $app), 'policy all grants an active user');

$db->execute("INSERT INTO oauth_access_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,'openid',DATE_ADD(NOW(),INTERVAL 1 HOUR))", [hash('sha256','access-test'),$appId,$user1]);
$db->execute("INSERT INTO oauth_refresh_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,'openid',DATE_ADD(NOW(),INTERVAL 1 DAY))", [hash('sha256','refresh-test'),$appId,$user1]);
$access->revokeUser($appId, $user1, $user2);
check(!$access->hasAccess($user1, $app), 'explicit deny overrides policy all');
$at = $db->one('SELECT revoked_at FROM oauth_access_tokens WHERE token_hash=?', [hash('sha256','access-test')]);
$rt = $db->one('SELECT revoked_at FROM oauth_refresh_tokens WHERE token_hash=?', [hash('sha256','refresh-test')]);
check(!empty($at['revoked_at']), 'access token is revoked immediately');
check(!empty($rt['revoked_at']), 'refresh token is revoked immediately');

$access->grantUser($appId, $user1, $user2);
check($access->hasAccess($user1, $app), 'grant removes explicit deny override');

fwrite(STDOUT, "Access policy smoke test passed.\n");
