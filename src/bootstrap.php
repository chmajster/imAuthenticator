<?php
declare(strict_types=1);

use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\AuthService;
use ImAuthenticator\Database;
use ImAuthenticator\OidcService;

spl_autoload_register(static function (string $class): void {
    $prefix = 'ImAuthenticator\\';
    if (!str_starts_with($class, $prefix)) return;
    $path = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($path)) require $path;
});

$configFile = dirname(__DIR__) . '/config/config.php';
if (!is_file($configFile)) {
    if (PHP_SAPI !== 'cli') {
        header('Location: /install.php');
        exit;
    }
    throw new RuntimeException('Application is not installed.');
}

$config = require $configFile;
if (!is_array($config)) throw new RuntimeException('Invalid configuration.');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_name((string)($config['session_name'] ?? 'imauthenticator_session'));
session_set_cookie_params(['httponly' => true, 'secure' => $isHttps, 'samesite' => 'Lax', 'path' => '/']);
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$db = new Database($config['db']);
$audit = new AuditLog($db);
$access = new ApplicationAccessService($db, $audit);
$auth = new AuthService($db, $audit);
$oidc = new OidcService($db, $access, $audit, $config);

return compact('config', 'db', 'audit', 'access', 'auth', 'oidc');
