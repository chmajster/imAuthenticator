<?php
declare(strict_types=1);

use ImAuthenticator\AccessRequestService;
use ImAuthenticator\AccessReviewService;
use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\ApplicationAdminService;
use ImAuthenticator\AuditIntegrityService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\AuthService;
use ImAuthenticator\ClientSecretService;
use ImAuthenticator\ConditionalAccessService;
use ImAuthenticator\Database;
use ImAuthenticator\DeviceRiskService;
use ImAuthenticator\DirectorySyncService;
use ImAuthenticator\EventService;
use ImAuthenticator\OidcService;
use ImAuthenticator\PasskeyChallengeService;
use ImAuthenticator\ScimService;
use ImAuthenticator\SessionService;

spl_autoload_register(static function (string $class): void {
    $prefix='ImAuthenticator\\';
    if(!str_starts_with($class,$prefix)) return;
    $path=__DIR__.'/'.str_replace('\\','/',substr($class,strlen($prefix))).'.php';
    if(is_file($path)) require $path;
});

$configFile=dirname(__DIR__).'/config/config.php';
if(!is_file($configFile)){
    if(PHP_SAPI!=='cli'){header('Location: /install.php');exit;}
    throw new RuntimeException('Application is not installed.');
}
$config=require $configFile;
if(!is_array($config)) throw new RuntimeException('Invalid configuration.');
$isHttps=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')||(($_SERVER['HTTP_X_FORWARDED_PROTO']??'')==='https');
session_name((string)($config['session_name']??'imauthenticator_session'));
session_set_cookie_params(['httponly'=>true,'secure'=>$isHttps,'samesite'=>'Lax','path'=>'/']);
if(session_status()!==PHP_SESSION_ACTIVE) session_start();

$db=new Database($config['db']);
$audit=new AuditLog($db);
$auditIntegrity=new AuditIntegrityService($db);
$events=new EventService($db);
$access=new ApplicationAccessService($db,$audit);
$appAdmins=new ApplicationAdminService($db);
$conditional=new ConditionalAccessService($db,$access);
$auth=new AuthService($db,$audit);
$risk=new DeviceRiskService($db);
$requests=new AccessRequestService($db,$access,$appAdmins,$audit,$events);
$reviews=new AccessReviewService($db,$access,$appAdmins,$audit,$events);
$sessions=new SessionService($db,$audit,$events);
$clientSecrets=new ClientSecretService($db,$appAdmins,$audit,$events);
$passkeys=new PasskeyChallengeService($db,$config,$audit);
$scim=new ScimService($db,$access,$audit,$events);
$directory=new DirectorySyncService($db,$audit,$events);
$oidc=new OidcService($db,$access,$conditional,$audit,$config);

return compact('config','db','audit','auditIntegrity','events','access','appAdmins','conditional','auth','risk','requests','reviews','sessions','clientSecrets','passkeys','scim','directory','oidc');
