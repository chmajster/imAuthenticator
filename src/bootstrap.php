<?php
declare(strict_types=1);

use ImAuthenticator\AccessRequestService;
use ImAuthenticator\AccessReviewService;
use ImAuthenticator\ApiKeyService;
use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\ApplicationAdminService;
use ImAuthenticator\AppLauncherService;
use ImAuthenticator\AuditIntegrityService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\AuthService;
use ImAuthenticator\ClientSecretService;
use ImAuthenticator\ConditionalAccessService;
use ImAuthenticator\ConsentService;
use ImAuthenticator\CryptoService;
use ImAuthenticator\Database;
use ImAuthenticator\DeliveryService;
use ImAuthenticator\DeviceRiskService;
use ImAuthenticator\DirectorySyncService;
use ImAuthenticator\EmailIdentityService;
use ImAuthenticator\EventService;
use ImAuthenticator\ExternalIdentityService;
use ImAuthenticator\HousekeepingService;
use ImAuthenticator\ImpersonationService;
use ImAuthenticator\IntegrationToolkitService;
use ImAuthenticator\JwtService;
use ImAuthenticator\LogoutPropagationService;
use ImAuthenticator\MagicLinkService;
use ImAuthenticator\MailQueueService;
use ImAuthenticator\OAuthAdvancedService;
use ImAuthenticator\OAuthProofService;
use ImAuthenticator\OAuthSecurityService;
use ImAuthenticator\OidcService;
use ImAuthenticator\PasskeyChallengeService;
use ImAuthenticator\RequiredActionService;
use ImAuthenticator\SamlIdpService;
use ImAuthenticator\ScimService;
use ImAuthenticator\SessionService;
use ImAuthenticator\SigningKeyService;
use ImAuthenticator\SystemSettingsService;

$vendorAutoload=dirname(__DIR__).'/vendor/autoload.php';
if(is_file($vendorAutoload)) require_once $vendorAutoload;

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
$settings=new SystemSettingsService($db,$audit);
$mail=new MailQueueService($db,$audit,$config);
$crypto=new CryptoService($config);
$delivery=new DeliveryService($db,$crypto,$settings,$mail,$audit);
$apiKeys=new ApiKeyService($db,$audit);
$access=new ApplicationAccessService($db,$audit);
$appAdmins=new ApplicationAdminService($db);
$conditional=new ConditionalAccessService($db,$access);
$auth=new AuthService($db,$audit,$settings);
$risk=new DeviceRiskService($db);
$requests=new AccessRequestService($db,$access,$appAdmins,$audit,$events);
$reviews=new AccessReviewService($db,$access,$appAdmins,$audit,$events);
$sessions=new SessionService($db,$audit,$events);
$clientSecrets=new ClientSecretService($db,$appAdmins,$audit,$events);
$passkeys=new PasskeyChallengeService($db,$config,$audit);
$scim=new ScimService($db,$access,$audit,$events);
$directory=new DirectorySyncService($db,$audit,$events);
$jwt=new JwtService($config);
$oauthProofs=new OAuthProofService($db,$jwt,$audit);
$signingKeys=new SigningKeyService($db,$audit,$config,$configFile);
$logoutPropagation=new LogoutPropagationService($db,$audit,$jwt);
$oauthAdvanced=new OAuthAdvancedService($db,$access,$conditional,$audit,$jwt,$config);
$oauthSecurity=new OAuthSecurityService($db,$access,$audit);
$oidc=new OidcService($db,$access,$conditional,$audit,$config);
$externalIdentity=new ExternalIdentityService($db,$settings,$audit,$config);
$saml=new SamlIdpService($db,$access,$conditional,$audit,$config);
$magicLinks=new MagicLinkService($db,$mail,$audit,$config);
$consents=new ConsentService($db,$audit);
$requiredActions=new RequiredActionService($db,$audit);
$emails=new EmailIdentityService($db,$mail,$audit,$config);
$impersonation=new ImpersonationService($db,$audit);
$launcher=new AppLauncherService($db,$access);
$toolkit=new IntegrationToolkitService($db,$config);
$housekeeping=new HousekeepingService($db,$settings,$audit,$sessions);

return compact('config','configFile','db','audit','auditIntegrity','events','settings','mail','crypto','delivery','apiKeys','access','appAdmins','conditional','auth','risk','requests','reviews','sessions','clientSecrets','passkeys','scim','directory','jwt','oauthProofs','signingKeys','logoutPropagation','oauthAdvanced','oauthSecurity','oidc','externalIdentity','saml','magicLinks','consents','requiredActions','emails','impersonation','launcher','toolkit','housekeeping');
