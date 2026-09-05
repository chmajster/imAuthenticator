<?php
declare(strict_types=1);

spl_autoload_register(static function(string $class):void{$prefix='ImAuthenticator\\';if(!str_starts_with($class,$prefix))return;$path=dirname(__DIR__).'/src/'.str_replace('\\','/',substr($class,strlen($prefix))).'.php';if(is_file($path))require$path;});

use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\ApplicationAdminService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\AuthService;
use ImAuthenticator\Database;
use ImAuthenticator\DeviceIdentityService;
use ImAuthenticator\DeviceRiskService;
use ImAuthenticator\EventService;
use ImAuthenticator\OrganizationService;
use ImAuthenticator\Security;
use ImAuthenticator\SystemSettingsService;

if(session_status()!==PHP_SESSION_ACTIVE){session_name('imauth_tenant_runtime_test');session_start();}
function checkRuntime(bool $ok,string $message):void{if(!$ok){fwrite(STDERR,"FAIL: {$message}\n");exit(1);}fwrite(STDOUT,"OK: {$message}\n");}
$env=static function(string$n,string$d):string{$v=getenv($n);return$v===false?$d:$v;};
$db=new Database(['dsn'=>$env('TEST_DB_DSN','mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4'),'user'=>$env('TEST_DB_USER','root'),'pass'=>$env('TEST_DB_PASS','')]);
$audit=new AuditLog($db);$events=new EventService($db);$settings=new SystemSettingsService($db,$audit);$organizations=new OrganizationService($db,$audit);$devices=new DeviceIdentityService($db,['security'=>[]]);$risk=new DeviceRiskService($db);$access=new ApplicationAccessService($db,$audit,$organizations);$admins=new ApplicationAdminService($db);$auth=new AuthService($db,$audit,$settings,$devices,$risk,$events,$organizations);
$suffix=bin2hex(random_bytes(4));$password='Tenant-runtime-password-123!';$hash=password_hash($password,PASSWORD_ARGON2ID);
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,is_admin,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,1,'active')",[Security::uuidV4(),'Tenant Root','root-'.$suffix,'root-'.$suffix.'@example.test',$hash]);$root=$db->lastInsertId();
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),'Tenant User','member-'.$suffix,'member-'.$suffix.'@example.test',$hash]);$member=$db->lastInsertId();
$org=$organizations->create('Tenant '.$suffix,'tenant-'.$suffix,$root);
$db->execute("INSERT INTO applications(organization_id,uuid,name,slug,url,client_id,client_type,access_policy,enabled) VALUES(?,?,?,?,?,?,'confidential','none',1)",[$org,Security::uuidV4(),'Tenant App','tenant-app-'.$suffix,'https://tenant.example.test','ima_tenant_'.$suffix]);$appId=$db->lastInsertId();$app=$db->one('SELECT * FROM applications WHERE id=?',[$appId]);
$access->grantUser($appId,$member,$root);
checkRuntime(!$access->hasAccess($member,$app),'tenant app denies direct grant without active tenant membership');
checkRuntime($organizations->ensureMember($org,$member,$root),'provisioning creates missing tenant membership');
checkRuntime($access->hasAccess($member,$app),'active tenant membership unlocks otherwise valid grant');
$organizations->setMember($org,$member,'member','suspended',null,null,$root);
checkRuntime(!$organizations->ensureMember($org,$member,null),'automatic provisioning does not override a suspended membership');
checkRuntime(!$access->hasAccess($member,$app),'suspended tenant membership remains denied');
$organizations->setMember($org,$member,'admin','active',null,null,$root);
checkRuntime($admins->canManage($member,$appId,'manage_users'),'tenant admin can manage applications in its organization');

$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),'SCIM Tenant User','scim-'.$suffix,'scim-'.$suffix.'@example.test',$hash]);$scimUser=$db->lastInsertId();
$access->grantUser($appId,$scimUser,null,null,null,'scim');
checkRuntime($organizations->isMember($scimUser,$org),'SCIM grant auto-provisions missing tenant membership');

$db->execute("INSERT INTO organizations(uuid,name,slug,status) VALUES(?,?,?,'active')",[Security::uuidV4(),'Federated Tenant '.$suffix,'federated-'.$suffix]);$federatedOrg=$db->lastInsertId();
$db->execute("INSERT INTO identity_providers(organization_id,name,provider_type,enabled,config_json) VALUES(?,?,'oidc',1,'{}')",[$federatedOrg,'Federated IdP '.$suffix]);$provider=$db->lastInsertId();
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),'Federated User','fed-'.$suffix,'fed-'.$suffix.'@example.test',$hash]);$fedUser=$db->lastInsertId();
$db->execute('INSERT INTO external_identities(user_id,identity_provider_id,external_subject) VALUES(?,?,?)',[$fedUser,$provider,'subject-'.$suffix]);
$_SERVER['REMOTE_ADDR']='198.51.100.10';$_SERVER['HTTP_USER_AGENT']='Mozilla/5.0 TestBrowser/'.$suffix;unset($_COOKIE['imauth_device']);
checkRuntime($auth->login('fed-'.$suffix.'@example.test',$password),'central login succeeds for provisioned federated user');
checkRuntime($organizations->isMember($fedUser,$federatedOrg),'login through a tenant-bound identity automatically provisions tenant membership');
checkRuntime((int)($_SESSION['device_id']??0)>0,'successful login registers a device identity');
checkRuntime((int)($_SESSION['risk_score']??0)>=30&&in_array('new_device',(array)($_SESSION['risk_reasons']??[]),true),'first login from a device receives new-device risk');
$deviceCount=$db->one('SELECT COUNT(*) AS c FROM user_devices WHERE user_id=?',[$fedUser]);checkRuntime((int)$deviceCount['c']===1,'device identity is persisted once');
$auth->logout();
checkRuntime($auth->login('fed-'.$suffix.'@example.test',$password),'second login with device cookie succeeds');
checkRuntime((int)($_SESSION['risk_score']??0)===0,'known device and unchanged IP do not retain new-device risk');
$deviceCount=$db->one('SELECT COUNT(*) AS c FROM user_devices WHERE user_id=?',[$fedUser]);checkRuntime((int)$deviceCount['c']===1,'known device is reused rather than duplicated');
$riskEvent=$db->one("SELECT 1 FROM event_outbox WHERE event_type='auth.risk.detected' ORDER BY id DESC LIMIT 1");checkRuntime($riskEvent!==null,'risk assessment emits an alertable security event');
fwrite(STDOUT,"Tenant and runtime security smoke test passed.\n");
