<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix='ImAuthenticator\\';
    if(!str_starts_with($class,$prefix))return;
    $path=dirname(__DIR__).'/src/'.str_replace('\\','/',substr($class,strlen($prefix))).'.php';
    if(is_file($path))require $path;
});

use ImAuthenticator\ApiKeyService;
use ImAuthenticator\ApplicationAccessService;
use ImAuthenticator\AuditLog;
use ImAuthenticator\ConditionalAccessService;
use ImAuthenticator\Database;
use ImAuthenticator\EventService;
use ImAuthenticator\JwtService;
use ImAuthenticator\OAuthAdvancedService;
use ImAuthenticator\Security;

function checkAdvanced(bool $condition,string $message):void{if(!$condition){fwrite(STDERR,"FAIL: {$message}\n");exit(1);}fwrite(STDOUT,"OK: {$message}\n");}
$env=static function(string $name,string $default):string{$value=getenv($name);return $value===false?$default:$value;};
$db=new Database(['dsn'=>$env('TEST_DB_DSN','mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4'),'user'=>$env('TEST_DB_USER','root'),'pass'=>$env('TEST_DB_PASS','')]);
$audit=new AuditLog($db);$events=new EventService($db);$access=new ApplicationAccessService($db,$audit);$conditional=new ConditionalAccessService($db,$access);$apiKeys=new ApiKeyService($db,$audit);
$key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);if($key===false)throw new RuntimeException('test key failed');openssl_pkey_export($key,$privatePem);$details=openssl_pkey_get_details($key);$tmp=sys_get_temp_dir().'/imauth-test-'.bin2hex(random_bytes(4)).'.pem';file_put_contents($tmp,$privatePem);$config=['issuer'=>'https://auth.example.test','keys'=>['private'=>$tmp,'kid'=>'test-kid']];$jwt=new JwtService($config);$oauth=new OAuthAdvancedService($db,$access,$conditional,$audit,$jwt,$config);

$suffix=bin2hex(random_bytes(4));$pwd=password_hash('test-password',PASSWORD_ARGON2ID);
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,is_admin,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,1,'active')",[Security::uuidV4(),'OAuth Admin','oadmin-'.$suffix,'oadmin-'.$suffix.'@example.test',$pwd]);$adminId=$db->lastInsertId();
$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),'OAuth User','ouser-'.$suffix,'ouser-'.$suffix.'@example.test',$pwd]);$userId=$db->lastInsertId();
$secret='client-secret-'.$suffix;
$db->execute("INSERT INTO applications(uuid,name,slug,url,app_type,integration_type,client_id,client_secret_hash,client_type,access_policy,enabled) VALUES(?,?,?,?, 'oidc','generic_oidc',?,?, 'confidential','none',1)",[Security::uuidV4(),'OAuth Advanced App','oauth-adv-'.$suffix,'https://oauth-'.$suffix.'.example.test','ima_adv_'.$suffix,Security::secretHash($secret)]);$appId=$db->lastInsertId();
$db->execute('INSERT INTO application_redirect_uris(application_id,redirect_uri) VALUES(?,?)',[$appId,'https://oauth-'.$suffix.'.example.test/callback']);foreach(['openid','profile','email','roles'] as $scope)$db->execute('INSERT INTO application_scopes(application_id,scope) VALUES(?,?)',[$appId,$scope]);$access->grantUser($appId,$userId,$adminId);

$device=$oauth->deviceAuthorization(['client_id'=>'ima_adv_'.$suffix,'client_secret'=>$secret,'scope'=>'openid profile'],null);checkAdvanced(str_starts_with($device['verification_uri'],'https://auth.example.test/activate'),'device flow returns verification URI');
try{$oauth->deviceToken(['client_id'=>'ima_adv_'.$suffix,'client_secret'=>$secret,'device_code'=>$device['device_code']],null);checkAdvanced(false,'pending device token must not succeed');}catch(RuntimeException $e){checkAdvanced($e->getMessage()==='authorization_pending','device poll returns authorization_pending');}
$poll=$db->one('SELECT poll_count,last_polled_at FROM oauth_device_codes WHERE device_code_hash=?',[Security::tokenHash($device['device_code'])]);checkAdvanced((int)$poll['poll_count']===1&&!empty($poll['last_polled_at']),'pending polling state is committed');
$authorized=$oauth->authorizeDevice($device['user_code'],$userId,['auth_level'=>2,'auth_time'=>time(),'risk_score'=>0,'ip'=>'127.0.0.1']);checkAdvanced((int)$authorized['application_id']===$appId,'user authorizes device against real entitlement');$db->execute('UPDATE oauth_device_codes SET last_polled_at=DATE_SUB(NOW(),INTERVAL 10 SECOND) WHERE device_code_hash=?',[Security::tokenHash($device['device_code'])]);$tokens=$oauth->deviceToken(['client_id'=>'ima_adv_'.$suffix,'client_secret'=>$secret,'device_code'=>$device['device_code']],null);checkAdvanced(!empty($tokens['access_token'])&&!empty($tokens['id_token']),'authorized device receives tokens');
try{$oauth->deviceToken(['client_id'=>'ima_adv_'.$suffix,'client_secret'=>$secret,'device_code'=>$device['device_code']],null);checkAdvanced(false,'consumed device code must be one-time');}catch(RuntimeException $e){checkAdvanced($e->getMessage()==='invalid_grant','consumed device code is rejected');}

$par=$oauth->pushAuthorizationRequest(['client_id'=>'ima_adv_'.$suffix,'client_secret'=>$secret,'redirect_uri'=>'https://oauth-'.$suffix.'.example.test/callback','response_type'=>'code','scope'=>'openid email','state'=>'state-1'],null);checkAdvanced(str_starts_with($par['request_uri'],'urn:ietf:params:oauth:request_uri:'),'PAR returns RFC request_uri');$parRow=$db->one('SELECT used_at,params_json FROM oauth_par_requests WHERE request_uri_hash=?',[Security::tokenHash($par['request_uri'])]);checkAdvanced($parRow!==null&&$parRow['used_at']===null,'PAR remains unconsumed until authorization');

$registrationToken=$oauth->createRegistrationToken('CI DCR '.$suffix,$adminId,['registered.example.test'],date('Y-m-d H:i:s',time()+3600));$registered=$oauth->dynamicRegister(['client_name'=>'Registered '.$suffix,'redirect_uris'=>['https://registered.example.test/callback'],'token_endpoint_auth_method'=>'none','scope'=>'openid email'],$registrationToken);checkAdvanced(!empty($registered['client_id'])&&!isset($registered['client_secret']),'DCR creates public client without secret');$registeredApp=$db->one('SELECT access_policy,client_type,integration_type FROM applications WHERE client_id=?',[$registered['client_id']]);checkAdvanced($registeredApp['access_policy']==='none'&&$registeredApp['client_type']==='public'&&$registeredApp['integration_type']==='public_pkce','DCR client defaults to no access and PKCE');
try{$oauth->dynamicRegister(['client_name'=>'Bad '.$suffix,'redirect_uris'=>['https://evil.example.test/callback']],$registrationToken);checkAdvanced(false,'DCR token domain restriction must apply');}catch(RuntimeException $e){checkAdvanced($e->getMessage()==='invalid_redirect_uri','DCR rejects redirect outside allowed domains');}

$serviceId=$apiKeys->createServiceAccount('SIEM '.$suffix,null,$adminId);$rawKey=$apiKeys->createKey($serviceId,['events.read'],$adminId,date('Y-m-d H:i:s',time()+3600));$events->emit('security.test',['marker'=>$suffix]);$principal=$apiKeys->authenticate($rawKey,'events.read');checkAdvanced((int)$principal['service_account_id']===$serviceId,'scoped API key authenticates service account');
try{$apiKeys->authenticate($rawKey,'audit.read');checkAdvanced(false,'API key scope must be enforced');}catch(RuntimeException $e){checkAdvanced($e->getMessage()==='insufficient_scope','API key rejects missing scope');}
$apiKeys->revokeKey((int)$principal['id'],$adminId);try{$apiKeys->authenticate($rawKey,'events.read');checkAdvanced(false,'revoked API key must fail');}catch(RuntimeException $e){checkAdvanced($e->getMessage()==='invalid_api_key','revoked API key is rejected immediately');}

@unlink($tmp);fwrite(STDOUT,"Advanced OAuth smoke test passed.\n");
