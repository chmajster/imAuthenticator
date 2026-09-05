<?php
declare(strict_types=1);

$vendor=dirname(__DIR__).'/vendor/autoload.php';if(is_file($vendor))require_once $vendor;
spl_autoload_register(static function(string $class):void{$prefix='ImAuthenticator\\';if(!str_starts_with($class,$prefix))return;$path=dirname(__DIR__).'/src/'.str_replace('\\','/',substr($class,strlen($prefix))).'.php';if(is_file($path))require $path;});

use ImAuthenticator\AuditLog;
use ImAuthenticator\Database;
use ImAuthenticator\PasskeyChallengeService;
use ImAuthenticator\Security;

function checkWebauthn(bool $condition,string $message):void{if(!$condition){fwrite(STDERR,"FAIL: {$message}\n");exit(1);}fwrite(STDOUT,"OK: {$message}\n");}
$env=static function(string $name,string $default):string{$value=getenv($name);return $value===false?$default:$value;};
$db=new Database(['dsn'=>$env('TEST_DB_DSN','mysql:host=127.0.0.1;dbname=imauth_ci;charset=utf8mb4'),'user'=>$env('TEST_DB_USER','root'),'pass'=>$env('TEST_DB_PASS','')]);$audit=new AuditLog($db);$service=new PasskeyChallengeService($db,['issuer'=>'https://auth.example.test'],$audit);
$suffix=bin2hex(random_bytes(4));$db->execute("INSERT INTO users(uuid,name,username,email,password_hash,enabled,lifecycle_status) VALUES(?,?,?,?,?,1,'active')",[Security::uuidV4(),'Passkey User','passkey-'.$suffix,'passkey-'.$suffix.'@example.test',password_hash('not-used',PASSWORD_ARGON2ID)]);$userId=$db->lastInsertId();
checkWebauthn($service->libraryAvailable(),'web-auth/webauthn-lib and serializer dependencies are loadable');
$options=$service->registrationOptions($userId);checkWebauthn(!empty($options['challenge_id'])&&strlen((string)$options['publicKey']['challenge'])>=43,'registration options create server challenge');checkWebauthn(($options['publicKey']['authenticatorSelection']['residentKey']??'')==='required'&&($options['publicKey']['authenticatorSelection']['userVerification']??'')==='required','registration requires discoverable credential and user verification');
$login=$service->authenticationOptions();checkWebauthn(!empty($login['challenge_id'])&&($login['publicKey']['userVerification']??'')==='required','passwordless request options require user verification');
$before=$db->one('SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id=?',[$userId]);try{$service->completeRegistration($userId,(int)$options['challenge_id'],json_encode(['id'=>'invalid','type'=>'public-key','rawId'=>'invalid','response'=>[]],JSON_THROW_ON_ERROR));checkWebauthn(false,'invalid attestation must be rejected');}catch(Throwable){checkWebauthn(true,'invalid attestation is rejected by WebAuthn stack');}$after=$db->one('SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id=?',[$userId]);checkWebauthn((int)$before['c']===(int)$after['c'],'invalid credential is never persisted');$challenge=$db->one('SELECT used_at FROM authentication_challenges WHERE id=?',[(int)$options['challenge_id']]);checkWebauthn($challenge['used_at']===null,'failed registration does not consume challenge');
fwrite(STDOUT,"WebAuthn stack smoke test passed.\n");
