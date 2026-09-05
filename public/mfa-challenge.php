<?php
declare(strict_types=1);
use ImAuthenticator\Security;
use ImAuthenticator\Web;
$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();$uid=(int)$user['id'];$level=max(2,min(3,(int)($_GET['level']??$_POST['level']??2)));$return=(string)($_GET['return']??$_POST['return']??'/dashboard');if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';
if((int)($_SESSION['auth_level']??1)>=$level)Web::redirect($return);
$error='';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$passwordOk=true;if($level>=3){$password=(string)($_POST['password']??'');$passwordOk=$auth->reauthenticatePassword($password);} $mfaOk=$passwordOk&&$mfa->verify($uid,(string)($_POST['code']??''));
 if($mfaOk){$auth->setAuthenticationLevel($level);$audit->write('auth.step_up.completed','success',$uid,$uid,null,null,['auth_level'=>$level]);Web::redirect($return);} $error='<div class="alert danger">Weryfikacja nie powiodła się.</div>';
}
$methods=$mfa->methods($uid);$hasTotp=false;foreach($methods as $method)if($method['method']==='totp'&&(bool)$method['enabled'])$hasTotp=true;$hasBackup=$mfa->remainingBackupCodes($uid)>0;
$explain=$level>=3?'Ta operacja wymaga świeżego hasła oraz drugiego składnika MFA.':'Podaj kod TOTP lub jeden z kodów zapasowych.';
$enroll=(!$hasTotp&&!$hasBackup)?'<div class="alert warning">Nie masz TOTP ani kodów zapasowych. <a href="/account/mfa">Skonfiguruj MFA</a> lub użyj passkey do poziomu MFA.</div>':'';
$passwordField=$level>=3?'<label>Aktualne hasło<input type="password" name="password" autocomplete="current-password" required></label>':'';
$content='<section class="card narrow"><h1>'.($level>=3?'Step-up authentication':'Weryfikacja MFA').'</h1><p>'.$explain.'</p>'.$error.$enroll.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="level" value="'.$level.'"><input type="hidden" name="return" value="'.Web::e($return).'">'.$passwordField.'<label>Kod TOTP / kod zapasowy<input name="code" autocomplete="one-time-code" required autofocus></label><button class="primary">Zweryfikuj</button></form>'.($level===2&&$passkeys->libraryAvailable()?'<p><a class="button" href="/login?reauth=1&return='.rawurlencode($return).'">Użyj Passkey</a></p>':'').'</section>';
Web::page($level>=3?'Step-up authentication':'MFA',$content,$user);
