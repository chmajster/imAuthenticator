<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();$message='';$code=strtoupper(trim((string)($_GET['user_code']??$_POST['user_code']??'')));
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$action=(string)($_POST['action']??'authorize');
 try{
  if($action==='deny'){$oauthAdvanced->denyDevice($code,(int)$user['id']);$message='<div class="alert warning">Żądanie urządzenia zostało odrzucone.</div>';}
  else{$result=$oauthAdvanced->authorizeDevice($code,(int)$user['id'],$auth->authenticationContext());$message='<div class="alert success">Urządzenie zostało autoryzowane dla aplikacji <strong>'.Web::e($result['application_name']).'</strong>. Możesz wrócić do urządzenia.</div>';}
 }catch(RuntimeException $e){$labels=['invalid_user_code'=>'Kod jest nieprawidłowy albo wygasł.','access_denied'=>'Nie masz dostępu do tej aplikacji.','interaction_required'=>'Ta aplikacja wymaga silniejszego uwierzytelnienia/MFA.'];$message='<div class="alert danger">'.Web::e($labels[$e->getMessage()]??$e->getMessage()).'</div>';}
}
$content='<div class="page-head"><div><h1>Autoryzuj urządzenie</h1><p>Wprowadź kod wyświetlony przez urządzenie lub aplikację CLI.</p></div></div>'.$message.'<section class="card narrow"><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Kod urządzenia<input name="user_code" value="'.Web::e($code).'" pattern="[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}" maxlength="9" autocomplete="one-time-code" required autofocus></label><div class="actions"><button class="primary" name="action" value="authorize">Autoryzuj</button><button name="action" value="deny">Odrzuć</button></div></form></section>';
Web::page('Autoryzuj urządzenie',$content,$user);
