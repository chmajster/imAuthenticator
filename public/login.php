<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';
extract($services,EXTR_SKIP);
$reauth=(string)($_GET['reauth']??$_POST['reauth']??'')==='1';
$existing=$auth->currentUser();
if($existing&&!$reauth) Web::redirect('/dashboard');
$error='';
$return=(string)($_GET['return']??$_POST['return']??'/dashboard');
if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
    Security::requireCsrf($_POST['_csrf']??null);
    $ok=$reauth ? $auth->reauthenticatePassword((string)($_POST['password']??'')) : $auth->login(trim((string)($_POST['identifier']??'')),(string)($_POST['password']??''));
    if($ok) Web::redirect($return);
    $error='<div class="alert danger">Nieprawidłowe dane logowania, konto jest wyłączone albo nowe logowania są chwilowo zablokowane.</div>';
}
$announcement=$settings->announcement();$systemBanner=$announcement?'<div class="alert warning">'.Web::e($announcement).'</div>':'';
if($settings->maintenanceMode())$systemBanner.='<div class="alert warning">Tryb maintenance jest aktywny. Nowe logowania użytkowników nieadministracyjnych są zablokowane.</div>';
$passkeyButton=$passkeys->libraryAvailable()?'<div class="separator"><span>lub</span></div><button class="button" type="button" id="loginPasskey">'.($reauth?'Potwierdź passkey':'Zaloguj passkey').'</button><div id="passkeyLoginResult"></div>':'';
$magic=!$reauth?'<p><a href="/magic-login/request?return='.rawurlencode($return).'">Zaloguj linkiem wysłanym e-mailem</a></p>':'';
$external='';
if(!$reauth){foreach($externalIdentity->providers() as $provider){$label=match($provider['provider_type']){'entra'=>'Microsoft Entra ID','google'=>'Google','github'=>'GitHub',default=>(string)$provider['name']};$external.='<a class="button" href="/auth/external/start?provider='.(int)$provider['id'].'&return='.rawurlencode($return).'">'.Web::e($label).'</a> ';}if($external!=='')$external='<div class="separator"><span>SSO</span></div><div class="external-providers">'.$external.'</div>';}
$identityField=$reauth?'<p><strong>Konto:</strong> '.Web::e($existing['email']??'').'</p>':'<label>Login lub e-mail<input type="text" name="identifier" autocomplete="username" required autofocus></label>';
$content='<section class="card narrow">'.$systemBanner.'<h1>'.($reauth?'Potwierdź tożsamość':'Logowanie').'</h1>'.($reauth?'<p>Hasło zostanie zweryfikowane wyłącznie dla aktualnie zalogowanego konta.</p>':'').$error.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.Web::e($return).'"><input type="hidden" name="reauth" value="'.($reauth?'1':'0').'">'.$identityField.'<label>Hasło<input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit">'.($reauth?'Potwierdź':'Zaloguj').'</button></form>'.$passkeyButton.$external.$magic.'</section>';
if($passkeys->libraryAvailable()){
 $returnJs=json_encode($return,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
 $content.='<script src="/assets/webauthn.js"></script><script>(()=>{const b=document.getElementById("loginPasskey"),out=document.getElementById("passkeyLoginResult");b.addEventListener("click",async()=>{b.disabled=true;out.innerHTML="";try{if(!window.PublicKeyCredential)throw new Error("Ta przeglądarka nie obsługuje WebAuthn.");const r=await fetch("/webauthn/login/options",{credentials:"same-origin",headers:{"Accept":"application/json"}}),p=await r.json();if(!r.ok)throw new Error(p.detail||p.error||"Nie można utworzyć challenge.");const cred=await navigator.credentials.get({publicKey:window.imWebAuthn.requestOptions(p.publicKey)});if(!cred)throw new Error("Logowanie zostało anulowane.");const c=await fetch("/webauthn/login/complete",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({challenge_id:p.challenge_id,credential:window.imWebAuthn.credentialToJSON(cred),return:'.$returnJs.'})}),res=await c.json();if(!c.ok)throw new Error(res.detail||res.error||"Walidacja passkey nie powiodła się.");location.href=res.return||"/dashboard";}catch(e){out.innerHTML="<div class=\"alert danger\"></div>";out.firstElementChild.textContent=e?.message||"Błąd WebAuthn";}finally{b.disabled=false;}});})();</script>';
}
Web::page($reauth?'Ponowne uwierzytelnienie':'Logowanie',$content,null);
