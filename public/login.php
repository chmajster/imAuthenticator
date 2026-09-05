<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';
extract($services,EXTR_SKIP);
$reauth=(string)($_GET['reauth']??$_POST['reauth']??'')==='1';
if($auth->currentUser()&&!$reauth) Web::redirect('/dashboard');
$error='';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
    Security::requireCsrf($_POST['_csrf']??null);
    $identifier=trim((string)($_POST['identifier']??''));
    if($auth->login($identifier,(string)($_POST['password']??''))){
        $return=(string)($_POST['return']??'/dashboard');
        if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';
        Web::redirect($return);
    }
    $error='<div class="alert danger">Nieprawidłowe dane logowania albo konto nie jest aktywne.</div>';
}
$return=(string)($_GET['return']??$_POST['return']??'/dashboard');
if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';
$passkeyButton=$passkeys->libraryAvailable()?'<div class="separator"><span>lub</span></div><button class="button" type="button" id="loginPasskey">'.($reauth?'Potwierdź passkey':'Zaloguj passkey').'</button><div id="passkeyLoginResult"></div>':'';
$content='<section class="card narrow"><h1>'.($reauth?'Potwierdź tożsamość':'Logowanie').'</h1>'.($reauth?'<p>Ta operacja wymaga ponownego uwierzytelnienia.</p>':'').$error.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.Web::e($return).'"><input type="hidden" name="reauth" value="'.($reauth?'1':'0').'"><label>Login lub e-mail<input type="text" name="identifier" autocomplete="username" required autofocus></label><label>Hasło<input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit">'.($reauth?'Potwierdź':'Zaloguj').'</button></form>'.$passkeyButton.'</section>';
if($passkeys->libraryAvailable()){
 $returnJs=json_encode($return,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
 $content.='<script src="/assets/webauthn.js"></script><script>(()=>{const b=document.getElementById("loginPasskey"),out=document.getElementById("passkeyLoginResult");b.addEventListener("click",async()=>{b.disabled=true;out.innerHTML="";try{if(!window.PublicKeyCredential)throw new Error("Ta przeglądarka nie obsługuje WebAuthn.");const r=await fetch("/webauthn/login/options",{credentials:"same-origin",headers:{"Accept":"application/json"}}),p=await r.json();if(!r.ok)throw new Error(p.detail||p.error||"Nie można utworzyć challenge.");const cred=await navigator.credentials.get({publicKey:window.imWebAuthn.requestOptions(p.publicKey)});if(!cred)throw new Error("Logowanie zostało anulowane.");const c=await fetch("/webauthn/login/complete",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({challenge_id:p.challenge_id,credential:window.imWebAuthn.credentialToJSON(cred),return:'.$returnJs.'})}),res=await c.json();if(!c.ok)throw new Error(res.detail||res.error||"Walidacja passkey nie powiodła się.");location.href=res.return||"/dashboard";}catch(e){out.innerHTML="<div class=\"alert danger\"></div>";out.firstElementChild.textContent=e?.message||"Błąd WebAuthn";}finally{b.disabled=false;}});})();</script>';
}
Web::page($reauth?'Ponowne uwierzytelnienie':'Logowanie',$content,null);
