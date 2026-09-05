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
$content='<section class="card narrow"><h1>'.($reauth?'Potwierdź tożsamość':'Logowanie').'</h1>'.($reauth?'<p>Ta operacja wymaga ponownego uwierzytelnienia.</p>':'').$error.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.Web::e($return).'"><input type="hidden" name="reauth" value="'.($reauth?'1':'0').'"><label>Login lub e-mail<input type="text" name="identifier" autocomplete="username" required autofocus></label><label>Hasło<input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit">'.($reauth?'Potwierdź':'Zaloguj').'</button></form><p class="muted">Passkeys mogą być używane jako silniejsze uwierzytelnienie po zakończeniu pełnej walidacji WebAuthn.</p></section>';
Web::page($reauth?'Ponowne uwierzytelnienie':'Logowanie',$content,null);
