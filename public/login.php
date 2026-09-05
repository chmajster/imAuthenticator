<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';
extract($services,EXTR_SKIP);
if($auth->currentUser()) Web::redirect('/dashboard');
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
$content='<section class="card narrow"><h1>Logowanie</h1>'.$error.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.Web::e($return).'"><label>Login lub e-mail<input type="text" name="identifier" autocomplete="username" required autofocus></label><label>Hasło<input type="password" name="password" autocomplete="current-password" required></label><button class="primary" type="submit">Zaloguj</button></form><p class="muted">Passkeys i zewnętrzni dostawcy logowania są przygotowywani jako dodatkowe metody.</p></section>';
Web::page('Logowanie',$content,null);
