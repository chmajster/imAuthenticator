<?php
declare(strict_types=1);
use ImAuthenticator\Security;use ImAuthenticator\Web;
$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$message='';$return=(string)($_GET['return']??$_POST['return']??'/dashboard');if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){Security::requireCsrf($_POST['_csrf']??null);$magicLinks->request((string)($_POST['identifier']??''),$return);$message='<div class="alert success">Jeżeli konto istnieje i może się logować, wysłano jednorazowy link.</div>';}
Web::page('Magic link','<section class="card narrow"><h1>Logowanie linkiem</h1>'.$message.'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.Web::e($return).'"><label>Login lub e-mail<input name="identifier" required></label><button class="primary">Wyślij link</button></form><p><a href="/login?return='.rawurlencode($return).'">Wróć do logowania</a></p></section>');
