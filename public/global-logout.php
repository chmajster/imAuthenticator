<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);exit;}
Security::requireCsrf($_POST['_csrf']??null);
$frontUrls=$logoutPropagation->propagate((int)$user['id']);
$sessions->globalLogout((int)$user['id'],(int)$user['id'],'user initiated global logout');
$auth->logout();
$frames='';foreach($frontUrls as $url)$frames.='<iframe src="'.Web::e($url).'" title="OIDC front-channel logout" hidden sandbox="allow-scripts allow-same-origin"></iframe>';
$content='<section class="card narrow"><h1>Wylogowano ze wszystkich aplikacji</h1><p>Tokeny i sesje OIDC zostały unieważnione. Zarejestrowane aplikacje otrzymały sygnał zakończenia sesji.</p>'.$frames.'<a class="button primary" href="/login">Przejdź do logowania</a></section>';
Web::page('Global logout',$content,null);
