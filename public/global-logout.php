<?php
declare(strict_types=1);

use ImAuthenticator\Security;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);exit;}
Security::requireCsrf($_POST['_csrf']??null);
$sessions->globalLogout((int)$user['id'],(int)$user['id'],'user initiated global logout');
$auth->logout();
header('Location: /login?global_logout=1');exit;
