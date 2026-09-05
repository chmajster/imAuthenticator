<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';$oauthAdvanced=$services['oauthAdvanced'];
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);header('Allow: POST');echo json_encode(['error'=>'invalid_request']);exit;}
try{$header=$_SERVER['HTTP_AUTHORIZATION']??null;$result=$oauthAdvanced->pushAuthorizationRequest($_POST,is_string($header)?$header:null);http_response_code(201);echo json_encode($result,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}catch(RuntimeException $e){$error=$e->getMessage();http_response_code($error==='invalid_client'?401:400);if($error==='invalid_client')header('WWW-Authenticate: Basic realm="imAuthenticator PAR"');echo json_encode(['error'=>$error],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
