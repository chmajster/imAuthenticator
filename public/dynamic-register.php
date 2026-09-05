<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';$oauthAdvanced=$services['oauthAdvanced'];
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);header('Allow: POST');echo json_encode(['error'=>'invalid_request']);exit;}
$header=(string)($_SERVER['HTTP_AUTHORIZATION']??'');$bearer=str_starts_with($header,'Bearer ')?trim(substr($header,7)):'';
$raw=file_get_contents('php://input');$payload=json_decode($raw?:'',true);
if(!is_array($payload)){$payload=$_POST;}
try{if($bearer==='')throw new RuntimeException('invalid_token');$result=$oauthAdvanced->dynamicRegister($payload,$bearer);http_response_code(201);echo json_encode($result,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);}catch(RuntimeException $e){$error=$e->getMessage();http_response_code($error==='invalid_token'?401:400);if($error==='invalid_token')header('WWW-Authenticate: Bearer error="invalid_token"');echo json_encode(['error'=>$error],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
