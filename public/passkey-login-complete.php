<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);echo json_encode(['error'=>'method_not_allowed']);exit;}
$payload=json_decode((string)file_get_contents('php://input'),true);if(!is_array($payload))$payload=[];
try{$credential=$payload['credential']??null;if(!is_array($credential))throw new RuntimeException('credential_required');$userId=$passkeys->completeAuthentication((int)($payload['challenge_id']??0),json_encode($credential,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));if(!$auth->loginVerifiedUser($userId,2,'passkey'))throw new RuntimeException('user_not_available');$return=(string)($payload['return']??'/dashboard');if(!str_starts_with($return,'/')||str_starts_with($return,'//'))$return='/dashboard';echo json_encode(['ok'=>true,'return'=>$return],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}catch(Throwable $e){http_response_code(401);$audit->write('webauthn.login.failed','denied',null,null,null,substr($e->getMessage(),0,500));echo json_encode(['error'=>'passkey_login_failed','detail'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
