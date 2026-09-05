<?php
declare(strict_types=1);

use ImAuthenticator\Security;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){http_response_code(405);echo json_encode(['error'=>'method_not_allowed']);exit;}
$payload=json_decode((string)file_get_contents('php://input'),true);if(!is_array($payload))$payload=[];
try{Security::requireCsrf(isset($payload['_csrf'])?(string)$payload['_csrf']:null);$credential=$payload['credential']??null;if(!is_array($credential))throw new RuntimeException('credential_required');$id=$passkeys->completeRegistration((int)$user['id'],(int)($payload['challenge_id']??0),json_encode($credential,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),trim((string)($payload['name']??''))?:null);echo json_encode(['ok'=>true,'credential_id'=>$id],JSON_THROW_ON_ERROR);}catch(Throwable $e){http_response_code(400);$audit->write('webauthn.registration.failed','failure',(int)$user['id'],(int)$user['id'],null,substr($e->getMessage(),0,500));echo json_encode(['error'=>'passkey_registration_failed','detail'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
