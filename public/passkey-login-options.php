<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';$passkeys=$services['passkeys'];header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
try{echo json_encode($passkeys->authenticationOptions(),JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);}catch(Throwable $e){http_response_code(400);echo json_encode(['error'=>'passkey_options_failed','detail'=>$e->getMessage()],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
