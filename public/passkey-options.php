<?php
declare(strict_types=1);

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireUser();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
try { echo json_encode($passkeys->registrationOptions((int)$user['id']), JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR); }
catch (Throwable $e) { http_response_code(400); echo json_encode(['error'=>$e->getMessage()], JSON_THROW_ON_ERROR); }
