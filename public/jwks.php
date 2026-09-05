<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';$signingKeys=$services['signingKeys'];
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: public, max-age=300');
echo json_encode($signingKeys->jwks(),JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
