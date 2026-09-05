<?php
declare(strict_types=1);

$services = require dirname(__DIR__) . '/src/bootstrap.php';
$oidc = $services['oidc'];
$oauthAdvanced = $services['oauthAdvanced'];
$oauthSecurity = $services['oauthSecurity'];
$oauthProofs = $services['oauthProofs'];

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('Pragma: no-cache');

try {
    if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        echo json_encode(['error'=>'invalid_request']);
        exit;
    }
    $grant = (string)($_POST['grant_type'] ?? '');
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
    $authHeader = is_string($header) ? $header : null;
    $app=$oauthProofs->applicationFromClientRequest($_POST,$authHeader);
    if(!$app)throw new RuntimeException('invalid_client');
    $dpop=$_SERVER['HTTP_DPOP']??null;$dpop=is_string($dpop)?$dpop:null;
    $clientCert=$_SERVER['SSL_CLIENT_CERT']??null;$clientCert=is_string($clientCert)?$clientCert:null;
    $jkt=$oauthProofs->validateTokenProofs($app,$_POST,$authHeader,$dpop,$clientCert);
    $result = match ($grant) {
        'authorization_code' => $oidc->exchangeAuthorizationCode($_POST, $authHeader),
        'refresh_token' => $oidc->refresh($_POST, $authHeader),
        'client_credentials' => $oidc->clientCredentials($_POST, $authHeader),
        'urn:ietf:params:oauth:grant-type:device_code' => $oauthAdvanced->deviceToken($_POST, $authHeader),
        'urn:ietf:params:oauth:grant-type:token-exchange' => $oauthSecurity->tokenExchange($_POST, $authHeader),
        default => throw new RuntimeException('unsupported_grant_type'),
    };
    $result=$oauthProofs->bindIssuedTokens($result,$jkt);
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (RuntimeException $e) {
    $error = $e->getMessage();
    $status = $error === 'invalid_client' ? 401 : 400;
    http_response_code($status);
    if ($status === 401) header('WWW-Authenticate: Basic realm="imAuthenticator token endpoint"');
    echo json_encode(['error'=>$error], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}
