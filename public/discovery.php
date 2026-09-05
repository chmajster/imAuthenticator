<?php
declare(strict_types=1);

$services = require dirname(__DIR__) . '/src/bootstrap.php';
$config = $services['config'];
$issuer = rtrim((string)$config['issuer'], '/');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: public, max-age=300');
echo json_encode([
    'issuer'=>$issuer,
    'authorization_endpoint'=>$issuer.'/oauth/authorize',
    'token_endpoint'=>$issuer.'/oauth/token',
    'userinfo_endpoint'=>$issuer.'/oauth/userinfo',
    'end_session_endpoint'=>$issuer.'/oauth/logout',
    'jwks_uri'=>$issuer.'/.well-known/jwks.json',
    'device_authorization_endpoint'=>$issuer.'/oauth/device_authorization',
    'pushed_authorization_request_endpoint'=>$issuer.'/oauth/par',
    'registration_endpoint'=>$issuer.'/connect/register',
    'require_pushed_authorization_requests'=>false,
    'response_types_supported'=>['code'],
    'grant_types_supported'=>['authorization_code','refresh_token','client_credentials','urn:ietf:params:oauth:grant-type:device_code'],
    'subject_types_supported'=>['public'],
    'id_token_signing_alg_values_supported'=>['RS256'],
    'scopes_supported'=>['openid','profile','email','roles'],
    'token_endpoint_auth_methods_supported'=>['client_secret_basic','client_secret_post','none'],
    'code_challenge_methods_supported'=>['S256'],
    'request_uri_parameter_supported'=>true,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
