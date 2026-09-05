<?php
declare(strict_types=1);

use ImAuthenticator\Security;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { http_response_code(405); exit; }
Security::requireCsrf($_POST['_csrf'] ?? null);
$appId = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
$secret = $_SESSION['client_secrets'][$appId] ?? null;
if (!$app || $app['client_type'] !== 'confidential' || !is_string($secret) || $secret === '') {
    http_response_code(409);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error'=>'secret_not_available','message'=>'Sekret nie jest już dostępny. Regeneruj go i wyeksportuj bezpośrednio po regeneracji.'], JSON_UNESCAPED_UNICODE);
    exit;
}
$redirects = array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id', [$appId]), 'redirect_uri');
$issuer = rtrim((string)$config['issuer'], '/');
$payload = [
    'issuer'=>$issuer,
    'client_id'=>$app['client_id'],
    'client_secret'=>$secret,
    'redirect_uri'=>$redirects[0] ?? null,
    'redirect_uris'=>$redirects,
    'discovery_url'=>$issuer.'/.well-known/openid-configuration',
];
$audit->write('application.configuration.secret_exported', 'success', (int)$admin['id'], null, $appId, 'administrator explicitly exported client secret');
header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="imAuthenticator-'.preg_replace('/[^A-Za-z0-9._-]/','-',(string)$app['slug']).'-with-secret.json"');
header('Cache-Control: no-store, private');
echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
