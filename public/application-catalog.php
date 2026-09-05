<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireUser();
$message = '';
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $action = (string)($_POST['action'] ?? 'request');
    $appId = (int)($_POST['application_id'] ?? 0);
    try {
        if ($action === 'request') {
            $days = (int)($_POST['duration_days'] ?? 30);
            $duration = $days <= 0 ? null : min($days,365) * 86400;
            $requests->request($appId,(int)$user['id'],null,$duration,trim((string)($_POST['justification'] ?? '')));
            $message = '<div class="alert success">Wniosek o dostęp został wysłany.</div>';
        } elseif ($action === 'revoke') {
            $access->revokeUser($appId,(int)$user['id'],(int)$user['id'],'user self-service revoke');
            $message = '<div class="alert success">Dostęp został cofnięty.</div>';
        }
    } catch (Throwable $e) { $message = '<div class="alert danger">'.Web::e($e->getMessage()).'</div>'; }
}
$apps = $db->all("SELECT * FROM applications WHERE enabled=1 AND deleted_at IS NULL AND app_type<>'m2m' ORDER BY name");
$pending = array_column($db->all("SELECT application_id FROM access_requests WHERE user_id=? AND status='pending'", [(int)$user['id']]), 'application_id');
$cards = '';
foreach ($apps as $app) {
    $has = $access->hasAccess((int)$user['id'],$app,$auth->authenticationContext());
    $isPending = in_array($app['id'],$pending);
    $cards .= '<section class="card"><h2>'.Web::e($app['name']).'</h2><p>'.Web::e($app['description'] ?: $app['url']).'</p>';
    if ($has) {
        $cards .= '<div class="actions"><a class="button primary" href="'.Web::e($app['url']).'">Otwórz</a><form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="application_id" value="'.(int)$app['id'].'"><button name="action" value="revoke">Cofnij mój dostęp</button></form></div>';
    } elseif ($isPending) {
        $cards .= '<span class="badge muted">Wniosek oczekuje na zatwierdzenie</span>';
    } else {
        $cards .= '<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="application_id" value="'.(int)$app['id'].'"><label>Uzasadnienie<textarea name="justification" rows="2" required></textarea></label><label>Dostęp na<select name="duration_days"><option value="1">1 dzień</option><option value="7">7 dni</option><option value="30" selected>30 dni</option><option value="90">90 dni</option><option value="0">bez terminu</option></select></label><button class="primary" name="action" value="request">Poproś o dostęp</button></form>';
    }
    $cards .= '</section>';
}
Web::page('Katalog aplikacji', '<div class="page-head"><div><h1>Katalog aplikacji</h1><p>Self-service access request i zarządzanie własnym dostępem.</p></div></div>'.$message.'<div class="app-grid">'.$cards.'</div>', $user);
