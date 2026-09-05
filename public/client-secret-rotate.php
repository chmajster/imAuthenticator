<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireUser();
$appId = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
if (!$app || !$appAdmins->canManage((int)$user['id'],$appId,'manage_secrets')) { http_response_code(403); Web::page('Brak dostępu','<div class="alert danger">Brak uprawnień do sekretów tej aplikacji.</div>',$user); }
$secretHtml = '';
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    try {
        $secret = $clientSecrets->rotate($appId,(int)$user['id'],(int)($_POST['valid_days'] ?? 365),(int)($_POST['overlap_days'] ?? 7));
        $secretHtml = '<div class="alert warning"><strong>Nowy Client Secret — skopiuj teraz.</strong><div class="code">'.Web::e($secret).'</div><p>Po opuszczeniu tej strony sekret nie będzie możliwy do odczytania.</p></div>';
    } catch (Throwable $e) { $secretHtml = '<div class="alert danger">'.Web::e($e->getMessage()).'</div>'; }
}
$content = '<div class="page-head"><div><h1>Rotacja Client Secret — '.Web::e($app['name']).'</h1><p>Dwa sekrety mogą działać równolegle w okresie migracji.</p></div><a class="button" href="/admin/applications/'.$appId.'">Wróć</a></div>'.$secretHtml.'<section class="card"><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Ważność nowego sekretu (dni)<input type="number" min="1" max="730" name="valid_days" value="365"></label><label>Okres nakładania starego i nowego sekretu (dni)<input type="number" min="0" max="90" name="overlap_days" value="7"></label><button class="primary">Wygeneruj i rozpocznij rotację</button></form></section>';
Web::page('Rotacja Client Secret',$content,$user);
