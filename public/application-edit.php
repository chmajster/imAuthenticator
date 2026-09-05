<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
$id = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$id]);
if (!$app) { http_response_code(404); Web::page('Nie znaleziono', '<div class="alert danger">Nie znaleziono aplikacji.</div>', $admin); }

if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $name = trim((string)($_POST['name'] ?? ''));
    $description = trim((string)($_POST['description'] ?? ''));
    $url = trim((string)($_POST['url'] ?? ''));
    $icon = trim((string)($_POST['icon'] ?? ''));
    $logoutUrl = trim((string)($_POST['logout_url'] ?? ''));
    $redirects = array_values(array_unique(array_filter(array_map('trim', preg_split('/\R/', (string)($_POST['redirect_uris'] ?? '')) ?: []))));

    $errors = [];
    if ($name === '') $errors[] = 'Nazwa aplikacji jest wymagana.';
    if (!filter_var($url, FILTER_VALIDATE_URL)) $errors[] = 'Adres aplikacji jest nieprawidłowy.';
    if ($logoutUrl !== '' && !Security::validRedirectUri($logoutUrl)) $errors[] = 'Logout URL musi być dokładnym adresem HTTPS; HTTP jest dozwolony tylko dla localhost.';
    if ($app['integration_type'] !== 'client_credentials' && $redirects === []) $errors[] = 'Co najmniej jeden Redirect URI jest wymagany.';
    foreach ($redirects as $uri) if (!Security::validRedirectUri($uri)) $errors[] = 'Nieprawidłowy Redirect URI: ' . $uri;

    if ($errors === []) {
        $db->transaction(function () use ($db,$id,$name,$description,$url,$icon,$logoutUrl,$redirects): void {
            $db->execute('UPDATE applications SET name=?,description=?,url=?,icon=?,logout_url=? WHERE id=?', [$name,$description ?: null,$url,$icon ?: null,$logoutUrl ?: null,$id]);
            $db->execute('DELETE FROM application_redirect_uris WHERE application_id=?', [$id]);
            foreach ($redirects as $uri) $db->execute('INSERT INTO application_redirect_uris(application_id,redirect_uri) VALUES(?,?)', [$id,$uri]);
        });
        $audit->write('application.configuration.updated', 'success', (int)$admin['id'], null, $id, null, ['redirect_count'=>count($redirects)]);
        Web::redirect('/admin/applications/'.$id);
    }
    $errorHtml = '<div class="alert danger"><strong>Nie zapisano zmian.</strong><ul><li>'.implode('</li><li>', array_map([Web::class,'e'], $errors)).'</li></ul></div>';
} else {
    $errorHtml = '';
}

$redirects = array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id', [$id]), 'redirect_uri');
$content = '<div class="page-head"><div><h1>Edytuj aplikację</h1><p>'.Web::e($app['name']).' · '.Web::e($app['client_id']).'</p></div><a class="button" href="/admin/applications/'.$id.'">Anuluj</a></div>'.$errorHtml;
$content .= '<form method="post" class="card"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'">';
$content .= '<label>Nazwa aplikacji<input name="name" value="'.Web::e($_POST['name'] ?? $app['name']).'" required></label>';
$content .= '<label>Opis<textarea name="description" rows="3">'.Web::e($_POST['description'] ?? $app['description'] ?? '').'</textarea></label>';
$content .= '<label>Adres aplikacji<input type="url" name="url" value="'.Web::e($_POST['url'] ?? $app['url']).'" required></label>';
$content .= '<label>Ikona/logo URL<input type="url" name="icon" value="'.Web::e($_POST['icon'] ?? $app['icon'] ?? '').'"></label>';
$content .= '<div class="form-row"><label>Typ aplikacji<input value="'.Web::e($app['app_type']).'" readonly></label><label>Typ integracji<input value="'.Web::e($app['integration_type']).'" readonly></label></div>';
if ($app['integration_type'] !== 'client_credentials') $content .= '<label>Redirect URI — jeden na linię<textarea name="redirect_uris" rows="5" required>'.Web::e($_POST['redirect_uris'] ?? implode("\n", $redirects)).'</textarea></label>';
$content .= '<label>Logout URL<input type="url" name="logout_url" value="'.Web::e($_POST['logout_url'] ?? $app['logout_url'] ?? '').'" placeholder="https://xyz.example.com/logout/callback"></label>';
$content .= '<div class="alert warning">Zmiana Redirect URI działa natychmiast. Stare URI przestają być akceptowane po zapisaniu.</div><button class="primary" type="submit">Zapisz zmiany</button></form>';
Web::page('Edytuj aplikację', $content, $admin);
