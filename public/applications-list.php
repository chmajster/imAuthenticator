<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireUser();
$allApps = $db->all('SELECT a.*,(SELECT COUNT(*) FROM application_users au WHERE au.application_id=a.id AND au.enabled=1 AND au.revoked_at IS NULL) AS users_count FROM applications a WHERE a.deleted_at IS NULL ORDER BY a.created_at DESC');
$apps=array_values(array_filter($allApps,fn(array $app):bool=>$appAdmins->canManage((int)$user['id'],(int)$app['id'],'manage')));
$labels = ['website'=>'Strona WWW','wordpress'=>'WordPress','php'=>'Własna aplikacja PHP','spa'=>'SPA','mobile'=>'Aplikacja mobilna','oidc'=>'Generic OpenID Connect','m2m'=>'Machine-to-Machine'];
$rows = '';
foreach ($apps as $app) {
    $id = (int)$app['id'];$rows .= '<tr><td><div class="app-icon small">'.Web::e(mb_strtoupper(mb_substr((string)$app['name'],0,1))).'</div></td><td><a href="/admin/applications/'.$id.'"><strong>'.Web::e($app['name']).'</strong></a></td><td>'.Web::e($labels[$app['app_type']] ?? $app['app_type']).'</td><td class="truncate"><a href="'.Web::e($app['url']).'" target="_blank" rel="noopener">'.Web::e($app['url']).'</a></td><td><code>'.Web::e($app['client_id']).'</code></td><td>'.(int)$app['users_count'].'</td><td><span class="badge '.((bool)$app['enabled']?'ok':'muted').'">'.((bool)$app['enabled']?'Aktywna':'Wyłączona').'</span></td><td>'.Web::e($app['last_used_at'] ?: '—').'</td><td><div class="actions compact"><a class="button" href="/admin/applications/'.$id.'">Otwórz</a><a class="button" href="/admin/applications/'.$id.'/users">Użytkownicy</a><a class="button" href="/admin/applications/'.$id.'/oauth-security">OAuth Security</a><a class="button" href="/admin/applications/'.$id.'/saml">SAML</a><a class="button" href="/admin/applications/'.$id.'/test">Testuj</a></div></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="9" class="empty">Brak aplikacji, którymi możesz zarządzać.</td></tr>';
$create=(bool)$user['is_admin']?'<a class="button primary" href="/admin/applications/new">Dodaj aplikację</a>':'';
$content = '<div class="page-head"><div><h1>Aplikacje</h1><p>Klienci OAuth/OIDC/SAML i polityki dostępu. Delegowany administrator widzi tylko przypisane aplikacje.</p></div>'.$create.'</div><div class="table-wrap"><table><thead><tr><th>Ikona</th><th>Nazwa</th><th>Typ</th><th>URL</th><th>Client ID</th><th>Użytkownicy</th><th>Status</th><th>Ostatnie użycie</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Aplikacje', $content, $user);
