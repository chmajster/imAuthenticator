<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
$apps = $db->all('SELECT a.*,(SELECT COUNT(*) FROM application_users au WHERE au.application_id=a.id AND au.enabled=1) AS users_count FROM applications a WHERE a.deleted_at IS NULL ORDER BY a.created_at DESC');
$labels = ['website'=>'Strona WWW','wordpress'=>'WordPress','php'=>'Własna aplikacja PHP','spa'=>'SPA','mobile'=>'Aplikacja mobilna','oidc'=>'Generic OpenID Connect','m2m'=>'Machine-to-Machine'];
$rows = '';
foreach ($apps as $app) {
    $id = (int)$app['id'];
    $name = Web::e($app['name']);
    $rows .= '<tr>';
    $rows .= '<td><div class="app-icon small">'.Web::e(mb_strtoupper(mb_substr((string)$app['name'],0,1))).'</div></td>';
    $rows .= '<td><a href="/admin/applications/'.$id.'"><strong>'.$name.'</strong></a></td>';
    $rows .= '<td>'.Web::e($labels[$app['app_type']] ?? $app['app_type']).'</td>';
    $rows .= '<td class="truncate"><a href="'.Web::e($app['url']).'" target="_blank" rel="noopener">'.Web::e($app['url']).'</a></td>';
    $rows .= '<td><code>'.Web::e($app['client_id']).'</code></td>';
    $rows .= '<td>'.(int)$app['users_count'].'</td>';
    $rows .= '<td><span class="badge '.((bool)$app['enabled']?'ok':'muted').'">'.((bool)$app['enabled']?'Aktywna':'Wyłączona').'</span></td>';
    $rows .= '<td>'.Web::e($app['last_used_at'] ?: '—').'</td>';
    $rows .= '<td><div class="actions compact">';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'">Otwórz</a>';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'/edit">Edytuj</a>';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'/users">Użytkownicy</a>';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'#roles">Role</a>';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'#config">Konfiguracja</a>';
    $rows .= '<a class="button" href="/admin/applications/'.$id.'/test">Testuj</a>';
    if ($app['client_type'] === 'confidential') {
        $rows .= '<form method="post" action="/admin/applications/'.$id.'/secret/regenerate" class="inline" onsubmit="return confirm(\'Regeneracja unieważni aktywne tokeny tej aplikacji. Kontynuować?\')"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button>Regeneruj secret</button></form>';
    }
    $rows .= '<form method="post" action="/admin/applications/'.$id.'/status" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="enabled" value="'.((bool)$app['enabled']?'0':'1').'"><button>'.((bool)$app['enabled']?'Wyłącz':'Włącz').'</button></form>';
    $rows .= '<form method="post" action="/admin/applications/'.$id.'/delete" class="inline" onsubmit="return confirm(\'Usunąć aplikację? Tokeny zostaną unieważnione, a wpis audytowy zachowany.\')"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button class="danger">Usuń</button></form>';
    $rows .= '</div></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="9" class="empty">Brak aplikacji.</td></tr>';

$content = '<div class="page-head"><div><h1>Aplikacje</h1><p>Klienci OAuth/OIDC, polityki dostępu i operacje administracyjne.</p></div><a class="button primary" href="/admin/applications/new">Dodaj aplikację</a></div>';
$content .= '<div class="table-wrap"><table><thead><tr><th>Ikona</th><th>Nazwa</th><th>Typ</th><th>URL</th><th>Client ID</th><th>Użytkownicy</th><th>Status</th><th>Ostatnie użycie</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Aplikacje', $content, $admin);
