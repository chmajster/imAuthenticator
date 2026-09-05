<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
$appId = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
if (!$app) { http_response_code(404); Web::page('Nie znaleziono', '<div class="alert danger">Nie znaleziono aplikacji.</div>', $admin); }

$applyRole = static function (int $userId, int $roleId, string $action) use ($db,$audit,$admin,$appId): void {
    $role = $db->one('SELECT id,name FROM app_roles WHERE id=? AND application_id=?', [$roleId,$appId]);
    if (!$role) return;
    if ($action === 'assign_role') {
        $db->execute('INSERT IGNORE INTO app_user_roles(application_id,user_id,app_role_id,created_by) VALUES(?,?,?,?)', [$appId,$userId,$roleId,(int)$admin['id']]);
    } else {
        $db->execute('DELETE FROM app_user_roles WHERE application_id=? AND user_id=? AND app_role_id=?', [$appId,$userId,$roleId]);
    }
    $audit->write('application.user_role.'.($action==='assign_role'?'assigned':'removed'), 'success', (int)$admin['id'], $userId, $appId, null, ['role'=>$role['name']]);
};

if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $action = (string)($_POST['action'] ?? '');
    $roleId = (int)($_POST['app_role_id'] ?? 0);
    $userIds = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['user_ids'] ?? [])), static fn(int $v): bool => $v > 0)));
    if ($userIds === []) {
        $single = (int)($_POST['user_id'] ?? 0);
        if ($single > 0) $userIds = [$single];
    }

    foreach ($userIds as $userId) {
        if ($action === 'grant') $access->grantUser($appId, $userId, (int)$admin['id']);
        elseif ($action === 'revoke') $access->revokeUser($appId, $userId, (int)$admin['id']);
        elseif (in_array($action, ['assign_role','remove_role'], true) && $roleId > 0) $applyRole($userId, $roleId, $action);
    }
    Web::redirect('/admin/applications/'.$appId.'/users'.(!empty($_GET['q'])?'?q='.rawurlencode((string)$_GET['q']):''));
}

$q = trim((string)($_GET['q'] ?? ''));
$params = [$appId];
$sql = 'SELECT u.id,u.name,u.email,u.enabled,au.enabled AS direct_enabled,au.created_at,creator.email AS creator_email FROM users u LEFT JOIN application_users au ON au.user_id=u.id AND au.application_id=? LEFT JOIN users creator ON creator.id=au.created_by';
if ($q !== '') { $sql .= ' WHERE u.name LIKE ? OR u.email LIKE ?'; $params[] = '%'.$q.'%'; $params[] = '%'.$q.'%'; }
$sql .= ' ORDER BY u.name LIMIT 200';
$users = $db->all($sql, $params);
$roles = $db->all('SELECT id,name FROM app_roles WHERE application_id=? ORDER BY name', [$appId]);
$roleOptions = '<option value="">— wybierz rolę —</option>';
foreach ($roles as $role) $roleOptions .= '<option value="'.(int)$role['id'].'">'.Web::e($role['name']).'</option>';

$rows = '';
foreach ($users as $user) {
    $uid = (int)$user['id'];
    $has = $access->hasAccess($uid, $app);
    $userRoles = $access->rolesForUser($uid, $appId);
    $direct = $user['direct_enabled'] === null ? 'Dziedziczony / brak wpisu' : ((bool)$user['direct_enabled'] ? 'Jawnie nadany' : 'Jawnie zablokowany');
    $rows .= '<tr><td><input type="checkbox" name="user_ids[]" value="'.$uid.'" form="bulkForm" aria-label="Wybierz '.Web::e($user['name']).'"></td><td><a href="/admin/users/'.$uid.'/applications"><strong>'.Web::e($user['name']).'</strong></a></td><td>'.Web::e($user['email']).'</td><td>'.((bool)$user['enabled']?'Aktywny':'Wyłączony').'</td><td><span class="badge '.($has?'ok':'muted').'">'.($has?'Tak':'Nie').'</span><div class="muted">'.Web::e($direct).'</div></td><td>'.Web::e(implode(', ', $userRoles) ?: '—').'</td><td>'.Web::e($user['created_at'] ?: '—').'</td><td>'.Web::e($user['creator_email'] ?: '—').'</td><td><div class="actions compact">';
    $rows .= '<form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="user_id" value="'.$uid.'"><button name="action" value="'.($has?'revoke':'grant').'" class="'.($has?'':'primary').'">'.($has?'Odbierz dostęp':'Nadaj dostęp').'</button></form>';
    if ($roles !== []) {
        $rows .= '<form method="post" class="inline role-form"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="user_id" value="'.$uid.'"><select name="app_role_id" required>'.$roleOptions.'</select><button name="action" value="assign_role">Przypisz rolę</button><button name="action" value="remove_role">Usuń rolę</button></form>';
    }
    $rows .= '</div></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="9" class="empty">Brak użytkowników spełniających kryteria.</td></tr>';

$content = '<div class="page-head"><div><h1>Użytkownicy — '.Web::e($app['name']).'</h1><p>Jawne nadania i blokady mają pierwszeństwo nad dostępem odziedziczonym z grup, ról lub polityki „wszyscy”.</p></div><a class="button" href="/admin/applications/'.$appId.'">Wróć do aplikacji</a></div>';
$content .= '<section class="card"><h2>Dodaj użytkownika</h2><form method="get" action="/admin/applications/'.$appId.'/users" class="toolbar"><input name="q" value="'.Web::e($q).'" placeholder="Szukaj po nazwie lub e-mailu"><button class="primary" type="submit">Szukaj</button>'.($q!==''?'<a class="button" href="/admin/applications/'.$appId.'/users">Wyczyść</a>':'').'</form></section>';
$content .= '<section class="card"><h2>Operacje zbiorcze</h2><form method="post" id="bulkForm" class="toolbar"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><select name="action" required><option value="grant">Nadaj dostęp</option><option value="revoke">Odbierz dostęp</option><option value="assign_role">Przypisz rolę</option><option value="remove_role">Usuń rolę</option></select><select name="app_role_id">'.$roleOptions.'</select><button class="primary" type="submit">Wykonaj dla zaznaczonych</button></form></section>';
$content .= '<div class="table-wrap"><table><thead><tr><th><input type="checkbox" id="selectAll" aria-label="Zaznacz wszystkich"></th><th>Użytkownik</th><th>E-mail</th><th>Status</th><th>Dostęp</th><th>Role w aplikacji</th><th>Data nadania</th><th>Kto nadał</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
$content .= '<script>const all=document.getElementById("selectAll");if(all)all.addEventListener("change",()=>document.querySelectorAll("input[name=\"user_ids[]\"]").forEach(x=>x.checked=all.checked));</script>';
Web::page('Użytkownicy aplikacji', $content, $admin);
