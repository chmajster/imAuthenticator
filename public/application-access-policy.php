<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$admin = $auth->requireAdmin();
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { http_response_code(405); exit; }
Security::requireCsrf($_POST['_csrf'] ?? null);
$appId = (int)($_GET['id'] ?? 0);
$app = $db->one('SELECT id,access_policy FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
if (!$app) { http_response_code(404); exit('Nie znaleziono aplikacji.'); }

$policy = (string)($_POST['access_policy'] ?? 'none');
if (!in_array($policy, ['none','all','users','groups','roles','mixed'], true)) $policy = 'none';
$groupIds = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['group_ids'] ?? [])), static fn(int $v): bool => $v > 0)));
$roleIds = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['system_role_ids'] ?? [])), static fn(int $v): bool => $v > 0)));

$validGroups = [];
if ($groupIds !== []) {
    $placeholders = implode(',', array_fill(0, count($groupIds), '?'));
    $validGroups = array_map('intval', array_column($db->all("SELECT id FROM user_groups WHERE id IN ($placeholders)", $groupIds), 'id'));
}
$validRoles = [];
if ($roleIds !== []) {
    $placeholders = implode(',', array_fill(0, count($roleIds), '?'));
    $validRoles = array_map('intval', array_column($db->all("SELECT id FROM system_roles WHERE id IN ($placeholders)", $roleIds), 'id'));
}

$oldGroups = array_map('intval', array_column($db->all('SELECT group_id FROM application_groups WHERE application_id=?', [$appId]), 'group_id'));
$oldRoles = array_map('intval', array_column($db->all('SELECT role_id FROM application_system_roles WHERE application_id=?', [$appId]), 'role_id'));
$addedGroups = array_values(array_diff($validGroups, $oldGroups));
$removedGroups = array_values(array_diff($oldGroups, $validGroups));
$addedRoles = array_values(array_diff($validRoles, $oldRoles));
$removedRoles = array_values(array_diff($oldRoles, $validRoles));

$db->transaction(function () use ($db,$appId,$policy,$validGroups,$validRoles,$admin): void {
    $db->execute('UPDATE applications SET access_policy=? WHERE id=?', [$policy,$appId]);
    $db->execute('DELETE FROM application_groups WHERE application_id=?', [$appId]);
    foreach ($validGroups as $id) $db->execute('INSERT INTO application_groups(application_id,group_id,created_by) VALUES(?,?,?)', [$appId,$id,(int)$admin['id']]);
    $db->execute('DELETE FROM application_system_roles WHERE application_id=?', [$appId]);
    foreach ($validRoles as $id) $db->execute('INSERT INTO application_system_roles(application_id,role_id,created_by) VALUES(?,?,?)', [$appId,$id,(int)$admin['id']]);
});

$audit->write('application.access_policy.updated', 'success', (int)$admin['id'], null, $appId, null, ['from'=>$app['access_policy'],'to'=>$policy]);
foreach ($addedGroups as $id) $audit->write('application.group.assigned', 'success', (int)$admin['id'], null, $appId, null, ['group_id'=>$id]);
foreach ($removedGroups as $id) $audit->write('application.group.removed', 'success', (int)$admin['id'], null, $appId, null, ['group_id'=>$id]);
foreach ($addedRoles as $id) $audit->write('application.system_role.assigned', 'success', (int)$admin['id'], null, $appId, null, ['role_id'=>$id]);
foreach ($removedRoles as $id) $audit->write('application.system_role.removed', 'success', (int)$admin['id'], null, $appId, null, ['role_id'=>$id]);

Web::redirect('/admin/applications/'.$appId.'#access');
