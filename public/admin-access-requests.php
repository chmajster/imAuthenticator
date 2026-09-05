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
    $id = (int)($_POST['request_id'] ?? 0);
    try {
        if (($_POST['action'] ?? '') === 'approve') $requests->approve($id,(int)$user['id'],trim((string)($_POST['reason'] ?? '')) ?: null);
        elseif (($_POST['action'] ?? '') === 'deny') $requests->deny($id,(int)$user['id'],trim((string)($_POST['reason'] ?? '')) ?: null);
        $message = '<div class="alert success">Decyzja została zapisana.</div>';
    } catch (Throwable $e) { $message = '<div class="alert danger">'.Web::e($e->getMessage()).'</div>'; }
}
$rows = $db->all("SELECT ar.*,a.name AS app_name,u.name AS user_name,u.email FROM access_requests ar JOIN applications a ON a.id=ar.application_id JOIN users u ON u.id=ar.user_id WHERE ar.status='pending' ORDER BY ar.created_at");
$html = '';
foreach ($rows as $row) {
    if (!$appAdmins->canManage((int)$user['id'],(int)$row['application_id'],'approve_access')) continue;
    $html .= '<tr><td>'.Web::e($row['app_name']).'</td><td>'.Web::e($row['user_name']).'<br><span class="muted">'.Web::e($row['email']).'</span></td><td>'.Web::e($row['justification'] ?: '—').'</td><td>'.($row['requested_duration_seconds']===null?'bez terminu':round((int)$row['requested_duration_seconds']/86400).' dni').'</td><td><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="request_id" value="'.(int)$row['id'].'"><input name="reason" placeholder="Komentarz decyzji"><button class="primary" name="action" value="approve">Zatwierdź</button><button name="action" value="deny">Odrzuć</button></form></td></tr>';
}
if ($html === '') $html = '<tr><td colspan="5" class="empty">Brak wniosków do rozpatrzenia.</td></tr>';
Web::page('Wnioski o dostęp', '<div class="page-head"><div><h1>Wnioski o dostęp</h1><p>Kolejka approval workflow dla administratorów i właścicieli aplikacji.</p></div></div>'.$message.'<div class="table-wrap"><table><thead><tr><th>Aplikacja</th><th>Użytkownik</th><th>Uzasadnienie</th><th>Czas</th><th>Decyzja</th></tr></thead><tbody>'.$html.'</tbody></table></div>', $user);
