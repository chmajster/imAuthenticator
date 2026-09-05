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
    $action = (string)($_POST['action'] ?? '');
    try {
        if ($action === 'create') {
            $reviews->create(
                (int)($_POST['application_id'] ?? 0),
                (int)($_POST['reviewer_user_id'] ?? $user['id']),
                (int)$user['id'],
                trim((string)($_POST['name'] ?? '')),
                trim((string)($_POST['due_at'] ?? '')) ?: null
            );
            $message = '<div class="alert success">Access Review został utworzony.</div>';
        } elseif ($action === 'decide') {
            $reviews->decide(
                (int)($_POST['review_id'] ?? 0),
                (int)($_POST['user_id'] ?? 0),
                (string)($_POST['decision'] ?? ''),
                (int)$user['id'],
                trim((string)($_POST['note'] ?? '')) ?: null
            );
            $message = '<div class="alert success">Decyzja została zapisana.</div>';
        } elseif ($action === 'complete') {
            $reviews->complete((int)($_POST['review_id'] ?? 0), (int)$user['id']);
            $message = '<div class="alert success">Przegląd został zakończony.</div>';
        }
    } catch (Throwable $e) {
        $message = '<div class="alert danger">'.Web::e($e->getMessage()).'</div>';
    }
}

$apps = $db->all('SELECT id,name FROM applications WHERE deleted_at IS NULL ORDER BY name');
$users = $db->all("SELECT id,name,email FROM users WHERE enabled=1 AND lifecycle_status='active' ORDER BY name");
$appOptions = '';
foreach ($apps as $a) {
    if ($appAdmins->canManage((int)$user['id'], (int)$a['id'], 'access_reviews')) {
        $appOptions .= '<option value="'.(int)$a['id'].'">'.Web::e($a['name']).'</option>';
    }
}
$userOptions = '';
foreach ($users as $u) {
    $userOptions .= '<option value="'.(int)$u['id'].'">'.Web::e($u['name'].' — '.$u['email']).'</option>';
}

$reviewRows = '';
foreach ($db->all("SELECT ar.*,a.name AS app_name,r.name AS reviewer_name FROM access_reviews ar JOIN applications a ON a.id=ar.application_id LEFT JOIN users r ON r.id=ar.reviewer_user_id ORDER BY ar.created_at DESC LIMIT 100") as $r) {
    if (!$appAdmins->canManage((int)$user['id'], (int)$r['application_id'], 'access_reviews') && (int)$r['reviewer_user_id'] !== (int)$user['id']) continue;
    $pending = $db->one("SELECT COUNT(*) AS c FROM access_review_items WHERE access_review_id=? AND decision='pending'", [(int)$r['id']]);
    $reviewRows .= '<tr><td>'.Web::e($r['app_name']).'</td><td>'.Web::e($r['name']).'</td><td>'.Web::e($r['reviewer_name'] ?: '—').'</td><td>'.Web::e($r['status']).'</td><td>'.(int)($pending['c'] ?? 0).'</td><td><a href="/admin/access-reviews?review='.(int)$r['id'].'">Otwórz</a></td></tr>';
}
if ($reviewRows === '') $reviewRows = '<tr><td colspan="6" class="empty">Brak przeglądów dostępu.</td></tr>';

$detail = '';
$reviewId = (int)($_GET['review'] ?? 0);
if ($reviewId > 0) {
    $rev = $db->one('SELECT ar.*,a.name AS app_name FROM access_reviews ar JOIN applications a ON a.id=ar.application_id WHERE ar.id=?', [$reviewId]);
    if ($rev && ($appAdmins->canManage((int)$user['id'], (int)$rev['application_id'], 'access_reviews') || (int)$rev['reviewer_user_id'] === (int)$user['id'])) {
        $items = '';
        foreach ($db->all('SELECT ari.*,u.name,u.email FROM access_review_items ari JOIN users u ON u.id=ari.user_id WHERE ari.access_review_id=? ORDER BY u.name', [$reviewId]) as $i) {
            $disabled = $rev['status'] !== 'active' ? ' disabled' : '';
            $items .= '<tr><td>'.Web::e($i['name']).'</td><td>'.Web::e($i['email']).'</td><td>'.Web::e($i['decision']).'</td><td>';
            if ($rev['status'] === 'active') {
                $items .= '<form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="action" value="decide"><input type="hidden" name="review_id" value="'.$reviewId.'"><input type="hidden" name="user_id" value="'.(int)$i['user_id'].'"><input name="note" placeholder="Notatka"><button class="primary" name="decision" value="keep"'.$disabled.'>Utrzymaj</button><button name="decision" value="revoke"'.$disabled.'>Odbierz</button></form>';
            }
            $items .= '</td></tr>';
        }
        if ($items === '') $items = '<tr><td colspan="4" class="empty">Brak użytkowników w tym przeglądzie.</td></tr>';
        $complete = $rev['status'] === 'active' ? '<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="review_id" value="'.$reviewId.'"><button name="action" value="complete">Zakończ przegląd</button></form>' : '';
        $detail = '<section class="card"><h2>'.Web::e($rev['app_name'].' — '.$rev['name']).'</h2><div class="table-wrap"><table><thead><tr><th>Użytkownik</th><th>E-mail</th><th>Decyzja</th><th>Akcje</th></tr></thead><tbody>'.$items.'</tbody></table></div>'.$complete.'</section>';
    }
}

$createForm = $appOptions !== '' ? '<section class="card"><h2>Nowy przegląd</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Nazwa<input name="name" required></label><label>Aplikacja<select name="application_id">'.$appOptions.'</select></label><label>Recenzent<select name="reviewer_user_id">'.$userOptions.'</select></label><label>Termin<input type="datetime-local" name="due_at"></label><button class="primary" name="action" value="create">Utwórz</button></form></section>' : '';
$content = '<div class="page-head"><div><h1>Access Reviews</h1><p>Okresowa recertyfikacja dostępu użytkowników.</p></div></div>'.$message.$createForm.'<div class="table-wrap"><table><thead><tr><th>Aplikacja</th><th>Nazwa</th><th>Recenzent</th><th>Status</th><th>Oczekujące</th><th></th></tr></thead><tbody>'.$reviewRows.'</tbody></table></div>'.$detail;
Web::page('Access Reviews', $content, $user);
