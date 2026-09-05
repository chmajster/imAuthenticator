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
    if (($_POST['action'] ?? '') === 'revoke') {
        $passkeys->revoke((int)($_POST['credential_id'] ?? 0),(int)$user['id']);
        $message = '<div class="alert success">Passkey został unieważniony.</div>';
    }
}
$rows = '';
foreach ($passkeys->credentials((int)$user['id']) as $cred) {
    $rows .= '<tr><td>'.Web::e($cred['name'] ?: 'Passkey').'</td><td>'.Web::e($cred['aaguid'] ?: '—').'</td><td>'.Web::e($cred['created_at']).'</td><td>'.Web::e($cred['last_used_at'] ?: '—').'</td><td><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="credential_id" value="'.(int)$cred['id'].'"><button name="action" value="revoke">Unieważnij</button></form></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="5" class="empty">Brak zarejestrowanych passkeys.</td></tr>';
$status = $passkeys->libraryAvailable() ? '<span class="badge ok">WebAuthn library dostępna</span>' : '<span class="badge muted">Wymagane composer install</span>';
$content = '<div class="page-head"><div><h1>WebAuthn / Passkeys</h1><p>Windows Hello, Touch ID, Face ID i klucze FIDO2.</p></div>'.$status.'</div>'.$message.'<section class="card"><h2>Stan implementacji</h2><p>Challenge, RP/user options, storage credentiali i unieważnianie są aktywne. Attestation/assertion zostaną zapisane dopiero po pełnej walidacji przez web-auth/webauthn-lib; aplikacja celowo nie przyjmuje nieweryfikowanych credentiali.</p><div class="code">GET /webauthn/register/options</div></section><div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>AAGUID</th><th>Dodano</th><th>Ostatnie użycie</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Passkeys',$content,$user);
