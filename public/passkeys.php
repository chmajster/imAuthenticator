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
    $transports=json_decode((string)($cred['transports_json']??'[]'),true);$transportText=is_array($transports)&&$transports!==[]?implode(', ',$transports):'—';
    $rows .= '<tr><td>'.Web::e($cred['name'] ?: 'Passkey').'</td><td>'.Web::e($cred['aaguid'] ?: '—').'</td><td>'.Web::e($transportText).'</td><td>'.Web::e($cred['created_at']).'</td><td>'.Web::e($cred['last_used_at'] ?: '—').'</td><td><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="credential_id" value="'.(int)$cred['id'].'"><button name="action" value="revoke">Unieważnij</button></form></td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="6" class="empty">Brak zarejestrowanych passkeys.</td></tr>';
$status = $passkeys->libraryAvailable() ? '<span class="badge ok">WebAuthn gotowe</span>' : '<span class="badge muted">Wymagane composer install</span>';
$csrf=Web::e(Security::csrfToken());
$content = '<div class="page-head"><div><h1>WebAuthn / Passkeys</h1><p>Windows Hello, Touch ID, Face ID i klucze FIDO2.</p></div>'.$status.'</div>'.$message;
$content .= '<section class="card"><h2>Dodaj passkey</h2><p>Credential jest zapisywany dopiero po kryptograficznej walidacji challenge, originu, RP ID, user verification i attestation przez web-auth/webauthn-lib.</p><label>Nazwa urządzenia/passkey<input id="passkeyName" maxlength="190" placeholder="np. Windows Hello — laptop"></label><button class="primary" type="button" id="registerPasskey">Dodaj passkey</button><div id="passkeyResult"></div></section>';
$content .= '<div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>AAGUID</th><th>Transport</th><th>Dodano</th><th>Ostatnie użycie</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
$content .= '<script src="/assets/webauthn.js"></script><script>(()=>{const btn=document.getElementById("registerPasskey"),out=document.getElementById("passkeyResult");btn.addEventListener("click",async()=>{out.innerHTML="";btn.disabled=true;try{if(!window.PublicKeyCredential)throw new Error("Ta przeglądarka nie obsługuje WebAuthn.");const optRes=await fetch("/webauthn/register/options",{credentials:"same-origin",headers:{"Accept":"application/json"}});const payload=await optRes.json();if(!optRes.ok)throw new Error(payload.detail||payload.error||"Nie można utworzyć challenge.");const credential=await navigator.credentials.create({publicKey:window.imWebAuthn.creationOptions(payload.publicKey)});if(!credential)throw new Error("Rejestracja została anulowana.");const complete=await fetch("/webauthn/register/complete",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({_csrf:"'.$csrf.'",challenge_id:payload.challenge_id,name:document.getElementById("passkeyName").value,credential:window.imWebAuthn.credentialToJSON(credential)})});const result=await complete.json();if(!complete.ok)throw new Error(result.detail||result.error||"Walidacja passkey nie powiodła się.");location.reload();}catch(e){out.innerHTML="<div class=\"alert danger\"></div>";out.firstElementChild.textContent=e?.message||"Błąd WebAuthn";}finally{btn.disabled=false;}});})();</script>';
Web::page('Passkeys',$content,$user);
