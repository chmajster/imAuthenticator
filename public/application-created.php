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
$redirects = array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id', [$appId]), 'redirect_uri');
$issuer = rtrim((string)$config['issuer'], '/');
$secret = $_SESSION['client_secrets'][$appId] ?? null;

$values = [
    'Issuer URL'=>$issuer,
    'Client ID'=>$app['client_id'],
    'Client Secret'=>$app['client_type']==='public' ? 'Public Client — brak sekretu' : (is_string($secret) ? $secret : 'Sekret nie jest już dostępny — regeneruj go w konfiguracji aplikacji.'),
    'Discovery URL'=>$issuer.'/.well-known/openid-configuration',
    'Authorization Endpoint'=>$issuer.'/oauth/authorize',
    'Token Endpoint'=>$issuer.'/oauth/token',
    'UserInfo Endpoint'=>$issuer.'/oauth/userinfo',
    'Logout Endpoint'=>$issuer.'/oauth/logout',
    'Redirect URI'=>$redirects === [] ? 'Nie dotyczy' : implode("\n", $redirects),
];
$rows='';
foreach($values as $label=>$value){$id='copy-'.substr(hash('sha256',$label),0,8);$rows.='<div class="kv"><span>'.Web::e($label).'</span><div><code id="'.$id.'">'.nl2br(Web::e($value)).'</code> <button type="button" class="copy-btn" data-copy="'.$id.'">Kopiuj</button></div></div>';}

$content='<div class="alert success"><strong>Aplikacja '.Web::e($app['name']).' została utworzona.</strong> Zapisz Client Secret teraz. imAuthenticator przechowuje tylko jego hash.</div>';
$content.='<div class="page-head"><div><h1>Konfiguracja '.Web::e($app['name']).'</h1><p>Gotowe dane integracji.</p></div><a class="button" href="/admin/applications/'.$appId.'">Przejdź do aplikacji</a></div>';
$content.='<section class="card"><h2>OIDC</h2>'.$rows.'<div class="actions"><a class="button primary" href="/admin/applications/'.$appId.'/config.json">Pobierz konfigurację</a><a class="button" href="/admin/applications/'.$appId.'/test">Testuj integrację</a></div></section>';
if($app['client_type']==='confidential' && is_string($secret)){
    $content.='<section class="card danger-zone"><h2>Eksport wraz z sekretem</h2><div class="alert warning"><strong>Plik będzie zawierał Client Secret w postaci jawnej.</strong> Traktuj go jak hasło. Nie wysyłaj go przez niezaufane kanały i nie zapisuj w repozytorium.</div><form method="post" action="/admin/applications/'.$appId.'/config-with-secret.json" onsubmit="return confirm(\'Eksportowany plik będzie zawierał Client Secret w postaci jawnej. Kontynuować?\')"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button class="danger" type="submit">Eksportuj konfigurację wraz z sekretem</button></form></section>';
}
$content.='<script>document.querySelectorAll(".copy-btn").forEach(b=>b.addEventListener("click",async()=>{const n=document.getElementById(b.dataset.copy);const t=n.innerText;try{await navigator.clipboard.writeText(t);const old=b.textContent;b.textContent="Skopiowano";setTimeout(()=>b.textContent=old,1200)}catch(e){}}));</script>';
Web::page('Aplikacja utworzona', $content, $admin);
