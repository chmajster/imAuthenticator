<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireAdmin();
$message = '';
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $type = (string)($_POST['provider_type'] ?? 'oidc');
    $allowed = ['oidc','saml','entra','google','github','ldap','active_directory'];
    $name = trim((string)($_POST['name'] ?? ''));
    $configJson = trim((string)($_POST['config_json'] ?? '{}'));
    $decoded = json_decode($configJson,true);
    if ($name === '' || !in_array($type,$allowed,true) || !is_array($decoded)) $message = '<div class="alert danger">Nieprawidłowa konfiguracja providera.</div>';
    else {
        $db->execute('INSERT INTO identity_providers(name,provider_type,config_json,enabled) VALUES(?,?,?,1)', [$name,$type,json_encode($decoded,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)]);
        $audit->write('identity_provider.created','success',(int)$user['id'],null,null,null,['name'=>$name,'type'=>$type]);
        $message = '<div class="alert success">Provider został zapisany.</div>';
    }
}
$rows = '';
foreach ($db->all('SELECT id,name,provider_type,enabled,updated_at FROM identity_providers ORDER BY name') as $idp) $rows .= '<tr><td>'.Web::e($idp['name']).'</td><td>'.Web::e($idp['provider_type']).'</td><td>'.((bool)$idp['enabled']?'Aktywny':'Wyłączony').'</td><td>'.Web::e($idp['updated_at']).'</td></tr>';
if ($rows==='') $rows='<tr><td colspan="4" class="empty">Brak providerów.</td></tr>';
$content='<div class="page-head"><div><h1>Identity Providers</h1><p>OIDC, SAML, Entra ID, Google, GitHub, LDAP i Active Directory.</p></div></div>'.$message.'<section class="card"><h2>Dodaj provider</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Nazwa<input name="name" required></label><label>Typ<select name="provider_type"><option value="entra">Microsoft Entra ID</option><option value="google">Google</option><option value="github">GitHub</option><option value="oidc">Generic OIDC</option><option value="saml">SAML 2.0</option><option value="ldap">LDAP</option><option value="active_directory">Active Directory</option></select></label><label>Konfiguracja JSON<textarea name="config_json" rows="8">{}</textarea></label><button class="primary">Zapisz</button></form></section><div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>Typ</th><th>Status</th><th>Aktualizacja</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Identity Providers',$content,$user);
