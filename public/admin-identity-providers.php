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
    $action=(string)($_POST['action']??'create');
    try{
        if($action==='toggle'){
            $id=(int)$_POST['id'];$db->execute('UPDATE identity_providers SET enabled=NOT enabled WHERE id=?',[$id]);$audit->write('identity_provider.toggled','success',(int)$user['id'],null,null,null,['provider_id'=>$id]);
        }else{
            $type = (string)($_POST['provider_type'] ?? 'oidc');
            $allowed = ['oidc','saml','entra','google','github','ldap','active_directory'];
            $name = trim((string)($_POST['name'] ?? ''));
            $configJson = trim((string)($_POST['config_json'] ?? '{}'));
            $decoded = json_decode($configJson,true);
            if ($name === '' || !in_array($type,$allowed,true) || !is_array($decoded)) throw new RuntimeException('Nieprawidłowa konfiguracja providera.');
            if(isset($decoded['client_secret']))throw new RuntimeException('Nie zapisuj client_secret w bazie. Użyj client_secret_env.');
            if(in_array($type,['oidc','entra','google','github'],true)){
                if(empty($decoded['client_id'])||empty($decoded['client_secret_env']))throw new RuntimeException('Provider OAuth/OIDC wymaga client_id i client_secret_env.');
                $env=(string)$decoded['client_secret_env'];if(!preg_match('/^[A-Z_][A-Z0-9_]*$/',$env))throw new RuntimeException('client_secret_env musi być nazwą zmiennej środowiskowej.');
                if($type==='oidc'&&(empty($decoded['issuer'])||!filter_var($decoded['issuer'],FILTER_VALIDATE_URL)))throw new RuntimeException('Generic OIDC wymaga issuer URL.');
                if($type==='entra'&&empty($decoded['tenant']))$decoded['tenant']='common';
                $decoded['auto_provision']=(bool)($decoded['auto_provision']??false);
                $decoded['auth_level']=max(1,min(3,(int)($decoded['auth_level']??1)));
            }
            $db->execute('INSERT INTO identity_providers(name,provider_type,config_json,enabled) VALUES(?,?,?,1)', [$name,$type,json_encode($decoded,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)]);
            $audit->write('identity_provider.created','success',(int)$user['id'],null,null,null,['name'=>$name,'type'=>$type]);
            $message = '<div class="alert success">Provider został zapisany.</div>';
        }
    }catch(Throwable $e){$message='<div class="alert danger">'.Web::e($e->getMessage()).'</div>';}
}
$rows = '';
foreach ($db->all('SELECT id,name,provider_type,enabled,config_json,updated_at FROM identity_providers ORDER BY name') as $idp){$cfg=json_decode((string)$idp['config_json'],true);if(!is_array($cfg))$cfg=[];unset($cfg['client_secret']);$rows .= '<tr><td>'.Web::e($idp['name']).'</td><td>'.Web::e($idp['provider_type']).'</td><td>'.((bool)$idp['enabled']?'Aktywny':'Wyłączony').'</td><td><code>'.Web::e(json_encode($cfg,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)).'</code></td><td>'.Web::e($idp['updated_at']).'</td><td><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="id" value="'.(int)$idp['id'].'"><button name="action" value="toggle">'.((bool)$idp['enabled']?'Wyłącz':'Włącz').'</button></form></td></tr>';}
if ($rows==='') $rows='<tr><td colspan="6" class="empty">Brak providerów.</td></tr>';
$example='{"client_id":"...","client_secret_env":"IMAUTH_GOOGLE_SECRET","scopes":"openid profile email","auto_provision":false,"allowed_domains":["example.com"],"auth_level":1}';
$content='<div class="page-head"><div><h1>Identity Providers</h1><p>OIDC, Microsoft Entra ID, Google, GitHub, SAML, LDAP i Active Directory.</p></div></div>'.$message.'<section class="card"><h2>Dodaj provider</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Nazwa<input name="name" required></label><label>Typ<select name="provider_type"><option value="entra">Microsoft Entra ID</option><option value="google">Google</option><option value="github">GitHub</option><option value="oidc">Generic OIDC</option><option value="saml">SAML 2.0</option><option value="ldap">LDAP</option><option value="active_directory">Active Directory</option></select></label><label>Konfiguracja JSON<textarea name="config_json" rows="10">'.Web::e($example).'</textarea></label><div class="alert warning">Sekretów OAuth nie zapisuj w JSON. Ustaw sekret w środowisku procesu PHP i podaj wyłącznie nazwę zmiennej w <code>client_secret_env</code>. Dla Generic OIDC dodaj <code>issuer</code>, dla Entra możesz podać <code>tenant</code>.</div><button class="primary" name="action" value="create">Zapisz</button></form></section><div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>Typ</th><th>Status</th><th>Konfiguracja</th><th>Aktualizacja</th><th></th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Identity Providers',$content,$user);
