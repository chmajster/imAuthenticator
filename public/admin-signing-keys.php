<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$admin=$auth->requireAdmin();$message='';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);
 try{$grace=max(3600,(int)($_POST['grace_seconds']??7200));$result=$signingKeys->rotate((int)$admin['id'],$grace);$message='<div class="alert success">Nowy klucz <code>'.Web::e($result['kid']).'</code> jest aktywny. Poprzedni pozostaje w JWKS do '.Web::e($result['old_key_visible_until']).'.</div>';}catch(Throwable $e){$message='<div class="alert danger">'.Web::e($e->getMessage()).'</div>';}
}
$signingKeys->retireExpired();$rows='';foreach($db->all('SELECT kid,algorithm,storage_provider,status,not_before,not_after,created_at,retired_at FROM signing_keys ORDER BY created_at DESC') as $r){$rows.='<tr><td><code>'.Web::e($r['kid']).'</code></td><td>'.Web::e($r['algorithm']).'</td><td>'.Web::e($r['storage_provider']).'</td><td>'.Web::e($r['status']).'</td><td>'.Web::e($r['not_before']).'</td><td>'.Web::e($r['not_after']?:'—').'</td></tr>';}
$current=(string)($config['keys']['kid']??'');$content='<div class="page-head"><div><h1>Signing Keys</h1><p>Aktywny kid: <code>'.Web::e($current).'</code>. Stare klucze publiczne pozostają w JWKS do końca okresu ochronnego.</p></div></div>'.$message.'<section class="card"><h2>Rotacja klucza</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Okres publikacji starego klucza (sekundy)<input type="number" min="3600" max="604800" name="grace_seconds" value="7200" required></label><div class="alert warning">Rotacja aktualizuje pliki kluczy i konfigurację atomowo. Nie wykonuj jej, jeśli katalog config/keys nie jest zapisywalny przez proces PHP.</div><button class="primary" type="submit">Rotuj signing key</button></form></section><div class="table-wrap"><table><thead><tr><th>kid</th><th>Algorytm</th><th>Storage</th><th>Status</th><th>Od</th><th>Do</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Signing Keys',$content,$admin);
