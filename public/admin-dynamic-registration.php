<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$admin=$auth->requireAdmin();$message='';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$action=(string)($_POST['action']??'');
 try{
  if($action==='create'){$name=trim((string)($_POST['name']??''));if($name==='')throw new RuntimeException('Podaj nazwę tokena.');$domains=array_values(array_filter(array_map('trim',preg_split('/\R/',(string)($_POST['domains']??''))?:[])));$until=trim((string)($_POST['valid_until']??''));$until=$until!==''?date('Y-m-d H:i:s',strtotime($until)):null;$raw=$oauthAdvanced->createRegistrationToken($name,(int)$admin['id'],$domains?:null,$until);$_SESSION['dcr_raw_token']=$raw;$message='<div class="alert success">Token został utworzony. Skopiuj go teraz; później nie będzie możliwy do odczytania.</div>';}
  if($action==='revoke'){$id=(int)($_POST['id']??0);$db->execute('UPDATE dynamic_registration_tokens SET revoked_at=NOW() WHERE id=?',[$id]);$audit->write('oauth.dcr.token_revoked','success',(int)$admin['id'],null,null,null,['token_id'=>$id]);$message='<div class="alert success">Token został unieważniony.</div>';}
 }catch(Throwable $e){$message='<div class="alert danger">'.Web::e($e->getMessage()).'</div>';}
}
$raw=$_SESSION['dcr_raw_token']??null;unset($_SESSION['dcr_raw_token']);$secret=$raw?'<section class="card"><h2>Initial Access Token</h2><code class="secret">'.Web::e($raw).'</code><p>Ten token jest wyświetlany tylko raz.</p></section>':'';
$rows='';foreach($db->all('SELECT id,name,allowed_domains_json,valid_until,revoked_at,last_used_at,created_at FROM dynamic_registration_tokens ORDER BY created_at DESC') as $r){$status=$r['revoked_at']?'Unieważniony':($r['valid_until']&&strtotime((string)$r['valid_until'])<=time()?'Wygasły':'Aktywny');$rows.='<tr><td>'.Web::e($r['name']).'</td><td>'.Web::e($r['allowed_domains_json']?:'dowolne poprawne HTTPS').'</td><td>'.Web::e($r['valid_until']?:'bezterminowo').'</td><td>'.Web::e($r['last_used_at']?:'—').'</td><td>'.Web::e($status).'</td><td>'.(!$r['revoked_at']?'<form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="id" value="'.(int)$r['id'].'"><button name="action" value="revoke">Unieważnij</button></form>':'').'</td></tr>';}
$content='<div class="page-head"><div><h1>Dynamic Client Registration</h1><p>Rejestracja klientów jest zamknięta i wymaga initial access tokena. Nowy klient otrzymuje domyślnie politykę „Brak dostępu”.</p></div></div>'.$message.$secret.'<section class="card"><h2>Nowy token rejestracyjny</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Nazwa<input name="name" required></label><label>Dozwolone domeny redirect URI — jedna na linię<textarea name="domains" rows="4" placeholder="example.com"></textarea></label><label>Ważny do<input type="datetime-local" name="valid_until"></label><button class="primary" name="action" value="create">Generuj token</button></form></section><div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>Domeny</th><th>Ważność</th><th>Ostatnie użycie</th><th>Status</th><th></th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('Dynamic Client Registration',$content,$admin);
