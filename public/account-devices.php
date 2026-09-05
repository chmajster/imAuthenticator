<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();$message='';
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$deviceId=(int)($_POST['device_id']??0);$action=(string)($_POST['action']??'');
 if($action==='revoke'){$sessions->revokeDevice($deviceId,(int)$user['id'],(int)$user['id']);$message='<div class="alert success">Urządzenie zostało unieważnione.</div>';}
 if($action==='trust'){
  if((int)($_SESSION['auth_level']??1)<2)$message='<div class="alert danger">Oznaczenie urządzenia jako zaufane wymaga MFA / step-up authentication.</div>';
  else{$db->execute('UPDATE user_devices SET trusted=1,trusted_until=DATE_ADD(NOW(),INTERVAL 30 DAY) WHERE id=? AND user_id=? AND revoked_at IS NULL',[$deviceId,(int)$user['id']]);$audit->write('device.trusted','success',(int)$user['id'],(int)$user['id'],null,null,['device_id'=>$deviceId,'days'=>30]);$message='<div class="alert success">Urządzenie jest zaufane przez 30 dni.</div>';}
 }
}
$rows='';foreach($db->all('SELECT * FROM user_devices WHERE user_id=? ORDER BY last_seen_at DESC',[(int)$user['id']]) as $d){$revoked=$d['revoked_at']!==null;$rows.='<tr><td>'.Web::e($d['name']?:'Urządzenie').'</td><td>'.Web::e(trim(($d['platform']?:'').' '.($d['browser']?:''))?:'—').'</td><td>'.Web::e($d['last_ip']?:'—').'</td><td>'.Web::e($d['last_seen_at']).'</td><td>'.($revoked?'<span class="badge muted">Unieważnione</span>':((bool)$d['trusted']?'<span class="badge ok">Zaufane</span>':'Niezaufane')).'</td><td>';if(!$revoked){$rows.='<form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="device_id" value="'.(int)$d['id'].'"><button name="action" value="trust">Zaufaj</button><button name="action" value="revoke">Unieważnij</button></form>';}$rows.='</td></tr>';}
if($rows==='')$rows='<tr><td colspan="6" class="empty">Brak zarejestrowanych urządzeń.</td></tr>';
$content='<div class="page-head"><div><h1>Urządzenia</h1><p>Zaufane urządzenia i możliwość natychmiastowego unieważnienia.</p></div></div>'.$message.'<div class="table-wrap"><table><thead><tr><th>Nazwa</th><th>Platforma</th><th>Ostatnie IP</th><th>Ostatnio widziane</th><th>Status</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div><section class="card"><h2>Global logout</h2><p>Unieważnia wszystkie access tokeny, refresh tokeny i sesje OIDC użytkownika.</p><form method="post" action="/account/global-logout"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button>Wyloguj ze wszystkich aplikacji</button></form></section>';
Web::page('Urządzenia',$content,$user);
