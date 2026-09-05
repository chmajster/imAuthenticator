<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();$message='';$newToken=null;
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$appId=(int)($_POST['application_id']??0);$action=(string)($_POST['action']??'create_inbound');
 try{
  if($action==='sync_outbound'){$connectorId=(int)$_POST['connector_id'];$connector=$db->one('SELECT application_id FROM scim_connectors WHERE id=?',[$connectorId]);if(!$connector||!$appAdmins->canManage((int)$user['id'],(int)$connector['application_id'],'manage_scim'))throw new RuntimeException('Brak uprawnień.');$result=$scimOutbound->sync($connectorId,(int)$user['id']);$message='<pre class="code">'.Web::e(json_encode($result,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)).'</pre>';
  }else{
   if(!$appAdmins->canManage((int)$user['id'],$appId,'manage_scim'))throw new RuntimeException('Brak uprawnień do SCIM tej aplikacji.');
   if($action==='create_outbound'){$id=$scimOutbound->createConnector($appId,trim((string)$_POST['base_url']),(string)$_POST['bearer_token'],(int)$user['id']);$message='<div class="alert success">Outbound connector #'.(int)$id.' został utworzony. Token zapisano zaszyfrowany.</div>';}
   else{$token='scim_'.Security::randomToken(48);$db->execute("INSERT INTO scim_connectors(application_id,enabled,direction,bearer_token_hash,mapping_json) VALUES(?,1,'inbound',?,?)",[$appId,hash('sha256',$token),json_encode(['userName'=>'username','email'=>'email'],JSON_THROW_ON_ERROR)]);$id=$db->lastInsertId();$audit->write('scim.connector.created','success',(int)$user['id'],null,$appId,null,['connector_id'=>$id]);$newToken=['token'=>$token,'id'=>$id];}
  }
 }catch(Throwable $e){$message='<div class="alert danger">'.Web::e($e->getMessage()).'</div>';}
}
$apps=$db->all('SELECT id,name FROM applications WHERE deleted_at IS NULL ORDER BY name');$appOptions='';foreach($apps as $a)if($appAdmins->canManage((int)$user['id'],(int)$a['id'],'manage_scim'))$appOptions.='<option value="'.(int)$a['id'].'">'.Web::e($a['name']).'</option>';
$rows='';foreach($db->all('SELECT sc.*,a.name AS app_name FROM scim_connectors sc JOIN applications a ON a.id=sc.application_id ORDER BY sc.id DESC') as $sc){if(!$appAdmins->canManage((int)$user['id'],(int)$sc['application_id'],'manage_scim'))continue;$endpoint=$sc['direction']==='inbound'?rtrim((string)$config['issuer'],'/').'/scim/v2/'.(int)$sc['id']:(string)$sc['base_url'];$action=$sc['direction']==='outbound'?'<form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><input type="hidden" name="connector_id" value="'.(int)$sc['id'].'"><button name="action" value="sync_outbound">Synchronizuj</button></form>':'';$rows.='<tr><td>'.Web::e($sc['app_name']).'</td><td>'.Web::e($sc['direction']).'</td><td><code>'.Web::e($endpoint).'</code></td><td>'.((bool)$sc['enabled']?'Aktywny':'Wyłączony').'</td><td>'.Web::e($sc['last_sync_at']?:'—').'</td><td>'.$action.'</td></tr>';}
if($rows==='')$rows='<tr><td colspan="6" class="empty">Brak connectorów SCIM.</td></tr>';
$tokenBox=$newToken?'<div class="alert warning"><strong>Bearer token — zapisz teraz.</strong><div class="code">'.Web::e($newToken['token']).'</div><p>Endpoint: <code>'.Web::e(rtrim((string)$config['issuer'],'/').'/scim/v2/'.$newToken['id']).'</code></p><p>Token jest przechowywany wyłącznie jako hash.</p></div>':'';
$forms='';if($appOptions!==''){$forms='<section class="card"><h2>Nowy inbound connector</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Aplikacja<select name="application_id">'.$appOptions.'</select></label><button class="primary" name="action" value="create_inbound">Utwórz connector i token</button></form></section><section class="card"><h2>Nowy outbound connector</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Aplikacja<select name="application_id">'.$appOptions.'</select></label><label>SCIM base URL HTTPS<input type="url" name="base_url" placeholder="https://service.example.com/scim/v2" required></label><label>Bearer token<input type="password" name="bearer_token" required autocomplete="off"></label><div class="alert warning">Token zostanie zaszyfrowany kluczem aplikacyjnym i nie będzie ponownie wyświetlany.</div><button class="primary" name="action" value="create_outbound">Utwórz outbound connector</button></form></section>';}
$content='<div class="page-head"><div><h1>SCIM 2.0</h1><p>Inbound i outbound provisioning/deprovisioning użytkowników oraz ról aplikacyjnych.</p></div></div>'.$message.$tokenBox.$forms.'<div class="table-wrap"><table><thead><tr><th>Aplikacja</th><th>Kierunek</th><th>Endpoint</th><th>Status</th><th>Ostatni sync</th><th></th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('SCIM 2.0',$content,$user);
