<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);$user=$auth->requireUser();$message='';$newToken=null;
if(strtoupper($_SERVER['REQUEST_METHOD']??'GET')==='POST'){
 Security::requireCsrf($_POST['_csrf']??null);$appId=(int)($_POST['application_id']??0);
 if(!$appAdmins->canManage((int)$user['id'],$appId,'manage_scim'))$message='<div class="alert danger">Brak uprawnień do SCIM tej aplikacji.</div>';
 else{$token='scim_'.Security::randomToken(48);$db->execute("INSERT INTO scim_connectors(application_id,enabled,direction,bearer_token_hash,mapping_json) VALUES(?,1,'inbound',?,?)",[$appId,hash('sha256',$token),json_encode(['userName'=>'username','email'=>'email'],JSON_THROW_ON_ERROR)]);$id=$db->lastInsertId();$audit->write('scim.connector.created','success',(int)$user['id'],null,$appId,null,['connector_id'=>$id]);$newToken=['token'=>$token,'id'=>$id];}
}
$apps=$db->all('SELECT id,name FROM applications WHERE deleted_at IS NULL ORDER BY name');$appOptions='';foreach($apps as $a)if($appAdmins->canManage((int)$user['id'],(int)$a['id'],'manage_scim'))$appOptions.='<option value="'.(int)$a['id'].'">'.Web::e($a['name']).'</option>';
$rows='';foreach($db->all('SELECT sc.*,a.name AS app_name FROM scim_connectors sc JOIN applications a ON a.id=sc.application_id ORDER BY sc.id DESC') as $sc){if(!$appAdmins->canManage((int)$user['id'],(int)$sc['application_id'],'manage_scim'))continue;$base=rtrim((string)$config['issuer'],'/').'/scim/v2/'.(int)$sc['id'];$rows.='<tr><td>'.Web::e($sc['app_name']).'</td><td>'.Web::e($sc['direction']).'</td><td><code>'.Web::e($base).'</code></td><td>'.((bool)$sc['enabled']?'Aktywny':'Wyłączony').'</td><td>'.Web::e($sc['last_sync_at']?:'—').'</td></tr>';}
if($rows==='')$rows='<tr><td colspan="5" class="empty">Brak connectorów SCIM.</td></tr>';
$tokenBox=$newToken?'<div class="alert warning"><strong>Bearer token — zapisz teraz.</strong><div class="code">'.Web::e($newToken['token']).'</div><p>Endpoint: <code>'.Web::e(rtrim((string)$config['issuer'],'/').'/scim/v2/'.$newToken['id']).'</code></p><p>Token jest przechowywany wyłącznie jako hash.</p></div>':'';
$content='<div class="page-head"><div><h1>SCIM 2.0</h1><p>Provisioning i deprovisioning użytkowników do aplikacji.</p></div></div>'.$message.$tokenBox.($appOptions!==''?'<section class="card"><h2>Nowy inbound connector</h2><form method="post"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><label>Aplikacja<select name="application_id">'.$appOptions.'</select></label><button class="primary">Utwórz connector i token</button></form></section>':'').'<div class="table-wrap"><table><thead><tr><th>Aplikacja</th><th>Kierunek</th><th>Base URL</th><th>Status</th><th>Ostatni sync</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('SCIM 2.0',$content,$user);
