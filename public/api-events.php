<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');
$header=(string)($_SERVER['HTTP_AUTHORIZATION']??'');$raw=str_starts_with($header,'Bearer ')?trim(substr($header,7)):(string)($_SERVER['HTTP_X_API_KEY']??'');
try{
 $principal=$apiKeys->authenticate($raw,'events.read');$after=max(0,(int)($_GET['after_id']??0));$limit=max(1,min(500,(int)($_GET['limit']??100)));$org=$principal['organization_id'];
 if($org===null)$rows=$db->all('SELECT id,event_uuid,organization_id,event_type,payload_json,created_at FROM event_outbox WHERE id>? ORDER BY id LIMIT '.$limit,[$after]);
 else $rows=$db->all('SELECT id,event_uuid,organization_id,event_type,payload_json,created_at FROM event_outbox WHERE id>? AND organization_id=? ORDER BY id LIMIT '.$limit,[$after,(int)$org]);
 $items=[];$next=$after;foreach($rows as $row){$next=max($next,(int)$row['id']);$items[]=['id'=>(int)$row['id'],'event_id'=>$row['event_uuid'],'organization_id'=>$row['organization_id']===null?null:(int)$row['organization_id'],'type'=>$row['event_type'],'payload'=>json_decode((string)$row['payload_json'],true),'created_at'=>$row['created_at']];}
 echo json_encode(['events'=>$items,'next_after_id'=>$next],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
}catch(RuntimeException $e){$error=$e->getMessage();http_response_code($error==='insufficient_scope'?403:401);header('WWW-Authenticate: Bearer realm="imAuthenticator Event API"');echo json_encode(['error'=>$error],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);}
