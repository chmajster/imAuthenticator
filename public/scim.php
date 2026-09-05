<?php
declare(strict_types=1);

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);
header('Content-Type: application/scim+json; charset=utf-8');header('Cache-Control: no-store');
function scimOut(array $data,int $status=200):never{http_response_code($status);echo json_encode($data,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);exit;}
function scimError(string $detail,int $status):never{scimOut(['schemas'=>['urn:ietf:params:scim:api:messages:2.0:Error'],'status'=>(string)$status,'detail'=>$detail],$status);}
$connectorId=(int)($_GET['connector']??0);$resource=(string)($_GET['resource']??'');$resourceId=(string)($_GET['resource_id']??'');$authz=(string)($_SERVER['HTTP_AUTHORIZATION']??'');$bearer=str_starts_with($authz,'Bearer ')?trim(substr($authz,7)):'';
try{$connector=$scim->authenticate($connectorId,$bearer);}catch(Throwable){scimError('Unauthorized',401);}
$method=strtoupper($_SERVER['REQUEST_METHOD']??'GET');$body=file_get_contents('php://input');$payload=$body!==false&&$body!==''?json_decode($body,true):[];if(!is_array($payload))scimError('Invalid JSON',400);
try{
 if($resource==='ServiceProviderConfig'&&$method==='GET')scimOut(['schemas'=>['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],'patch'=>['supported'=>true],'bulk'=>['supported'=>false],'filter'=>['supported'=>true,'maxResults'=>200],'changePassword'=>['supported'=>false],'sort'=>['supported'=>false],'etag'=>['supported'=>false],'authenticationSchemes'=>[['type'=>'oauthbearertoken','name'=>'Bearer Token','description'=>'SCIM bearer token']]]);
 if($resource==='Users'){
  if($method==='GET'&&$resourceId===''){ $r=$scim->listUsers($connector,isset($_GET['filter'])?(string)$_GET['filter']:null);scimOut(['schemas'=>['urn:ietf:params:scim:api:messages:2.0:ListResponse'],'totalResults'=>count($r),'startIndex'=>1,'itemsPerPage'=>count($r),'Resources'=>$r]); }
  if($method==='GET')scimOut($scim->getUser($connector,$resourceId));
  if($method==='POST')scimOut($scim->createUser($connector,$payload),201);
  if($method==='PATCH')scimOut($scim->patchUser($connector,$resourceId,$payload));
  if($method==='DELETE'){ $scim->deleteUser($connector,$resourceId);http_response_code(204);exit; }
 }
 if($resource==='Groups'&&$method==='GET'){ $r=$scim->listGroups($connector);scimOut(['schemas'=>['urn:ietf:params:scim:api:messages:2.0:ListResponse'],'totalResults'=>count($r),'startIndex'=>1,'itemsPerPage'=>count($r),'Resources'=>$r]); }
 scimError('Not implemented',501);
}catch(RuntimeException $e){$map=['not_found'=>404,'invalidValue'=>400,'unauthorized'=>401];scimError($e->getMessage(),$map[$e->getMessage()]??400);}
