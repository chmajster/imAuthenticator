<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services=require dirname(__DIR__).'/src/bootstrap.php';extract($services,EXTR_SKIP);
$params=$_GET;$parId=null;
try{
 if(isset($_GET['request_uri'])){
  $requestUri=(string)$_GET['request_uri'];
  $par=$db->one('SELECT * FROM oauth_par_requests WHERE request_uri_hash=? AND used_at IS NULL AND expires_at>NOW()',[Security::tokenHash($requestUri)]);
  if(!$par)throw new RuntimeException('invalid_request_uri');
  $decoded=json_decode((string)$par['params_json'],true);if(!is_array($decoded))throw new RuntimeException('invalid_request_uri');$params=$decoded;$parId=(int)$par['id'];
 }
 $clientId=(string)($params['client_id']??'');$redirectUri=(string)($params['redirect_uri']??'');$state=isset($params['state'])?(string)$params['state']:null;
 $app=$oidc->client($clientId);
 if(!$app){http_response_code(400);Web::page('Błąd OAuth','<section class="card narrow"><h1>Nieprawidłowy klient</h1><div class="code">invalid_client</div></section>');}
 if(!$oidc->redirectAllowed((int)$app['id'],$redirectUri)){http_response_code(400);Web::page('Błąd OAuth','<section class="card narrow"><h1>Nieprawidłowy Redirect URI</h1><p>Żądanie zostało zatrzymane bez przekierowania do klienta.</p><div class="code">invalid_request</div></section>');}
 $fail=static function(string $error,?string $description=null)use($redirectUri,$state):never{$query=['error'=>$error];if($description)$query['error_description']=$description;if($state!==null)$query['state']=$state;Web::redirect($redirectUri.(str_contains($redirectUri,'?')?'&':'?').http_build_query($query));};
 if((string)($params['response_type']??'')!=='code')$fail('unsupported_response_type');
 $user=$auth->currentUser();
 if(!$user)Web::redirect('/login?return='.rawurlencode($_SERVER['REQUEST_URI']??'/dashboard'));
 $requiredActions->refreshAutomaticCompletions((int)$user['id']);$pending=$requiredActions->pending((int)$user['id']);if($pending!==[]){$_SESSION['required_action_return']=$_SERVER['REQUEST_URI']??'/dashboard';Web::redirect('/account/required-actions');}
 $prompt=(string)($params['prompt']??'');$maxAge=isset($params['max_age'])?(int)$params['max_age']:null;$authTime=(int)($_SESSION['auth_time']??0);
 if($prompt==='login'||($maxAge!==null&&$maxAge>=0&&($authTime===0||time()-$authTime>$maxAge))){Web::redirect('/login?reauth=1&return='.rawurlencode($_SERVER['REQUEST_URI']??'/dashboard'));}
 $context=$auth->authenticationContext();
 if(!$access->hasAccess((int)$user['id'],$app,$context))$fail('access_denied','User is not allowed to access this application');
 $scopes=$oidc->allowedScopes((int)$app['id'],(string)($params['scope']??'openid'));
 if($consents->required($app)&&!$consents->hasConsent((int)$user['id'],(int)$app['id'],$scopes)){
   $consentToken=Security::randomToken(24);$_SESSION['pending_consents'][$consentToken]=['created_at'=>time(),'authorize_uri'=>$_SERVER['REQUEST_URI']??'/oauth/authorize','application_id'=>(int)$app['id'],'scopes'=>$scopes,'redirect_uri'=>$redirectUri,'state'=>$state];Web::redirect('/oauth/consent?token='.rawurlencode($consentToken));
 }
 $code=$oidc->createAuthorizationCode($app,(int)$user['id'],$redirectUri,$scopes,isset($params['code_challenge'])?(string)$params['code_challenge']:null,isset($params['code_challenge_method'])?(string)$params['code_challenge_method']:null,isset($params['nonce'])?(string)$params['nonce']:null);
 if($parId!==null){$updated=$db->execute('UPDATE oauth_par_requests SET used_at=NOW() WHERE id=? AND used_at IS NULL',[$parId]);if($updated!==1)throw new RuntimeException('invalid_request_uri');}
 $consents->touch((int)$user['id'],(int)$app['id']);
 $query=['code'=>$code];if($state!==null)$query['state']=$state;Web::redirect($redirectUri.(str_contains($redirectUri,'?')?'&':'?').http_build_query($query));
}catch(RuntimeException $e){
 $error=$e->getMessage();
 if(isset($fail)&&is_callable($fail)&&isset($redirectUri)&&$redirectUri!=='')$fail(in_array($error,['access_denied','interaction_required','invalid_scope','invalid_request'],true)?$error:'invalid_request');
 http_response_code(400);Web::page('Błąd OAuth','<section class="card narrow"><h1>Błąd żądania autoryzacyjnego</h1><div class="code">'.Web::e($error).'</div></section>');
}
