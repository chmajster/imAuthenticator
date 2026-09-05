<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class OAuthAdvancedService
{
    public function __construct(
        private Database $db,
        private ApplicationAccessService $access,
        private ConditionalAccessService $conditional,
        private AuditLog $audit,
        private JwtService $jwt,
        private array $config
    ) {}

    public function deviceAuthorization(array $input, ?string $authorizationHeader): array
    {
        $app = $this->authenticateClient($input, $authorizationHeader, true);
        if ($app['integration_type'] === 'client_credentials') throw new RuntimeException('unauthorized_client');
        $scopes = $this->allowedScopes((int)$app['id'], (string)($input['scope'] ?? 'openid'));
        $deviceCode = Security::randomToken(48);
        $userCode = strtoupper(substr(bin2hex(random_bytes(4)), 0, 4) . '-' . substr(bin2hex(random_bytes(4)), 0, 4));
        $expiresIn = 900;
        $interval = 5;
        $expiresAt = date('Y-m-d H:i:s', time() + $expiresIn);
        $this->db->execute(
            'INSERT INTO oauth_device_codes(application_id,device_code_hash,user_code_hash,user_code_display,scopes,interval_seconds,expires_at) VALUES(?,?,?,?,?,?,?)',
            [(int)$app['id'], Security::tokenHash($deviceCode), Security::tokenHash($userCode), $userCode, implode(' ', $scopes), $interval, $expiresAt]
        );
        $issuer = $this->jwt->issuer();
        $this->audit->write('oauth.device.started', 'success', null, null, (int)$app['id']);
        return [
            'device_code' => $deviceCode,
            'user_code' => $userCode,
            'verification_uri' => $issuer . '/activate',
            'verification_uri_complete' => $issuer . '/activate?user_code=' . rawurlencode($userCode),
            'expires_in' => $expiresIn,
            'interval' => $interval,
        ];
    }

    public function authorizeDevice(string $userCode, int $userId, array $context): array
    {
        $normalized = strtoupper(trim($userCode));
        return $this->db->transaction(function () use ($normalized, $userId, $context): array {
            $row = $this->db->one(
                "SELECT dc.id AS device_code_id,dc.application_id,dc.status,dc.expires_at,a.name AS application_name,a.enabled,a.deleted_at
                 FROM oauth_device_codes dc JOIN applications a ON a.id=dc.application_id
                 WHERE dc.user_code_hash=? FOR UPDATE",
                [Security::tokenHash($normalized)]
            );
            if (!$row || $row['status'] !== 'pending' || strtotime((string)$row['expires_at']) <= time() || !(bool)$row['enabled'] || $row['deleted_at'] !== null) throw new RuntimeException('invalid_user_code');
            if (!$this->access->hasAccess($userId, (int)$row['application_id'], $context)) throw new RuntimeException('access_denied');
            $decision = $this->conditional->evaluate($userId, (int)$row['application_id'], $context);
            if (!$decision['allowed']) throw new RuntimeException(($decision['action'] ?? 'deny') === 'deny' ? 'access_denied' : 'interaction_required');
            $authLevel = max(1, (int)($context['auth_level'] ?? 1));
            $authTime = (int)($context['auth_time'] ?? time());
            $this->db->execute("UPDATE oauth_device_codes SET status='authorized',user_id=?,auth_level=?,auth_time=?,authorized_at=NOW() WHERE id=?", [$userId,$authLevel,date('Y-m-d H:i:s',$authTime),(int)$row['device_code_id']]);
            $this->audit->write('oauth.device.authorized', 'success', $userId, $userId, (int)$row['application_id'], null, ['auth_level'=>$authLevel]);
            return ['application_id'=>(int)$row['application_id'],'application_name'=>(string)$row['application_name']];
        });
    }

    public function denyDevice(string $userCode, int $userId): void
    {
        $normalized = strtoupper(trim($userCode));
        $row = $this->db->one('SELECT id,application_id FROM oauth_device_codes WHERE user_code_hash=? AND status=\'pending\' AND expires_at>NOW()', [Security::tokenHash($normalized)]);
        if (!$row) throw new RuntimeException('invalid_user_code');
        $this->db->execute("UPDATE oauth_device_codes SET status='denied',user_id=?,authorized_at=NOW() WHERE id=?", [$userId,(int)$row['id']]);
        $this->audit->write('oauth.device.denied', 'denied', $userId, $userId, (int)$row['application_id']);
    }

    public function deviceToken(array $input, ?string $authorizationHeader): array
    {
        $app = $this->authenticateClient($input, $authorizationHeader, true);
        $deviceCode = (string)($input['device_code'] ?? '');
        if ($deviceCode === '') throw new RuntimeException('invalid_grant');

        $result = $this->db->transaction(function () use ($app, $deviceCode): array {
            $row = $this->db->one('SELECT * FROM oauth_device_codes WHERE device_code_hash=? FOR UPDATE', [Security::tokenHash($deviceCode)]);
            if (!$row || (int)$row['application_id'] !== (int)$app['id']) throw new RuntimeException('invalid_grant');
            if (strtotime((string)$row['expires_at']) <= time()) throw new RuntimeException('expired_token');
            if ($row['status'] === 'denied') throw new RuntimeException('access_denied');
            if ($row['status'] === 'consumed') throw new RuntimeException('invalid_grant');

            if ($row['last_polled_at']) {
                $elapsed = time() - strtotime((string)$row['last_polled_at']);
                if ($elapsed < (int)$row['interval_seconds']) {
                    $this->db->execute('UPDATE oauth_device_codes SET interval_seconds=LEAST(interval_seconds+5,60),poll_count=poll_count+1,last_polled_at=NOW() WHERE id=?', [(int)$row['id']]);
                    return ['__error'=>'slow_down'];
                }
            }
            $this->db->execute('UPDATE oauth_device_codes SET poll_count=poll_count+1,last_polled_at=NOW() WHERE id=?', [(int)$row['id']]);
            if ($row['status'] === 'pending') return ['__error'=>'authorization_pending'];
            if ($row['status'] !== 'authorized' || !$row['user_id']) throw new RuntimeException('invalid_grant');

            $userId = (int)$row['user_id'];
            if (!$this->access->hasAccess($userId, $app)) throw new RuntimeException('access_denied');
            $tokens = $this->mintUserTokens($app, $userId, (string)$row['scopes'], (int)($row['auth_level'] ?: 1), $row['auth_time'] ? strtotime((string)$row['auth_time']) : time());
            $this->db->execute("UPDATE oauth_device_codes SET status='consumed',consumed_at=NOW() WHERE id=?", [(int)$row['id']]);
            $this->audit->write('oauth.device.token_issued', 'success', $userId, $userId, (int)$app['id']);
            return $tokens;
        });
        if (isset($result['__error'])) throw new RuntimeException((string)$result['__error']);
        return $result;
    }

    public function pushAuthorizationRequest(array $input, ?string $authorizationHeader): array
    {
        $app = $this->authenticateClient($input, $authorizationHeader, true);
        $redirectUri = trim((string)($input['redirect_uri'] ?? ''));
        if (!$this->redirectAllowed((int)$app['id'], $redirectUri)) throw new RuntimeException('invalid_request');
        if ((string)($input['response_type'] ?? 'code') !== 'code') throw new RuntimeException('unsupported_response_type');
        $scopes = $this->allowedScopes((int)$app['id'], (string)($input['scope'] ?? 'openid'));
        if ($app['client_type'] === 'public' && ((string)($input['code_challenge_method'] ?? '') !== 'S256' || empty($input['code_challenge']))) throw new RuntimeException('invalid_request');

        $params = [
            'client_id'=>(string)$app['client_id'],
            'redirect_uri'=>$redirectUri,
            'response_type'=>'code',
            'scope'=>implode(' ', $scopes),
            'state'=>isset($input['state']) ? (string)$input['state'] : null,
            'nonce'=>isset($input['nonce']) ? (string)$input['nonce'] : null,
            'code_challenge'=>isset($input['code_challenge']) ? (string)$input['code_challenge'] : null,
            'code_challenge_method'=>isset($input['code_challenge_method']) ? (string)$input['code_challenge_method'] : null,
            'prompt'=>isset($input['prompt']) ? (string)$input['prompt'] : null,
            'max_age'=>isset($input['max_age']) ? max(0,(int)$input['max_age']) : null,
        ];
        $requestUri = 'urn:ietf:params:oauth:request_uri:' . Security::randomToken(32);
        $this->db->execute('INSERT INTO oauth_par_requests(application_id,request_uri_hash,params_json,expires_at) VALUES(?,?,?,DATE_ADD(NOW(),INTERVAL 90 SECOND))', [(int)$app['id'],Security::tokenHash($requestUri),json_encode($params, JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)]);
        $this->audit->write('oauth.par.created', 'success', null, null, (int)$app['id']);
        return ['request_uri'=>$requestUri,'expires_in'=>90];
    }

    public function consumePar(string $requestUri): array
    {
        return $this->db->transaction(function () use ($requestUri): array {
            $row = $this->db->one('SELECT * FROM oauth_par_requests WHERE request_uri_hash=? FOR UPDATE', [Security::tokenHash($requestUri)]);
            if (!$row || $row['used_at'] !== null || strtotime((string)$row['expires_at']) <= time()) throw new RuntimeException('invalid_request_uri');
            $params = json_decode((string)$row['params_json'], true);
            if (!is_array($params)) throw new RuntimeException('invalid_request_uri');
            $this->db->execute('UPDATE oauth_par_requests SET used_at=NOW() WHERE id=?', [(int)$row['id']]);
            return $params;
        });
    }

    public function createRegistrationToken(string $name, int $actorUserId, ?array $allowedDomains = null, ?string $validUntil = null): string
    {
        $name = trim($name);
        if ($name === '') throw new RuntimeException('name_required');
        if ($validUntil !== null && strtotime($validUntil) === false) throw new RuntimeException('invalid_expiration');
        $token = 'imat_' . Security::randomToken(48);
        $domains = $allowedDomains === null ? null : array_values(array_unique(array_filter(array_map(static fn($v)=>strtolower(trim((string)$v)), $allowedDomains))));
        $this->db->execute('INSERT INTO dynamic_registration_tokens(name,token_hash,allowed_domains_json,valid_until,created_by) VALUES(?,?,?,?,?)', [$name,Security::tokenHash($token),$domains===null?null:json_encode($domains,JSON_THROW_ON_ERROR),$validUntil,$actorUserId]);
        $this->audit->write('oauth.dcr.token_created','success',$actorUserId,null,null,null,['name'=>$name,'valid_until'=>$validUntil]);
        return $token;
    }

    public function dynamicRegister(array $payload, string $bearer): array
    {
        $token = $this->db->one('SELECT * FROM dynamic_registration_tokens WHERE token_hash=? AND revoked_at IS NULL AND (valid_until IS NULL OR valid_until>NOW())', [Security::tokenHash($bearer)]);
        if (!$token) throw new RuntimeException('invalid_token');
        $clientName = trim((string)($payload['client_name'] ?? ''));
        $redirectUris = $payload['redirect_uris'] ?? [];
        if ($clientName === '' || !is_array($redirectUris) || $redirectUris === []) throw new RuntimeException('invalid_client_metadata');
        $redirectUris = array_values(array_unique(array_map('trim', array_map('strval', $redirectUris))));
        foreach ($redirectUris as $uri) if (!Security::validRedirectUri($uri) || !$this->domainAllowed($uri, $token['allowed_domains_json'])) throw new RuntimeException('invalid_redirect_uri');

        $authMethod = (string)($payload['token_endpoint_auth_method'] ?? 'client_secret_basic');
        if (!in_array($authMethod,['none','client_secret_basic','client_secret_post'],true)) throw new RuntimeException('invalid_client_metadata');
        $clientType = $authMethod === 'none' ? 'public' : 'confidential';
        $integration = $clientType === 'public' ? 'public_pkce' : 'generic_oidc';
        $clientId = Security::clientId();
        $secret = $clientType === 'confidential' ? Security::clientSecret() : null;
        $first = parse_url($redirectUris[0]);
        $url = is_array($first) && !empty($first['scheme']) && !empty($first['host']) ? $first['scheme'].'://'.$first['host'] : $redirectUris[0];
        $slugBase = Security::slug($clientName);
        $slug = $slugBase;
        while ($this->db->one('SELECT 1 FROM applications WHERE slug=?',[$slug])) $slug = $slugBase.'-'.strtolower(Security::randomToken(4));
        $requestedScopes = $payload['scope'] ?? 'openid profile email';
        $scopes = array_values(array_unique(array_filter(preg_split('/\s+/', is_array($requestedScopes)?implode(' ',array_map('strval',$requestedScopes)):(string)$requestedScopes) ?: [])));
        $permittedScopes = ['openid','profile','email','roles'];
        if (array_diff($scopes,$permittedScopes)!==[]) throw new RuntimeException('invalid_client_metadata');
        if (!in_array('openid',$scopes,true)) $scopes[]='openid';

        $appId = $this->db->transaction(function () use ($clientName,$url,$integration,$clientId,$secret,$clientType,$slug,$redirectUris,$scopes): int {
            $this->db->execute('INSERT INTO applications(uuid,name,slug,url,app_type,integration_type,client_id,client_secret_hash,client_type,access_policy,enabled) VALUES(?,?,?,?,\'oidc\',?,?,?,?,\'none\',1)', [Security::uuidV4(),$clientName,$slug,$url,$integration,$clientId,$secret?Security::secretHash($secret):null,$clientType]);
            $id=$this->db->lastInsertId();
            foreach($redirectUris as $uri)$this->db->execute('INSERT INTO application_redirect_uris(application_id,redirect_uri) VALUES(?,?)',[$id,$uri]);
            foreach($scopes as $scope)$this->db->execute('INSERT INTO application_scopes(application_id,scope) VALUES(?,?)',[$id,$scope]);
            return $id;
        });
        $this->db->execute('UPDATE dynamic_registration_tokens SET last_used_at=NOW() WHERE id=?',[(int)$token['id']]);
        $actor = $token['created_by'] !== null ? (int)$token['created_by'] : null;
        $this->audit->write('oauth.dcr.client_created','success',$actor,null,$appId,null,['client_name'=>$clientName]);
        $result=[
            'client_id'=>$clientId,
            'client_id_issued_at'=>time(),
            'redirect_uris'=>$redirectUris,
            'token_endpoint_auth_method'=>$authMethod,
            'grant_types'=>['authorization_code','refresh_token'],
            'response_types'=>['code'],
        ];
        if($secret!==null){$result['client_secret']=$secret;$result['client_secret_expires_at']=0;}
        return $result;
    }

    private function authenticateClient(array $input, ?string $authorizationHeader, bool $allowPublic): array
    {
        $clientId=(string)($input['client_id']??'');$secret=(string)($input['client_secret']??'');
        if($authorizationHeader&&str_starts_with($authorizationHeader,'Basic ')){
            $decoded=base64_decode(substr($authorizationHeader,6),true);
            if(is_string($decoded)&&str_contains($decoded,':')){[$clientId,$secret]=explode(':',$decoded,2);$clientId=rawurldecode($clientId);$secret=rawurldecode($secret);}
        }
        $app=$this->db->one('SELECT * FROM applications WHERE client_id=? AND enabled=1 AND deleted_at IS NULL',[$clientId]);
        if(!$app)throw new RuntimeException('invalid_client');
        if($app['client_type']==='public'){
            if(!$allowPublic) throw new RuntimeException('invalid_client');
            return $app;
        }
        if(!$this->verifyClientSecret($app,$secret))throw new RuntimeException('invalid_client');
        return $app;
    }

    private function verifyClientSecret(array $app,string $secret): bool
    {
        if($secret==='')return false;
        if(Security::verifySecret($secret,$app['client_secret_hash']))return true;
        foreach($this->db->all('SELECT secret_hash FROM client_secrets WHERE application_id=? AND revoked_at IS NULL AND valid_from<=NOW() AND (valid_until IS NULL OR valid_until>NOW())',[(int)$app['id']]) as $row)if(Security::verifySecret($secret,(string)$row['secret_hash']))return true;
        return false;
    }

    private function allowedScopes(int $applicationId,string $requested): array
    {
        $allowed=array_column($this->db->all('SELECT scope FROM application_scopes WHERE application_id=?',[$applicationId]),'scope');
        $requestedScopes=array_values(array_unique(array_filter(preg_split('/\s+/',trim($requested))?:[])));
        if(array_diff($requestedScopes,$allowed)!==[])throw new RuntimeException('invalid_scope');
        return array_values(array_intersect($requestedScopes,$allowed));
    }

    private function redirectAllowed(int $applicationId,string $uri): bool
    {
        return Security::validRedirectUri($uri)&&$this->db->one('SELECT 1 FROM application_redirect_uris WHERE application_id=? AND redirect_uri=?',[$applicationId,$uri])!==null;
    }

    private function domainAllowed(string $uri,?string $json): bool
    {
        if($json===null||$json==='')return true;
        $allowed=json_decode($json,true);if(!is_array($allowed)||$allowed===[])return true;
        $host=strtolower((string)parse_url($uri,PHP_URL_HOST));
        foreach($allowed as $domain){$domain=strtolower(trim((string)$domain));if($domain!==''&&($host===$domain||str_ends_with($host,'.'.$domain)))return true;}
        return false;
    }

    private function mintUserTokens(array $app,int $userId,string $scopes,int $authLevel,int $authTime): array
    {
        $accessToken=Security::randomToken(48);$refreshToken=Security::randomToken(64);$sid=Security::randomToken(32);
        $this->db->execute('INSERT INTO oauth_access_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,?,DATE_ADD(NOW(),INTERVAL 1 HOUR))',[Security::tokenHash($accessToken),(int)$app['id'],$userId,$scopes]);
        $this->db->execute('INSERT INTO oauth_refresh_tokens(token_hash,application_id,user_id,scopes,auth_level,auth_time,expires_at) VALUES(?,?,?,?,?,?,DATE_ADD(NOW(),INTERVAL 30 DAY))',[Security::tokenHash($refreshToken),(int)$app['id'],$userId,$scopes,$authLevel,date('Y-m-d H:i:s',$authTime)]);
        $this->db->execute('INSERT INTO oidc_sessions(sid,application_id,user_id,auth_level) VALUES(?,?,?,?)',[$sid,(int)$app['id'],$userId,$authLevel]);
        $user=$this->db->one('SELECT uuid,name,email,username FROM users WHERE id=?',[$userId]);if(!$user)throw new RuntimeException('invalid_grant');
        $claims=['iss'=>$this->jwt->issuer(),'sub'=>$user['uuid'],'aud'=>$app['client_id'],'iat'=>time(),'exp'=>time()+3600,'sid'=>$sid,'auth_time'=>$authTime,'acr'=>'urn:imauthenticator:loa:'.$authLevel,'name'=>$user['name'],'email'=>$user['email'],'roles'=>$this->access->rolesForUser($userId,(int)$app['id'])];
        $this->db->execute('UPDATE applications SET last_used_at=NOW() WHERE id=?',[(int)$app['id']]);
        return ['token_type'=>'Bearer','expires_in'=>3600,'access_token'=>$accessToken,'refresh_token'=>$refreshToken,'id_token'=>$this->jwt->sign($claims),'scope'=>$scopes];
    }
}
