<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class OidcService
{
    public function __construct(
        private Database $db,
        private ApplicationAccessService $access,
        private ConditionalAccessService $conditional,
        private AuditLog $audit,
        private array $config
    ) {}

    public function client(string $clientId): ?array
    {
        return $this->db->one('SELECT * FROM applications WHERE client_id=? AND enabled=1 AND deleted_at IS NULL', [$clientId]);
    }

    public function redirectAllowed(int $applicationId, string $redirectUri): bool
    {
        return Security::validRedirectUri($redirectUri) && $this->db->one('SELECT 1 FROM application_redirect_uris WHERE application_id=? AND redirect_uri=?', [$applicationId,$redirectUri]) !== null;
    }

    public function allowedScopes(int $applicationId, string $requested): array
    {
        $allowed = array_column($this->db->all('SELECT scope FROM application_scopes WHERE application_id=?', [$applicationId]), 'scope');
        $requestedScopes = array_values(array_unique(array_filter(preg_split('/\s+/', trim($requested)) ?: [])));
        $unknown = array_diff($requestedScopes, $allowed);
        if ($unknown !== []) throw new RuntimeException('invalid_scope');
        return array_values(array_intersect($requestedScopes, $allowed));
    }

    public function createAuthorizationCode(array $app, int $userId, string $redirectUri, array $scopes, ?string $challenge, ?string $method, ?string $nonce): string
    {
        $context = $this->authenticationContext();
        if (!$this->access->hasAccess($userId, $app, $context)) {
            $this->audit->write('oidc.authorization.denied', 'denied', $userId, $userId, (int)$app['id'], 'user has no application entitlement');
            throw new RuntimeException('access_denied');
        }
        $decision = $this->conditional->evaluate($userId, $app, $context);
        if (!$decision['allowed']) {
            $this->audit->write('oidc.conditional_access.denied', 'denied', $userId, $userId, (int)$app['id'], implode(',', $decision['reasons'] ?? []), ['action'=>$decision['action'] ?? 'deny']);
            throw new RuntimeException(($decision['action'] ?? 'deny') === 'deny' ? 'access_denied' : 'interaction_required');
        }
        if ($app['client_type'] === 'public' && (!$challenge || $method !== 'S256')) throw new RuntimeException('invalid_request');

        $code = Security::randomToken(48);
        $authLevel = max(1, (int)($context['auth_level'] ?? 1));
        $authTime = (int)($context['auth_time'] ?? time());
        $this->db->execute(
            'INSERT INTO oauth_authorization_codes(code_hash,application_id,user_id,redirect_uri,scopes,code_challenge,code_challenge_method,nonce,auth_level,auth_time,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,DATE_ADD(NOW(),INTERVAL 5 MINUTE))',
            [Security::tokenHash($code),(int)$app['id'],$userId,$redirectUri,implode(' ', $scopes),$challenge,$method,$nonce,$authLevel,date('Y-m-d H:i:s',$authTime)]
        );
        $this->audit->write('oidc.authorization_code.issued', 'success', $userId, $userId, (int)$app['id'], null, ['auth_level'=>$authLevel]);
        return $code;
    }

    public function exchangeAuthorizationCode(array $input, ?string $authorizationHeader): array
    {
        [$app] = $this->authenticateClient($input, $authorizationHeader);
        $code = (string)($input['code'] ?? '');
        $redirectUri = (string)($input['redirect_uri'] ?? '');
        if ($code === '' || !$this->redirectAllowed((int)$app['id'], $redirectUri)) throw new RuntimeException('invalid_grant');

        return $this->db->transaction(function () use ($app,$input,$code,$redirectUri): array {
            $row = $this->db->one('SELECT * FROM oauth_authorization_codes WHERE code_hash=? FOR UPDATE', [Security::tokenHash($code)]);
            if (!$row || (int)$row['application_id'] !== (int)$app['id'] || $row['redirect_uri'] !== $redirectUri || $row['used_at'] !== null || strtotime((string)$row['expires_at']) < time()) throw new RuntimeException('invalid_grant');
            if (!$this->access->hasAccess((int)$row['user_id'], $app)) {
                $this->audit->write('oidc.token.denied', 'denied', (int)$row['user_id'], (int)$row['user_id'], (int)$app['id'], 'application access revoked before token exchange');
                throw new RuntimeException('access_denied');
            }
            if ($app['client_type'] === 'public') {
                $verifier = (string)($input['code_verifier'] ?? '');
                if (!$row['code_challenge'] || !Security::verifyPkce($verifier, (string)$row['code_challenge'], (string)$row['code_challenge_method'])) throw new RuntimeException('invalid_grant');
            }
            $this->db->execute('UPDATE oauth_authorization_codes SET used_at=NOW() WHERE id=?', [(int)$row['id']]);
            return $this->mintUserTokens($app,(int)$row['user_id'],(string)$row['scopes'],$row['nonce'] ?: null,(int)$row['auth_level'],$row['auth_time'] ? strtotime((string)$row['auth_time']) : time());
        });
    }

    public function refresh(array $input, ?string $authorizationHeader): array
    {
        [$app] = $this->authenticateClient($input, $authorizationHeader);
        $refresh = (string)($input['refresh_token'] ?? '');
        if ($refresh === '') throw new RuntimeException('invalid_grant');
        return $this->db->transaction(function () use ($app,$refresh): array {
            $row = $this->db->one('SELECT * FROM oauth_refresh_tokens WHERE token_hash=? FOR UPDATE', [Security::tokenHash($refresh)]);
            if (!$row || (int)$row['application_id'] !== (int)$app['id'] || $row['revoked_at'] !== null || strtotime((string)$row['expires_at']) < time()) throw new RuntimeException('invalid_grant');
            $userId = (int)$row['user_id'];
            if (!$this->access->hasAccess($userId, $app)) {
                $this->db->execute('UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE id=?', [(int)$row['id']]);
                throw new RuntimeException('access_denied');
            }
            $context = ['auth_level'=>(int)$row['auth_level'],'auth_time'=>$row['auth_time'] ? strtotime((string)$row['auth_time']) : 0,'ip'=>Security::currentIp()];
            $decision = $this->conditional->evaluate($userId, $app, $context);
            if (!$decision['allowed']) throw new RuntimeException(($decision['action'] ?? 'deny') === 'deny' ? 'access_denied' : 'interaction_required');
            $new = $this->mintUserTokens($app,$userId,(string)$row['scopes'],null,(int)$row['auth_level'],$context['auth_time']);
            $this->db->execute('UPDATE oauth_refresh_tokens SET revoked_at=NOW(),replaced_by_hash=? WHERE id=?', [Security::tokenHash($new['refresh_token']),(int)$row['id']]);
            return $new;
        });
    }

    public function clientCredentials(array $input, ?string $authorizationHeader): array
    {
        [$app] = $this->authenticateClient($input, $authorizationHeader);
        if ($app['integration_type'] !== 'client_credentials' || $app['client_type'] !== 'confidential') throw new RuntimeException('unauthorized_client');
        $scopes = $this->allowedScopes((int)$app['id'], (string)($input['scope'] ?? 'roles'));
        $token = Security::randomToken(48);
        $this->db->execute('INSERT INTO oauth_access_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,NULL,?,DATE_ADD(NOW(),INTERVAL 1 HOUR))', [Security::tokenHash($token),(int)$app['id'],implode(' ', $scopes)]);
        $this->db->execute('UPDATE applications SET last_used_at=NOW() WHERE id=?', [(int)$app['id']]);
        $this->audit->write('oauth.client_credentials.success', 'success', null, null, (int)$app['id']);
        return ['token_type'=>'Bearer','expires_in'=>3600,'access_token'=>$token,'scope'=>implode(' ', $scopes)];
    }

    public function userInfo(string $bearer): array
    {
        $row = $this->db->one('SELECT t.*,a.enabled AS app_enabled,a.deleted_at,u.uuid,u.name,u.username,u.email,u.enabled AS user_enabled,u.lifecycle_status FROM oauth_access_tokens t JOIN applications a ON a.id=t.application_id JOIN users u ON u.id=t.user_id WHERE t.token_hash=?', [Security::tokenHash($bearer)]);
        if (!$row || $row['revoked_at'] !== null || strtotime((string)$row['expires_at']) < time() || !(bool)$row['app_enabled'] || $row['deleted_at'] !== null || !(bool)$row['user_enabled'] || $row['lifecycle_status'] !== 'active') throw new RuntimeException('invalid_token');
        if (!$this->access->hasAccess((int)$row['user_id'], (int)$row['application_id'])) {
            $this->db->execute('UPDATE oauth_access_tokens SET revoked_at=NOW() WHERE id=?', [(int)$row['id']]);
            throw new RuntimeException('invalid_token');
        }
        return array_merge(['sub'=>$row['uuid']], $this->mappedClaims((int)$row['application_id'],(int)$row['user_id'],(string)$row['scopes'],$row));
    }

    private function authenticateClient(array $input, ?string $authorizationHeader): array
    {
        $clientId = (string)($input['client_id'] ?? '');
        $secret = (string)($input['client_secret'] ?? '');
        if ($authorizationHeader && str_starts_with($authorizationHeader, 'Basic ')) {
            $decoded = base64_decode(substr($authorizationHeader, 6), true);
            if (is_string($decoded) && str_contains($decoded, ':')) {
                [$clientId,$secret] = explode(':',$decoded,2);
                $clientId = rawurldecode($clientId);
                $secret = rawurldecode($secret);
            }
        }
        $app = $this->client($clientId);
        if (!$app) throw new RuntimeException('invalid_client');
        if ($app['client_type'] === 'confidential' && !$this->verifyClientSecret($app, $secret)) {
            $this->audit->write('oidc.client_auth.denied', 'denied', null, null, (int)$app['id'], 'invalid or expired client secret');
            throw new RuntimeException('invalid_client');
        }
        return [$app,$clientId];
    }

    private function verifyClientSecret(array $app, string $secret): bool
    {
        if ($secret === '') return false;
        if (Security::verifySecret($secret, $app['client_secret_hash'])) return true;
        $rows = $this->db->all('SELECT secret_hash FROM client_secrets WHERE application_id=? AND revoked_at IS NULL AND valid_from<=NOW() AND (valid_until IS NULL OR valid_until>NOW())', [(int)$app['id']]);
        foreach ($rows as $row) if (Security::verifySecret($secret, (string)$row['secret_hash'])) return true;
        return false;
    }

    private function mintUserTokens(array $app, int $userId, string $scopes, ?string $nonce, int $authLevel, int $authTime): array
    {
        if (!$this->access->hasAccess($userId, $app)) throw new RuntimeException('access_denied');
        $accessToken = Security::randomToken(48);
        $refreshToken = Security::randomToken(64);
        $sid = Security::randomToken(32);
        $this->db->execute('INSERT INTO oauth_access_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,?,DATE_ADD(NOW(),INTERVAL 1 HOUR))', [Security::tokenHash($accessToken),(int)$app['id'],$userId,$scopes]);
        $this->db->execute('INSERT INTO oauth_refresh_tokens(token_hash,application_id,user_id,scopes,auth_level,auth_time,expires_at) VALUES(?,?,?,?,?,?,DATE_ADD(NOW(),INTERVAL 30 DAY))', [Security::tokenHash($refreshToken),(int)$app['id'],$userId,$scopes,$authLevel,date('Y-m-d H:i:s',$authTime)]);
        $this->db->execute('INSERT INTO oidc_sessions(sid,application_id,user_id,auth_level) VALUES(?,?,?,?)', [$sid,(int)$app['id'],$userId,$authLevel]);
        $this->db->execute('UPDATE applications SET last_used_at=NOW() WHERE id=?', [(int)$app['id']]);
        $user = $this->db->one('SELECT uuid,name,username,email FROM users WHERE id=?', [$userId]);
        if (!$user) throw new RuntimeException('invalid_grant');
        $claims = array_merge([
            'iss'=>rtrim((string)$this->config['issuer'],'/'),'sub'=>$user['uuid'],'aud'=>$app['client_id'],'iat'=>time(),'exp'=>time()+3600,'sid'=>$sid,'auth_time'=>$authTime,'acr'=>'urn:imauthenticator:loa:'.$authLevel,
        ], $this->mappedClaims((int)$app['id'],$userId,$scopes,$user));
        if ($nonce !== null) $claims['nonce'] = $nonce;
        $this->audit->write('oidc.sso.success', 'success', $userId, $userId, (int)$app['id'], null, ['auth_level'=>$authLevel]);
        return ['token_type'=>'Bearer','expires_in'=>3600,'access_token'=>$accessToken,'refresh_token'=>$refreshToken,'id_token'=>$this->signJwt($claims),'scope'=>$scopes];
    }

    private function mappedClaims(int $applicationId, int $userId, string $scopes, array $user): array
    {
        $rows = $this->db->all('SELECT * FROM claims_mappings WHERE application_id=? ORDER BY id', [$applicationId]);
        $roles = $this->access->rolesForUser($userId, $applicationId);
        if ($rows === []) return ['name'=>$user['name'] ?? null,'email'=>$user['email'] ?? null,'roles'=>$roles];
        $granted = array_fill_keys(array_filter(preg_split('/\s+/', trim($scopes)) ?: []), true);
        $claims = [];
        foreach ($rows as $row) {
            if ($row['required_scope'] && !isset($granted[$row['required_scope']])) continue;
            $value = null;
            switch ($row['source_type']) {
                case 'standard':
                    $key = (string)$row['source_key'];
                    $value = $key === 'roles' ? $roles : ($user[$key] ?? null);
                    break;
                case 'attribute':
                    $attr = $this->db->one('SELECT attribute_value FROM user_attributes WHERE user_id=? AND attribute_key=?', [$userId,(string)$row['source_key']]);
                    $value = $attr['attribute_value'] ?? null;
                    break;
                case 'role': $value = $roles; break;
                case 'static': $value = $row['static_value']; break;
            }
            if ($value !== null) $claims[(string)$row['claim_name']] = $value;
        }
        return $claims;
    }

    private function authenticationContext(): array
    {
        return ['auth_level'=>(int)($_SESSION['auth_level'] ?? 1),'auth_time'=>(int)($_SESSION['auth_time'] ?? 0),'device_id'=>(int)($_SESSION['device_id'] ?? 0),'risk_score'=>(int)($_SESSION['risk_score'] ?? 0),'country_code'=>$_SESSION['country_code'] ?? null,'ip'=>Security::currentIp()];
    }

    private function signJwt(array $claims): string
    {
        $privateKey = @file_get_contents((string)($this->config['keys']['private'] ?? ''));
        if (!$privateKey) throw new RuntimeException('server_error');
        $header = ['alg'=>'RS256','typ'=>'JWT','kid'=>(string)($this->config['keys']['kid'] ?? 'default')];
        $b64 = static fn(array $v): string => rtrim(strtr(base64_encode(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $data = $b64($header).'.'.$b64($claims);
        if (!openssl_sign($data,$signature,$privateKey,OPENSSL_ALGO_SHA256)) throw new RuntimeException('server_error');
        return $data.'.'.rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }
}
