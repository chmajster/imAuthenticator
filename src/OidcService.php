<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class OidcService
{
    public function __construct(
        private Database $db,
        private ApplicationAccessService $access,
        private AuditLog $audit,
        private array $config
    ) {}

    public function client(string $clientId): ?array
    {
        return $this->db->one('SELECT * FROM applications WHERE client_id=? AND enabled=1 AND deleted_at IS NULL', [$clientId]);
    }

    public function redirectAllowed(int $applicationId, string $redirectUri): bool
    {
        if (!Security::validRedirectUri($redirectUri)) return false;
        return $this->db->one('SELECT 1 FROM application_redirect_uris WHERE application_id=? AND redirect_uri=?', [$applicationId, $redirectUri]) !== null;
    }

    public function allowedScopes(int $applicationId, string $requested): array
    {
        $allowed = array_column($this->db->all('SELECT scope FROM application_scopes WHERE application_id=?', [$applicationId]), 'scope');
        $requestedScopes = array_values(array_unique(array_filter(preg_split('/\s+/', trim($requested)) ?: [])));
        $result = array_values(array_intersect($requestedScopes, $allowed));
        if (in_array('openid', $requestedScopes, true) && !in_array('openid', $result, true)) {
            throw new RuntimeException('invalid_scope');
        }
        return $result;
    }

    public function createAuthorizationCode(array $app, int $userId, string $redirectUri, array $scopes, ?string $challenge, ?string $method, ?string $nonce): string
    {
        if (!$this->access->hasAccess($userId, $app)) {
            $this->audit->write('oidc.authorization.denied', 'denied', $userId, $userId, (int)$app['id'], 'user has no application access');
            throw new RuntimeException('access_denied');
        }

        if ($app['client_type'] === 'public' && (!$challenge || $method !== 'S256')) {
            throw new RuntimeException('invalid_request');
        }

        $code = Security::randomToken(48);
        $this->db->execute(
            'INSERT INTO oauth_authorization_codes(code_hash,application_id,user_id,redirect_uri,scopes,code_challenge,code_challenge_method,nonce,expires_at) VALUES(?,?,?,?,?,?,?,?,DATE_ADD(NOW(),INTERVAL 5 MINUTE))',
            [Security::tokenHash($code), (int)$app['id'], $userId, $redirectUri, implode(' ', $scopes), $challenge, $method, $nonce]
        );
        $this->audit->write('oidc.authorization_code.issued', 'success', $userId, $userId, (int)$app['id']);
        return $code;
    }

    public function exchangeAuthorizationCode(array $input, ?string $authorizationHeader): array
    {
        [$app, $clientId] = $this->authenticateClient($input, $authorizationHeader);
        $code = (string)($input['code'] ?? '');
        $redirectUri = (string)($input['redirect_uri'] ?? '');
        if ($code === '' || !$this->redirectAllowed((int)$app['id'], $redirectUri)) throw new RuntimeException('invalid_grant');

        return $this->db->transaction(function () use ($app, $clientId, $input, $code, $redirectUri): array {
            $row = $this->db->one('SELECT * FROM oauth_authorization_codes WHERE code_hash=? FOR UPDATE', [Security::tokenHash($code)]);
            if (!$row || (int)$row['application_id'] !== (int)$app['id'] || $row['redirect_uri'] !== $redirectUri || $row['used_at'] !== null || strtotime($row['expires_at']) < time()) {
                throw new RuntimeException('invalid_grant');
            }

            if (!$this->access->hasAccess((int)$row['user_id'], $app)) {
                $this->audit->write('oidc.token.denied', 'denied', (int)$row['user_id'], (int)$row['user_id'], (int)$app['id'], 'application access revoked before token exchange');
                throw new RuntimeException('access_denied');
            }

            if ($app['client_type'] === 'public') {
                $verifier = (string)($input['code_verifier'] ?? '');
                if (!$row['code_challenge'] || !Security::verifyPkce($verifier, (string)$row['code_challenge'], (string)$row['code_challenge_method'])) {
                    throw new RuntimeException('invalid_grant');
                }
            }

            $this->db->execute('UPDATE oauth_authorization_codes SET used_at=NOW() WHERE id=?', [(int)$row['id']]);
            return $this->mintUserTokens($app, (int)$row['user_id'], (string)$row['scopes'], $row['nonce'] ?: null);
        });
    }

    public function refresh(array $input, ?string $authorizationHeader): array
    {
        [$app] = $this->authenticateClient($input, $authorizationHeader);
        $refresh = (string)($input['refresh_token'] ?? '');
        if ($refresh === '') throw new RuntimeException('invalid_grant');

        return $this->db->transaction(function () use ($app, $refresh): array {
            $row = $this->db->one('SELECT * FROM oauth_refresh_tokens WHERE token_hash=? FOR UPDATE', [Security::tokenHash($refresh)]);
            if (!$row || (int)$row['application_id'] !== (int)$app['id'] || $row['revoked_at'] !== null || strtotime($row['expires_at']) < time()) {
                throw new RuntimeException('invalid_grant');
            }
            if (!$this->access->hasAccess((int)$row['user_id'], $app)) {
                $this->db->execute('UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE id=?', [(int)$row['id']]);
                $this->audit->write('oidc.refresh.denied', 'denied', (int)$row['user_id'], (int)$row['user_id'], (int)$app['id'], 'application access revoked');
                throw new RuntimeException('access_denied');
            }

            $new = $this->mintUserTokens($app, (int)$row['user_id'], (string)$row['scopes'], null);
            $this->db->execute('UPDATE oauth_refresh_tokens SET revoked_at=NOW(),replaced_by_hash=? WHERE id=?', [Security::tokenHash($new['refresh_token']), (int)$row['id']]);
            return $new;
        });
    }

    public function userInfo(string $bearer): array
    {
        $row = $this->db->one(
            'SELECT t.*,a.client_id,a.enabled AS app_enabled,a.deleted_at,u.uuid,u.name,u.email,u.enabled AS user_enabled FROM oauth_access_tokens t JOIN applications a ON a.id=t.application_id JOIN users u ON u.id=t.user_id WHERE t.token_hash=?',
            [Security::tokenHash($bearer)]
        );
        if (!$row || $row['revoked_at'] !== null || strtotime($row['expires_at']) < time() || !(bool)$row['app_enabled'] || $row['deleted_at'] !== null || !(bool)$row['user_enabled']) {
            throw new RuntimeException('invalid_token');
        }
        if (!$this->access->hasAccess((int)$row['user_id'], (int)$row['application_id'])) {
            $this->db->execute('UPDATE oauth_access_tokens SET revoked_at=NOW() WHERE id=?', [(int)$row['id']]);
            throw new RuntimeException('invalid_token');
        }

        return [
            'sub' => $row['uuid'],
            'name' => $row['name'],
            'email' => $row['email'],
            'email_verified' => true,
            'roles' => $this->access->rolesForUser((int)$row['user_id'], (int)$row['application_id']),
        ];
    }

    private function authenticateClient(array $input, ?string $authorizationHeader): array
    {
        $clientId = (string)($input['client_id'] ?? '');
        $secret = (string)($input['client_secret'] ?? '');
        if ($authorizationHeader && str_starts_with($authorizationHeader, 'Basic ')) {
            $decoded = base64_decode(substr($authorizationHeader, 6), true);
            if (is_string($decoded) && str_contains($decoded, ':')) {
                [$clientId, $secret] = explode(':', $decoded, 2);
                $clientId = rawurldecode($clientId);
                $secret = rawurldecode($secret);
            }
        }

        $app = $this->client($clientId);
        if (!$app) throw new RuntimeException('invalid_client');
        if ($app['client_type'] === 'confidential' && !Security::verifySecret($secret, $app['client_secret_hash'])) {
            $this->audit->write('oidc.client_auth.denied', 'denied', null, null, (int)$app['id'], 'invalid client secret');
            throw new RuntimeException('invalid_client');
        }
        return [$app, $clientId];
    }

    private function mintUserTokens(array $app, int $userId, string $scopes, ?string $nonce): array
    {
        if (!$this->access->hasAccess($userId, $app)) throw new RuntimeException('access_denied');

        $accessToken = Security::randomToken(48);
        $refreshToken = Security::randomToken(64);
        $this->db->execute('INSERT INTO oauth_access_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,?,DATE_ADD(NOW(),INTERVAL 1 HOUR))', [Security::tokenHash($accessToken),(int)$app['id'],$userId,$scopes]);
        $this->db->execute('INSERT INTO oauth_refresh_tokens(token_hash,application_id,user_id,scopes,expires_at) VALUES(?,?,?,?,DATE_ADD(NOW(),INTERVAL 30 DAY))', [Security::tokenHash($refreshToken),(int)$app['id'],$userId,$scopes]);
        $this->db->execute('UPDATE applications SET last_used_at=NOW() WHERE id=?', [(int)$app['id']]);

        $user = $this->db->one('SELECT uuid,name,email FROM users WHERE id=?', [$userId]);
        if (!$user) throw new RuntimeException('invalid_grant');
        $claims = [
            'iss' => rtrim((string)$this->config['issuer'], '/'),
            'sub' => $user['uuid'],
            'aud' => $app['client_id'],
            'iat' => time(),
            'exp' => time() + 3600,
            'name' => $user['name'],
            'email' => $user['email'],
            'roles' => $this->access->rolesForUser($userId, (int)$app['id']),
        ];
        if ($nonce !== null) $claims['nonce'] = $nonce;

        $this->audit->write('oidc.sso.success', 'success', $userId, $userId, (int)$app['id']);
        return [
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'id_token' => $this->signJwt($claims),
            'scope' => $scopes,
        ];
    }

    private function signJwt(array $claims): string
    {
        $privateKeyPath = (string)($this->config['keys']['private'] ?? '');
        $privateKey = @file_get_contents($privateKeyPath);
        if (!$privateKey) throw new RuntimeException('server_error');
        $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => (string)($this->config['keys']['kid'] ?? 'default')];
        $b64 = static fn(array $v): string => rtrim(strtr(base64_encode(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $data = $b64($header) . '.' . $b64($claims);
        if (!openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256)) throw new RuntimeException('server_error');
        return $data . '.' . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }
}
