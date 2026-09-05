<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AuthService
{
    public function __construct(private Database $db, private AuditLog $audit) {}

    public function currentUser(): ?array
    {
        $id = (int)($_SESSION['user_id'] ?? 0);
        if ($id < 1) return null;
        $user = $this->db->one('SELECT id,uuid,name,username,email,is_admin,enabled,lifecycle_status,account_starts_at,account_ends_at FROM users WHERE id=?', [$id]);
        if (!$this->isActive($user)) {
            $this->logout();
            return null;
        }
        $this->db->execute('UPDATE users SET last_activity_at=NOW() WHERE id=?', [$id]);
        return $user;
    }

    public function login(string $identifier, string $password): bool
    {
        $identifier = trim(strtolower($identifier));
        $user = $this->db->one('SELECT * FROM users WHERE LOWER(email)=? OR LOWER(username)=? LIMIT 1', [$identifier,$identifier]);
        if (!$this->isActive($user) || !password_verify($password, (string)($user['password_hash'] ?? ''))) {
            $this->audit->write('auth.login.failed', 'denied', null, $user ? (int)$user['id'] : null, null, 'invalid credentials or inactive account');
            return false;
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['auth_level'] = 1;
        $_SESSION['auth_time'] = time();
        $this->db->execute('UPDATE users SET last_login_at=NOW(),last_activity_at=NOW() WHERE id=?', [(int)$user['id']]);
        $this->audit->write('auth.login.success', 'success', (int)$user['id'], (int)$user['id']);
        return true;
    }

    public function setAuthenticationLevel(int $level): void
    {
        $_SESSION['auth_level'] = max(1, min(3, $level));
        $_SESSION['auth_time'] = time();
    }

    public function authenticationContext(): array
    {
        return ['auth_level'=>(int)($_SESSION['auth_level'] ?? 1),'auth_time'=>(int)($_SESSION['auth_time'] ?? 0),'device_id'=>(int)($_SESSION['device_id'] ?? 0),'risk_score'=>(int)($_SESSION['risk_score'] ?? 0),'country_code'=>$_SESSION['country_code'] ?? null,'ip'=>Security::currentIp()];
    }

    public function logout(): void
    {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) session_regenerate_id(true);
    }

    public function requireUser(): array
    {
        $user = $this->currentUser();
        if (!$user) {
            $return = $_SERVER['REQUEST_URI'] ?? '/dashboard';
            header('Location: /login?return=' . rawurlencode($return));
            exit;
        }
        return $user;
    }

    public function requireAdmin(): array
    {
        $user = $this->requireUser();
        if (!(bool)$user['is_admin']) {
            http_response_code(403);
            exit('Brak uprawnień administratora.');
        }
        return $user;
    }

    private function isActive(?array $user): bool
    {
        if (!$user || !(bool)$user['enabled'] || ($user['lifecycle_status'] ?? 'active') !== 'active') return false;
        $now = time();
        if (!empty($user['account_starts_at']) && strtotime((string)$user['account_starts_at']) > $now) return false;
        if (!empty($user['account_ends_at']) && strtotime((string)$user['account_ends_at']) <= $now) return false;
        return true;
    }
}
