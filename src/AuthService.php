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
        $user = $this->db->one('SELECT id,uuid,name,email,is_admin,enabled FROM users WHERE id=?', [$id]);
        if (!$user || !(bool)$user['enabled']) {
            $this->logout();
            return null;
        }
        return $user;
    }

    public function login(string $email, string $password): bool
    {
        $user = $this->db->one('SELECT * FROM users WHERE email=?', [trim(strtolower($email))]);
        if (!$user || !(bool)$user['enabled'] || !password_verify($password, $user['password_hash'])) {
            $this->audit->write('auth.login.failed', 'denied', null, $user ? (int)$user['id'] : null, null, 'invalid credentials');
            return false;
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$user['id'];
        $this->audit->write('auth.login.success', 'success', (int)$user['id'], (int)$user['id']);
        return true;
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
}
