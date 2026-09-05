<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class AuthService
{
    public function __construct(private Database $db, private AuditLog $audit, private ?SystemSettingsService $settings = null) {}

    public function currentUser(): ?array
    {
        $id = (int)($_SESSION['user_id'] ?? 0);
        if ($id < 1) return null;
        $user = $this->db->one('SELECT id,uuid,name,username,email,is_admin,break_glass,inactive_lock_exempt,enabled,lifecycle_status,account_starts_at,account_ends_at,last_login_at FROM users WHERE id=?', [$id]);
        if (!$this->isActive($user, false)) {
            $this->logout();
            return null;
        }
        $this->db->execute('UPDATE users SET last_activity_at=NOW() WHERE id=?', [$id]);
        return $user;
    }

    public function login(string $identifier, string $password): bool
    {
        $identifier = trim(strtolower($identifier));
        $user = $this->db->one('SELECT DISTINCT u.* FROM users u LEFT JOIN user_emails ue ON ue.user_id=u.id WHERE LOWER(u.email)=? OR LOWER(u.username)=? OR LOWER(ue.email)=? LIMIT 1', [$identifier,$identifier,$identifier]);
        if (!$this->isActive($user, true) || !password_verify($password, (string)($user['password_hash'] ?? ''))) {
            $this->audit->write('auth.login.failed', 'denied', null, $user ? (int)$user['id'] : null, null, 'invalid credentials, maintenance or inactive account');
            return false;
        }
        $this->establishSession((int)$user['id'],1);
        $this->audit->write('auth.login.success', 'success', (int)$user['id'], (int)$user['id'], null, null, ['method'=>'password']);
        return true;
    }

    public function loginVerifiedUser(int $userId, int $authLevel = 2, string $method = 'passkey'): bool
    {
        $user=$this->db->one('SELECT * FROM users WHERE id=?',[$userId]);
        if(!$this->isActive($user,true))return false;
        $this->establishSession($userId,max(1,min(3,$authLevel)));
        $this->audit->write('auth.login.success','success',$userId,$userId,null,null,['method'=>$method,'auth_level'=>(int)$_SESSION['auth_level']]);
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
        if ((bool)($user['break_glass'] ?? false) && (int)($_SESSION['auth_level'] ?? 1) < 2) {
            $return=$_SERVER['REQUEST_URI']??'/admin/security';
            header('Location: /login?reauth=1&return='.rawurlencode($return));
            exit;
        }
        return $user;
    }

    private function establishSession(int $userId,int $authLevel): void
    {
        session_regenerate_id(true);
        $_SESSION['user_id']=$userId;
        $_SESSION['auth_level']=$authLevel;
        $_SESSION['auth_time']=time();
        $this->db->execute('UPDATE users SET last_login_at=NOW(),last_activity_at=NOW() WHERE id=?',[$userId]);
    }

    private function isActive(?array $user, bool $forNewLogin): bool
    {
        if (!$user || !(bool)$user['enabled'] || ($user['lifecycle_status'] ?? 'active') !== 'active') return false;
        $now = time();
        if (!empty($user['account_starts_at']) && strtotime((string)$user['account_starts_at']) > $now) return false;
        if (!empty($user['account_ends_at']) && strtotime((string)$user['account_ends_at']) <= $now) return false;
        if ($forNewLogin && $this->settings?->maintenanceMode() && !(bool)($user['is_admin'] ?? false)) return false;
        if ($forNewLogin && $this->settings) {
            $days=$this->settings->inactiveDays();
            if($days>0 && !(bool)($user['is_admin']??false) && !(bool)($user['break_glass']??false) && !(bool)($user['inactive_lock_exempt']??false) && !empty($user['last_login_at']) && strtotime((string)$user['last_login_at']) < time()-$days*86400){
                $this->db->execute("UPDATE users SET lifecycle_status='suspended' WHERE id=?",[(int)$user['id']]);
                $this->audit->write('account.auto_suspended','success',null,(int)$user['id'],null,'inactive account during login');
                return false;
            }
        }
        return true;
    }
}
