<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class AuthService
{
    public function __construct(
        private Database $db,
        private AuditLog $audit,
        private ?SystemSettingsService $settings = null,
        private ?DeviceIdentityService $devices = null,
        private ?DeviceRiskService $risk = null,
        private ?EventService $events = null,
        private ?OrganizationService $organizations = null
    ) {}

    public function currentUser(): ?array
    {
        $id = (int)($_SESSION['user_id'] ?? 0);
        if ($id < 1) return null;
        $user = $this->db->one('SELECT id,uuid,name,username,email,is_admin,break_glass,inactive_lock_exempt,enabled,lifecycle_status,account_starts_at,account_ends_at,last_login_at FROM users WHERE id=?', [$id]);
        if (!$this->isActive($user,false)) { $this->logout(); return null; }
        $this->db->execute('UPDATE users SET last_activity_at=NOW() WHERE id=?', [$id]);
        $user['organization_admin'] = (bool)$user['is_admin'] || $this->db->one("SELECT 1 FROM organization_memberships om JOIN organizations o ON o.id=om.organization_id WHERE om.user_id=? AND om.role IN ('owner','admin') AND om.status='active' AND o.status='active' AND (om.valid_from IS NULL OR om.valid_from<=NOW()) AND (om.valid_until IS NULL OR om.valid_until>NOW()) LIMIT 1", [$id]) !== null;
        return $user;
    }

    public function login(string $identifier, string $password): bool
    {
        $identifier = trim(strtolower($identifier));
        $user = $this->db->one('SELECT DISTINCT u.* FROM users u LEFT JOIN user_emails ue ON ue.user_id=u.id WHERE LOWER(u.email)=? OR LOWER(u.username)=? OR LOWER(ue.email)=? LIMIT 1', [$identifier,$identifier,$identifier]);
        if (!$this->isActive($user,true) || !password_verify($password,(string)($user['password_hash'] ?? ''))) {
            $userId = $user ? (int)$user['id'] : null;
            $this->audit->write('auth.login.failed','denied',null,$userId,null,'invalid credentials, maintenance or inactive account');
            $this->recordFailure($userId);
            $this->events?->emit('auth.login.failed',['user_id'=>$userId,'ip'=>Security::currentIp(),'severity'=>'warning']);
            return false;
        }
        $this->establishSession((int)$user['id'],1);
        $this->audit->write('auth.login.success','success',(int)$user['id'],(int)$user['id'],null,null,['method'=>'password','risk_score'=>(int)($_SESSION['risk_score'] ?? 0),'risk_reasons'=>$_SESSION['risk_reasons'] ?? []]);
        return true;
    }

    public function loginVerifiedUser(int $userId, int $authLevel = 2, string $method = 'passkey'): bool
    {
        $user = $this->db->one('SELECT * FROM users WHERE id=?', [$userId]);
        if (!$this->isActive($user,true)) return false;
        $this->establishSession($userId,max(1,min(3,$authLevel)));
        $this->audit->write('auth.login.success','success',$userId,$userId,null,null,['method'=>$method,'auth_level'=>(int)$_SESSION['auth_level'],'risk_score'=>(int)($_SESSION['risk_score'] ?? 0),'risk_reasons'=>$_SESSION['risk_reasons'] ?? []]);
        return true;
    }

    public function reauthenticatePassword(string $password): bool
    {
        $user = $this->currentUser(); if (!$user) return false;
        $row = $this->db->one('SELECT password_hash FROM users WHERE id=?', [(int)$user['id']]);
        if (!$row || !password_verify($password,(string)$row['password_hash'])) {
            $this->audit->write('auth.reauthentication.failed','denied',(int)$user['id'],(int)$user['id'],null,'invalid password');
            return false;
        }
        $_SESSION['auth_time'] = time(); $_SESSION['password_reauth_at'] = time(); $_SESSION['auth_level'] = max(1,(int)($_SESSION['auth_level'] ?? 1));
        $this->audit->write('auth.reauthentication.success','success',(int)$user['id'],(int)$user['id'],null,null,['method'=>'password']);
        return true;
    }

    public function setAuthenticationLevel(int $level): void { $_SESSION['auth_level']=max(1,min(3,$level)); $_SESSION['auth_time']=time(); }

    public function authenticationContext(): array
    {
        return ['auth_level'=>(int)($_SESSION['auth_level'] ?? 1),'auth_time'=>(int)($_SESSION['auth_time'] ?? 0),'device_id'=>(int)($_SESSION['device_id'] ?? 0),'risk_score'=>(int)($_SESSION['risk_score'] ?? 0),'risk_reasons'=>$_SESSION['risk_reasons'] ?? [],'country_code'=>$_SESSION['country_code'] ?? null,'ip'=>Security::currentIp()];
    }

    public function logout(): void { $_SESSION=[]; if (session_status()===PHP_SESSION_ACTIVE) session_regenerate_id(true); }

    public function requireUser(): array
    {
        $user=$this->currentUser();
        if(!$user){$return=$_SERVER['REQUEST_URI']??'/dashboard';header('Location: /login?return='.rawurlencode($return));exit;}
        return $user;
    }

    public function requireAdmin(): array
    {
        $user=$this->requireUser();
        if(!(bool)$user['is_admin']){http_response_code(403);exit('Brak uprawnień administratora.');}
        if((bool)($user['break_glass']??false)&&(int)($_SESSION['auth_level']??1)<2){$return=$_SERVER['REQUEST_URI']??'/admin/security';header('Location: /mfa/challenge?level=2&return='.rawurlencode($return));exit;}
        return $user;
    }

    private function establishSession(int $userId, int $authLevel): void
    {
        session_regenerate_id(true);
        $_SESSION['user_id']=$userId; $_SESSION['auth_level']=$authLevel; $_SESSION['auth_time']=time(); unset($_SESSION['password_reauth_at']);
        $this->db->execute('UPDATE users SET last_login_at=NOW(),last_activity_at=NOW() WHERE id=?', [$userId]);
        $this->ensureProvisionedOrganizations($userId);
        $this->hydrateSecurityContext($userId);
    }

    private function ensureProvisionedOrganizations(int $userId): void
    {
        if (!$this->organizations) return;
        $rows = $this->db->all('SELECT DISTINCT ip.organization_id FROM external_identities ei JOIN identity_providers ip ON ip.id=ei.identity_provider_id WHERE ei.user_id=? AND ip.enabled=1 AND ip.organization_id IS NOT NULL', [$userId]);
        foreach ($rows as $row) $this->organizations->ensureMember((int)$row['organization_id'],$userId,null,'member');
    }

    private function hydrateSecurityContext(int $userId): void
    {
        try {
            $context = $this->devices?->touch($userId) ?? ['device_id'=>0,'new_device'=>false,'ip'=>Security::currentIp(),'country_code'=>''];
            $assessment = $this->risk?->assess($userId,$context) ?? ['score'=>0,'reasons'=>[]];
            $_SESSION['device_id']=(int)($context['device_id']??0); $_SESSION['risk_score']=(int)($assessment['score']??0); $_SESSION['risk_reasons']=$assessment['reasons']??[]; $_SESSION['country_code']=$context['country_code']??null;
            $this->risk?->record($userId,null,'login_success',$context,(int)$_SESSION['risk_score'],(array)$_SESSION['risk_reasons']);
            if ((int)$_SESSION['risk_score'] > 0) {
                $severity = (int)$_SESSION['risk_score'] >= 70 ? 'high' : ((int)$_SESSION['risk_score'] >= 40 ? 'warning' : 'info');
                $payload=['user_id'=>$userId,'device_id'=>(int)$_SESSION['device_id'],'risk_score'=>(int)$_SESSION['risk_score'],'reasons'=>(array)$_SESSION['risk_reasons'],'ip'=>$context['ip']??Security::currentIp(),'country_code'=>$context['country_code']??null,'severity'=>$severity];
                $this->audit->write('auth.risk.assessed','success',$userId,$userId,null,null,$payload);
                $this->events?->emit('auth.risk.detected',$payload);
            }
        } catch (\Throwable $e) {
            $_SESSION['device_id']=0; $_SESSION['risk_score']=100; $_SESSION['risk_reasons']=['risk_engine_error']; $_SESSION['country_code']=null;
            $this->audit->write('auth.risk.error','failure',$userId,$userId,null,substr($e->getMessage(),0,500));
            $this->events?->emit('auth.risk.error',['user_id'=>$userId,'severity'=>'high']);
        }
    }

    private function recordFailure(?int $userId): void
    {
        if ($userId === null || !$this->risk) return;
        try { $context=$this->devices?->requestContext() ?? ['device_id'=>0,'ip'=>Security::currentIp()]; $this->risk->record($userId,null,'login_failure',$context,0,['invalid_credentials']); } catch (\Throwable) {}
    }

    private function isActive(?array $user, bool $forNewLogin): bool
    {
        if(!$user||!(bool)$user['enabled']||($user['lifecycle_status']??'active')!=='active')return false;
        $now=time();if(!empty($user['account_starts_at'])&&strtotime((string)$user['account_starts_at'])>$now)return false;if(!empty($user['account_ends_at'])&&strtotime((string)$user['account_ends_at'])<=$now)return false;
        if($forNewLogin&&$this->settings?->maintenanceMode()&&!(bool)($user['is_admin']??false))return false;
        if($forNewLogin&&$this->settings){$days=$this->settings->inactiveDays();if($days>0&&!(bool)($user['is_admin']??false)&&!(bool)($user['break_glass']??false)&&!(bool)($user['inactive_lock_exempt']??false)&&!empty($user['last_login_at'])&&strtotime((string)$user['last_login_at'])<time()-$days*86400){$this->db->execute("UPDATE users SET lifecycle_status='suspended' WHERE id=?",[(int)$user['id']]);$this->audit->write('account.auto_suspended','success',null,(int)$user['id'],null,'inactive account during login');return false;}}
        return true;
    }
}
