<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class ConditionalAccessService
{
    public function __construct(private Database $db, private ApplicationAccessService $access) {}

    public function evaluate(int $userId, array|int $app, array $context = []): array
    {
        if (is_int($app)) {
            $loaded = $this->db->one('SELECT * FROM applications WHERE id=? AND enabled=1 AND deleted_at IS NULL', [$app]);
            if (!$loaded) return $this->deny('application_not_available');
            $app = $loaded;
        }

        $reasons = [];
        $user = $this->db->one('SELECT is_admin FROM users WHERE id=?', [$userId]);
        if ((bool)($app['maintenance_mode'] ?? false) && !(bool)($user['is_admin'] ?? false)) return $this->deny('maintenance_mode');

        $policy = $this->db->one('SELECT * FROM application_security_policies WHERE application_id=?', [(int)$app['id']]);
        $requiredLevel = 1;
        $requireMfa = false;
        if ($policy) {
            $requiredLevel = max($requiredLevel, (int)$policy['minimum_auth_level']);
            $requireMfa = (bool)$policy['require_mfa'];
            $risk = (int)($context['risk_score'] ?? 0);
            if ($risk > (int)$policy['risk_threshold']) return $this->deny('risk_threshold');
            $ip = (string)($context['ip'] ?? Security::currentIp());
            if ($this->ipListed($ip, $policy['ip_denylist_json'] ?? null)) return $this->deny('ip_denied');
            if ($this->jsonList($policy['ip_allowlist_json'] ?? null) !== [] && !$this->ipListed($ip, $policy['ip_allowlist_json'])) return $this->deny('ip_not_allowlisted');
            $country = strtoupper((string)($context['country_code'] ?? ''));
            if ($country !== '' && in_array($country, $this->upperList($policy['denied_countries_json'] ?? null), true)) return $this->deny('country_denied');
            $allowedCountries = $this->upperList($policy['allowed_countries_json'] ?? null);
            if ($allowedCountries !== [] && ($country === '' || !in_array($country, $allowedCountries, true))) return $this->deny('country_not_allowed');
            if (!$this->withinAccessHours($policy['access_hours_json'] ?? null)) return $this->deny('outside_access_hours');
            if ((bool)$policy['require_trusted_device']) {
                $deviceId = (int)($context['device_id'] ?? 0);
                $trusted = $deviceId > 0 ? $this->db->one('SELECT 1 FROM user_devices WHERE id=? AND user_id=? AND trusted=1 AND revoked_at IS NULL AND (trusted_until IS NULL OR trusted_until>NOW())', [$deviceId,$userId]) : null;
                if (!$trusted) return $this->deny('trusted_device_required');
            }
            $force = (int)($policy['force_reauth_seconds'] ?? 0);
            $authTime = (int)($context['auth_time'] ?? 0);
            if ($force > 0 && ($authTime < 1 || time() - $authTime > $force)) return ['allowed'=>false,'action'=>'step_up','reasons'=>['reauthentication_required']];
        }

        $rolePolicy = $this->db->one('SELECT MAX(rsp.minimum_auth_level) AS level,MAX(rsp.require_mfa) AS mfa FROM role_security_policies rsp JOIN user_system_roles usr ON usr.role_id=rsp.system_role_id WHERE usr.user_id=?', [$userId]);
        if ($rolePolicy) {
            $requiredLevel = max($requiredLevel, (int)($rolePolicy['level'] ?? 1));
            $requireMfa = $requireMfa || (bool)($rolePolicy['mfa'] ?? false);
        }

        $effects = $this->access->matchingDynamicEffects($userId, (int)$app['id'], $context);
        if (in_array('require_step_up', $effects, true)) $requiredLevel = max($requiredLevel, 3);
        if (in_array('require_mfa', $effects, true)) $requireMfa = true;
        if ($requireMfa) $requiredLevel = max($requiredLevel, 2);

        $authLevel = (int)($context['auth_level'] ?? 1);
        if ($authLevel < $requiredLevel) return ['allowed'=>false,'action'=>$requiredLevel >= 3 ? 'step_up' : 'mfa','reasons'=>['authentication_level_'.$requiredLevel.'_required']];

        $maxSessions = (int)($app['max_concurrent_sessions'] ?? 0);
        if ($maxSessions > 0) {
            $row = $this->db->one('SELECT COUNT(*) AS c FROM oidc_sessions WHERE application_id=? AND user_id=? AND revoked_at IS NULL', [(int)$app['id'],$userId]);
            if ((int)($row['c'] ?? 0) >= $maxSessions) return $this->deny('concurrent_session_limit');
        }
        return ['allowed'=>true,'action'=>'allow','reasons'=>$reasons,'required_auth_level'=>$requiredLevel];
    }

    private function deny(string $reason): array { return ['allowed'=>false,'action'=>'deny','reasons'=>[$reason]]; }

    private function jsonList(?string $json): array
    {
        if (!$json) return [];
        $value = json_decode($json, true);
        return is_array($value) ? array_values($value) : [];
    }

    private function upperList(?string $json): array { return array_map(static fn($v) => strtoupper((string)$v), $this->jsonList($json)); }

    private function ipListed(string $ip, ?string $json): bool
    {
        if ($ip === '') return false;
        foreach ($this->jsonList($json) as $cidr) if (Security::ipInCidr($ip, (string)$cidr)) return true;
        return false;
    }

    private function withinAccessHours(?string $json): bool
    {
        if (!$json) return true;
        $cfg = json_decode($json, true);
        if (!is_array($cfg)) return true;
        $tz = new \DateTimeZone((string)($cfg['timezone'] ?? 'UTC'));
        $now = new \DateTimeImmutable('now', $tz);
        $days = $cfg['days'] ?? [];
        if (is_array($days) && $days !== [] && !in_array((int)$now->format('N'), array_map('intval', $days), true)) return false;
        $start = (string)($cfg['start'] ?? '00:00');
        $end = (string)($cfg['end'] ?? '23:59');
        $current = $now->format('H:i');
        return $start <= $end ? ($current >= $start && $current <= $end) : ($current >= $start || $current <= $end);
    }
}
