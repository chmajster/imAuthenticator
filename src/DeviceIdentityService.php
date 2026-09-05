<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class DeviceIdentityService
{
    public function __construct(private Database $db, private array $config) {}

    public function touch(int $userId): array
    {
        $cookieName = (string)($this->config['security']['device_cookie_name'] ?? 'imauth_device');
        $cookie = (string)($_COOKIE[$cookieName] ?? '');
        $ua = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 500);
        $row = null;
        if (preg_match('/^[a-f0-9-]{36}$/i', $cookie)) {
            $candidate = $this->db->one('SELECT * FROM user_devices WHERE uuid=? AND user_id=? AND revoked_at IS NULL', [$cookie,$userId]);
            if ($candidate) {
                $expected = hash('sha256', $cookie.'|'.$ua);
                if (!empty($candidate['fingerprint_hash']) && hash_equals((string)$candidate['fingerprint_hash'], $expected)) $row = $candidate;
            }
        }
        $isNew = false;
        if (!$row) {
            $isNew = true;
            $cookie = Security::uuidV4();
            [$platform,$browser] = $this->uaLabels($ua);
            $this->db->execute('INSERT INTO user_devices(uuid,user_id,name,fingerprint_hash,platform,browser,last_ip) VALUES(?,?,?,?,?,?,?)', [$cookie,$userId,trim($browser.' / '.$platform),hash('sha256',$cookie.'|'.$ua),$platform,$browser,Security::currentIp()]);
            $row = $this->db->one('SELECT * FROM user_devices WHERE id=?', [$this->db->lastInsertId()]);
            $_COOKIE[$cookieName] = $cookie;
            if (PHP_SAPI !== 'cli' && !headers_sent()) {
                setcookie($cookieName,$cookie,['expires'=>time()+31536000,'path'=>'/','secure'=>$this->isHttps(),'httponly'=>true,'samesite'=>'Lax']);
            }
        } else {
            $this->db->execute('UPDATE user_devices SET last_seen_at=NOW(),last_ip=? WHERE id=?', [Security::currentIp(),(int)$row['id']]);
        }
        return $this->context((int)$row['id'],$isNew);
    }

    public function requestContext(): array { return $this->context(0,false); }

    private function context(int $deviceId, bool $isNew): array
    {
        $context = ['device_id'=>$deviceId,'new_device'=>$isNew,'ip'=>Security::currentIp(),'country_code'=>$this->countryCode()];
        $lat = $this->trustedHeader('geo_latitude_header'); $lon = $this->trustedHeader('geo_longitude_header');
        if ($lat !== null && is_numeric($lat)) $context['latitude'] = (float)$lat;
        if ($lon !== null && is_numeric($lon)) $context['longitude'] = (float)$lon;
        return $context;
    }

    private function countryCode(): string
    {
        $v = strtoupper(trim((string)$this->trustedHeader('geo_country_header')));
        return preg_match('/^[A-Z]{2}$/',$v) ? $v : '';
    }

    private function trustedHeader(string $key): ?string
    {
        $name = (string)($this->config['security'][$key] ?? '');
        if ($name === '' || !preg_match('/^HTTP_[A-Z0-9_]+$/',$name)) return null;
        $v = $_SERVER[$name] ?? null;
        return is_string($v) ? $v : null;
    }

    private function uaLabels(string $ua): array
    {
        $platform = str_contains($ua,'Windows') ? 'Windows' : (str_contains($ua,'Android') ? 'Android' : ((str_contains($ua,'iPhone') || str_contains($ua,'iPad')) ? 'iOS' : (str_contains($ua,'Macintosh') ? 'macOS' : (str_contains($ua,'Linux') ? 'Linux' : 'Unknown'))));
        $browser = str_contains($ua,'Edg/') ? 'Edge' : (str_contains($ua,'Chrome/') ? 'Chrome' : (str_contains($ua,'Firefox/') ? 'Firefox' : (str_contains($ua,'Safari/') ? 'Safari' : 'Browser')));
        return [$platform,$browser];
    }

    private function isHttps(): bool { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'); }
}
