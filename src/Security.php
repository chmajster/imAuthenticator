<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class Security
{
    public static function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public static function clientId(): string { return 'ima_' . self::randomToken(24); }
    public static function clientSecret(): string { return 'ims_' . self::randomToken(48); }
    public static function tokenHash(string $token): string { return hash('sha256', $token); }
    public static function secretHash(string $secret): string { return password_hash($secret, PASSWORD_ARGON2ID); }
    public static function verifySecret(string $secret, ?string $hash): bool { return $hash !== null && password_verify($secret, $hash); }

    public static function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    public static function validRedirectUri(string $uri): bool
    {
        if ($uri === '' || str_contains($uri, '*') || preg_match('/[\x00-\x20]/', $uri)) return false;
        $parts = parse_url($uri);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) return false;
        $scheme = strtolower((string)$parts['scheme']);
        $host = strtolower((string)$parts['host']);
        if ($scheme === 'https') return true;
        return $scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    public static function verifyPkce(string $verifier, string $challenge, string $method): bool
    {
        if (!preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier) || $method !== 'S256') return false;
        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        return hash_equals($challenge, $expected);
    }

    public static function csrfToken(): string
    {
        if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = self::randomToken(32);
        return (string)$_SESSION['_csrf'];
    }

    public static function requireCsrf(?string $token): void
    {
        if (!is_string($token) || !hash_equals(self::csrfToken(), $token)) {
            http_response_code(419);
            exit('Nieprawidłowy token CSRF.');
        }
    }

    public static function slug(string $value): string
    {
        $value = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value) ?: $value;
        $value = strtolower(trim(preg_replace('/[^a-zA-Z0-9]+/', '-', $value) ?? '', '-'));
        return $value !== '' ? $value : 'app-' . strtolower(self::randomToken(6));
    }

    public static function currentIp(): string
    {
        return substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 64);
    }

    public static function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', trim($cidr), 2);
        $network = inet_pton($parts[0]);
        $address = inet_pton($ip);
        if ($network === false || $address === false || strlen($network) !== strlen($address)) return false;
        $max = strlen($network) * 8;
        $prefix = isset($parts[1]) ? (int)$parts[1] : $max;
        if ($prefix < 0 || $prefix > $max) return false;
        $bytes = intdiv($prefix, 8);
        $bits = $prefix % 8;
        if ($bytes > 0 && substr($network, 0, $bytes) !== substr($address, 0, $bytes)) return false;
        if ($bits === 0) return true;
        $mask = (0xFF << (8 - $bits)) & 0xFF;
        return (ord($network[$bytes]) & $mask) === (ord($address[$bytes]) & $mask);
    }
}
