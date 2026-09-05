<?php
declare(strict_types=1);

namespace ImAuthenticator;

use RuntimeException;

final class JwtService
{
    public function __construct(private array $config) {}

    public function sign(array $claims, array $header = []): string
    {
        $privatePath = (string)($this->config['keys']['private'] ?? '');
        $privateKey = $privatePath !== '' ? @file_get_contents($privatePath) : false;
        if (!$privateKey) throw new RuntimeException('server_error');

        $header = array_merge([
            'alg' => 'RS256',
            'typ' => 'JWT',
            'kid' => (string)($this->config['keys']['kid'] ?? 'default'),
        ], $header);

        $encode = static fn(array $value): string => rtrim(strtr(base64_encode(json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
        $data = $encode($header) . '.' . $encode($claims);
        if (!openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256)) throw new RuntimeException('server_error');
        return $data . '.' . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    }

    public function issuer(): string
    {
        return rtrim((string)($this->config['issuer'] ?? ''), '/');
    }
}
