<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class Web
{
    public static function e(mixed $value): string
    {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function page(string $title, string $content, ?array $user = null): never
    {
        $e = [self::class, 'e'];
        $nav = '';
        if ($user) {
            $nav = '<nav><a href="/dashboard">Moje aplikacje</a>';
            if ((bool)$user['is_admin']) {
                $nav .= '<a href="/admin/applications">Aplikacje</a><a href="/admin/audit">Audit Log</a>';
            }
            $nav .= '<form method="post" action="/logout" class="inline"><input type="hidden" name="_csrf" value="'.self::e(Security::csrfToken()).'"><button class="link">Wyloguj</button></form></nav>';
        }

        echo '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.self::e($title).' — imAuthenticator</title><link rel="stylesheet" href="/assets/app.css"></head><body><header><a class="brand" href="/dashboard">imAuthenticator</a>'.$nav.'</header><main>'.$content.'</main></body></html>';
        exit;
    }

    public static function redirect(string $url): never
    {
        header('Location: ' . $url);
        exit;
    }
}
