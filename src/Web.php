<?php
declare(strict_types=1);

namespace ImAuthenticator;

final class Web
{
    public static function e(mixed $value): string{return htmlspecialchars((string)$value,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
    public static function page(string $title,string $content,?array $user=null):never
    {
        $nav='';
        if($user){
            $nav='<nav><a href="/dashboard">Moje aplikacje</a><a href="/applications/catalog">Katalog</a><a href="/account/passkeys">Passkeys</a><a href="/account/emails">E-maile</a><a href="/account/devices">Urządzenia</a><a href="/account/consents">Zgody</a><a href="/access-requests">Wnioski</a>';
            if((bool)$user['is_admin'])$nav.='<a href="/admin/applications">Aplikacje</a><a href="/admin/access-requests">Approval</a><a href="/admin/access-reviews">Reviews</a><a href="/admin/identity-providers">Identity</a><a href="/admin/scim">SCIM</a><a href="/admin/security">Security</a><a href="/admin/system">System</a><a href="/admin/integration-tools">Integracje</a><a href="/admin/audit">Audit Log</a>';
            $nav.='<form method="post" action="/logout" class="inline"><input type="hidden" name="_csrf" value="'.self::e(Security::csrfToken()).'"><button class="link">Wyloguj</button></form></nav>';
        }
        $impersonating=!empty($_SESSION['impersonation_actor_id']);
        $banner=$impersonating?'<div class="alert warning"><strong>Tryb impersonacji.</strong> Działasz jako inny użytkownik. <form class="inline" method="post" action="/impersonation/end"><input type="hidden" name="_csrf" value="'.self::e(Security::csrfToken()).'"><button>Zakończ</button></form></div>':'';
        echo '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.self::e($title).' — imAuthenticator</title><link rel="stylesheet" href="/assets/app.css"></head><body><header><a class="brand" href="/dashboard">imAuthenticator</a>'.$nav.'</header><main>'.$banner.$content.'</main></body></html>';exit;
    }
    public static function redirect(string $url):never{header('Location: '.$url);exit;}
}
