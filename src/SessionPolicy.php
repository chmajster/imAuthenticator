<?php
declare(strict_types=1);
namespace ImAuthenticator;

final class SessionPolicy
{
    public static function lifetimes(array $app,int $authTime=0):array
    {
        $now=time();$configured=(int)($app['session_ttl_seconds']??0);
        if($configured<=0)return['access'=>3600,'refresh'=>2592000,'session'=>2592000];
        $ttl=max(300,min(2592000,$configured));$anchor=$authTime>0?$authTime:$now;$remaining=$anchor+$ttl-$now;
        if($remaining<=0)throw new \RuntimeException('login_required');
        return['access'=>max(1,min(3600,$remaining)),'refresh'=>$remaining,'session'=>$remaining];
    }
    public static function machineAccessTtl(array $app):int
    {
        $configured=(int)($app['session_ttl_seconds']??0);return$configured>0?max(300,min(3600,$configured)):3600;
    }
}
