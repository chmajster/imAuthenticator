<?php
return [
    'db' => ['dsn' => 'mysql:host=127.0.0.1;dbname=imauthenticator;charset=utf8mb4', 'user' => '', 'pass' => ''],
    'issuer' => 'https://auth.example.com',
    'session_name' => 'imauthenticator_session',
    'keys' => [
        'private' => __DIR__ . '/keys/private.pem',
        'public' => __DIR__ . '/keys/public.pem',
        'kid' => 'default',
    ],
    'security' => [
        'device_cookie_name' => 'imauth_device',
        // Set these only when a trusted reverse proxy strips client-supplied copies
        // and injects verified geolocation headers. Values use PHP's HTTP_* names.
        'geo_country_header' => '',
        'geo_latitude_header' => '',
        'geo_longitude_header' => '',
    ],
];
