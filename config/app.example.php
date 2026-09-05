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
];
