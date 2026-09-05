<?php
declare(strict_types=1);

$configPath = dirname(__DIR__) . '/config/config.php';
$keyDir = dirname(__DIR__) . '/config/keys';
if (is_file($configPath)) {
    header('Location: /login');
    exit;
}

session_name('imauthenticator_install');
session_start();
if (empty($_SESSION['_install_csrf'])) $_SESSION['_install_csrf'] = bin2hex(random_bytes(32));
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals((string)$_SESSION['_install_csrf'], (string)($_POST['_csrf'] ?? ''))) {
        $errors[] = 'Nieprawidłowy token CSRF.';
    }

    $host = trim((string)($_POST['db_host'] ?? '127.0.0.1'));
    $dbName = trim((string)($_POST['db_name'] ?? 'imauthenticator'));
    $dbUser = trim((string)($_POST['db_user'] ?? ''));
    $dbPass = (string)($_POST['db_pass'] ?? '');
    $issuer = rtrim(trim((string)($_POST['issuer'] ?? '')), '/');
    $adminName = trim((string)($_POST['admin_name'] ?? 'Administrator'));
    $adminEmail = strtolower(trim((string)($_POST['admin_email'] ?? '')));
    $adminPassword = (string)($_POST['admin_password'] ?? '');

    if (!preg_match('/^[A-Za-z0-9_]+$/', $dbName)) $errors[] = 'Nazwa bazy może zawierać tylko litery, cyfry i znak _.';
    if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) $errors[] = 'Nieprawidłowy e-mail administratora.';
    if (strlen($adminPassword) < 12) $errors[] = 'Hasło administratora musi mieć co najmniej 12 znaków.';
    if (!filter_var($issuer, FILTER_VALIDATE_URL) || parse_url($issuer, PHP_URL_SCHEME) !== 'https') $errors[] = 'Issuer URL musi być poprawnym adresem HTTPS.';

    if (!$errors) {
        try {
            $server = new PDO("mysql:host={$host};charset=utf8mb4", $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $server->exec('CREATE DATABASE IF NOT EXISTS `' . $dbName . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
            $pdo = new PDO("mysql:host={$host};dbname={$dbName};charset=utf8mb4", $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $schema = file_get_contents(dirname(__DIR__) . '/database/schema.sql');
            if ($schema === false) throw new RuntimeException('Brak database/schema.sql.');
            $pdo->exec($schema);

            $uuid = (static function (): string {
                $d = random_bytes(16);
                $d[6] = chr((ord($d[6]) & 0x0f) | 0x40);
                $d[8] = chr((ord($d[8]) & 0x3f) | 0x80);
                return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($d), 4));
            })();
            $stmt = $pdo->prepare('INSERT INTO users(uuid,name,email,password_hash,is_admin,enabled) VALUES(?,?,?,?,1,1)');
            $stmt->execute([$uuid, $adminName, $adminEmail, password_hash($adminPassword, PASSWORD_ARGON2ID)]);

            if (!is_dir($keyDir) && !mkdir($keyDir, 0700, true) && !is_dir($keyDir)) throw new RuntimeException('Nie można utworzyć config/keys.');
            $key = openssl_pkey_new(['private_key_bits' => 3072, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($key === false) throw new RuntimeException('Nie można wygenerować klucza RSA.');
            if (!openssl_pkey_export($key, $privatePem)) throw new RuntimeException('Nie można wyeksportować klucza prywatnego.');
            $details = openssl_pkey_get_details($key);
            if (!is_array($details) || empty($details['key'])) throw new RuntimeException('Nie można odczytać klucza publicznego.');
            file_put_contents($keyDir . '/private.pem', $privatePem, LOCK_EX);
            file_put_contents($keyDir . '/public.pem', $details['key'], LOCK_EX);
            @chmod($keyDir . '/private.pem', 0600);
            @chmod($keyDir . '/public.pem', 0644);

            $config = [
                'db' => ['dsn' => "mysql:host={$host};dbname={$dbName};charset=utf8mb4", 'user' => $dbUser, 'pass' => $dbPass],
                'issuer' => $issuer,
                'session_name' => 'imauthenticator_session',
                'keys' => ['private' => $keyDir . '/private.pem', 'public' => $keyDir . '/public.pem', 'kid' => substr(hash('sha256', $details['key']), 0, 16)],
            ];
            if (!is_dir(dirname($configPath)) && !mkdir(dirname($configPath), 0750, true) && !is_dir(dirname($configPath))) throw new RuntimeException('Nie można utworzyć config/.');
            $written = file_put_contents($configPath, "<?php\nreturn " . var_export($config, true) . ";\n", LOCK_EX);
            if ($written === false) throw new RuntimeException('Nie można zapisać config/config.php.');
            @chmod($configPath, 0640);
            session_destroy();
            header('Location: /login?installed=1');
            exit;
        } catch (Throwable $e) {
            $errors[] = 'Instalacja nie powiodła się: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        }
    }
}

function e(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Instalacja imAuthenticator</title><link rel="stylesheet" href="/assets/app.css"></head><body class="install"><main class="card installer"><h1>Instalacja imAuthenticator</h1><p>Instalator utworzy bazę, schemat, konto administratora oraz klucze OIDC. Nie trzeba wykonywać SQL ręcznie.</p><?php foreach($errors as $error): ?><div class="alert danger"><?= $error ?></div><?php endforeach; ?><form method="post"><input type="hidden" name="_csrf" value="<?= e((string)$_SESSION['_install_csrf']) ?>"><h2>Baza danych</h2><label>Host<input name="db_host" value="<?= e((string)($_POST['db_host'] ?? '127.0.0.1')) ?>" required></label><label>Nazwa bazy<input name="db_name" value="<?= e((string)($_POST['db_name'] ?? 'imauthenticator')) ?>" required></label><label>Użytkownik<input name="db_user" value="<?= e((string)($_POST['db_user'] ?? '')) ?>" required></label><label>Hasło<input type="password" name="db_pass"></label><h2>OIDC</h2><label>Issuer URL<input type="url" name="issuer" placeholder="https://auth.example.com" value="<?= e((string)($_POST['issuer'] ?? '')) ?>" required></label><h2>Administrator</h2><label>Imię i nazwisko<input name="admin_name" value="<?= e((string)($_POST['admin_name'] ?? 'Administrator')) ?>" required></label><label>E-mail<input type="email" name="admin_email" value="<?= e((string)($_POST['admin_email'] ?? '')) ?>" required></label><label>Hasło<input type="password" name="admin_password" minlength="12" required></label><button class="primary" type="submit">Zainstaluj</button></form></main></body></html>
