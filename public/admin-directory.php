<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use ImAuthenticator\Web;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);
$user = $auth->requireAdmin();
$providerId = (int)($_GET['id'] ?? 0);
$provider = $db->one("SELECT * FROM identity_providers WHERE id=? AND provider_type IN ('ldap','active_directory')", [$providerId]);
if (!$provider) {
    http_response_code(404);
    Web::page('Nie znaleziono', '<div class="alert danger">Nie znaleziono providera LDAP/AD.</div>', $user);
}

$message = '';
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $action = (string)($_POST['action'] ?? '');
    try {
        if ($action === 'test') {
            $result = $directory->test($providerId);
            $message = '<div class="alert success">Połączenie działa. Base DN: '.Web::e($result['base_dn']).', opóźnienie: '.(int)$result['latency_ms'].' ms.</div>';
        } elseif ($action === 'sync') {
            $result = $directory->sync($providerId, (int)$user['id']);
            $message = '<div class="alert success">Synchronizacja zakończona. Nowi: '.(int)$result['created'].', zaktualizowani: '.(int)$result['updated'].', wyłączeni: '.(int)$result['disabled'].', grupy: '.(int)$result['groups'].'.</div>';
        }
    } catch (Throwable $e) {
        $message = '<div class="alert danger">'.Web::e($e->getMessage()).'</div>';
    }
}

$config = json_decode((string)$provider['config_json'], true);
$config = is_array($config) ? $config : [];
$runs = $db->all('SELECT * FROM directory_sync_runs WHERE identity_provider_id=? ORDER BY id DESC LIMIT 30', [$providerId]);
$rows = '';
foreach ($runs as $run) {
    $rows .= '<tr><td>'.Web::e($run['started_at']).'</td><td>'.Web::e($run['status']).'</td><td>'.(int)$run['users_created'].'</td><td>'.(int)$run['users_updated'].'</td><td>'.(int)$run['users_disabled'].'</td><td>'.(int)$run['groups_updated'].'</td><td>'.Web::e($run['error_summary'] ?: '—').'</td></tr>';
}
if ($rows === '') $rows = '<tr><td colspan="7" class="empty">Brak wykonanych synchronizacji.</td></tr>';

$envName = (string)($config['bind_password_env'] ?? '');
$extensionStatus = extension_loaded('ldap') ? '<span class="badge ok">ext-ldap dostępne</span>' : '<span class="badge muted">Brak ext-ldap</span>';
$content = '<div class="page-head"><div><h1>'.Web::e($provider['name']).' — LDAP / Active Directory</h1><p>Test połączenia i synchronizacja użytkowników oraz grup.</p></div><a class="button" href="/admin/identity-providers">Wróć</a></div>'.$message;
$content .= '<section class="card"><h2>Konfiguracja</h2>'.$extensionStatus.'<div class="kv"><span>URI</span><code>'.Web::e((string)($config['uri'] ?? '—')).'</code></div><div class="kv"><span>Base DN</span><code>'.Web::e((string)($config['base_dn'] ?? '—')).'</code></div><div class="kv"><span>Bind DN</span><code>'.Web::e((string)($config['bind_dn'] ?? '—')).'</code></div><div class="kv"><span>Hasło bind</span><code>'.Web::e($envName !== '' ? 'ENV: '.$envName : 'anonimowy bind / brak').'</code></div><div class="kv"><span>Authoritative</span><code>'.((bool)($config['authoritative'] ?? false) ? 'Tak' : 'Nie').'</code></div><div class="actions"><form method="post" class="inline"><input type="hidden" name="_csrf" value="'.Web::e(Security::csrfToken()).'"><button name="action" value="test">Testuj połączenie</button><button class="primary" name="action" value="sync">Uruchom synchronizację</button></form></div></section>';
$content .= '<section class="card"><h2>Bezpieczna konfiguracja hasła bind</h2><p>W `config_json` podaj nazwę zmiennej środowiskowej w <code>bind_password_env</code>. Hasło nie jest zapisywane jawnie w bazie.</p><pre class="code">'.Web::e(json_encode([
    'uri'=>'ldaps://ad.example.com:636',
    'base_dn'=>'DC=example,DC=com',
    'user_base_dn'=>'OU=Users,DC=example,DC=com',
    'group_base_dn'=>'OU=Groups,DC=example,DC=com',
    'bind_dn'=>'CN=svc-imauth,OU=Service Accounts,DC=example,DC=com',
    'bind_password_env'=>'IMAUTH_LDAP_BIND_PASSWORD',
    'user_filter'=>'(&(objectClass=user)(mail=*))',
    'group_filter'=>'(objectClass=group)',
    'username_attribute'=>'sAMAccountName',
    'email_attribute'=>'mail',
    'name_attribute'=>'displayName',
    'attribute_mapping'=>['department'=>'department'],
    'sync_groups'=>true,
    'authoritative'=>false,
    'disable_missing_users'=>false
], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)).'</pre></section>';
$content .= '<div class="table-wrap"><table><thead><tr><th>Start</th><th>Status</th><th>Utworzeni</th><th>Aktualizowani</th><th>Wyłączeni</th><th>Grupy</th><th>Błąd</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
Web::page('LDAP / Active Directory', $content, $user);
