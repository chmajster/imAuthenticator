<?php
declare(strict_types=1);

use ImAuthenticator\Security;
use RuntimeException;

$services = require dirname(__DIR__) . '/src/bootstrap.php';
extract($services, EXTR_SKIP);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

function e(mixed $value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function redirect(string $url): never { header('Location: ' . $url); exit; }
function jsonResponse(array $data, int $status = 200): never { http_response_code($status); header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store'); echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR); exit; }
function bearerToken(): string { $h = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''); return str_starts_with($h, 'Bearer ') ? trim(substr($h, 7)) : ''; }
function appTypeLabel(string $type): string { return ['website'=>'Strona WWW','wordpress'=>'WordPress','php'=>'Własna aplikacja PHP','spa'=>'SPA','mobile'=>'Aplikacja mobilna','oidc'=>'Generic OpenID Connect','m2m'=>'Machine-to-Machine'][$type] ?? $type; }
function page(string $title, string $content, ?array $user = null): never {
    $nav = $user ? '<nav><a href="/dashboard">Moje aplikacje</a>' . ((bool)$user['is_admin'] ? '<a href="/admin/applications">Aplikacje</a><a href="/admin/audit">Audit Log</a>' : '') . '<form method="post" action="/logout" class="inline"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><button class="link">Wyloguj</button></form></nav>' : '';
    echo '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.e($title).' — imAuthenticator</title><link rel="stylesheet" href="/assets/app.css"></head><body><header><a class="brand" href="/dashboard">imAuthenticator</a>'.$nav.'</header><main>'.$content.'</main></body></html>';
    exit;
}
function oauthDeniedPage(array $app, string $redirectUri, ?string $state): never {
    http_response_code(403);
    $return = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query(array_filter(['error'=>'access_denied','error_description'=>'User is not allowed to access this application','state'=>$state], static fn($v) => $v !== null));
    $body = '<section class="card narrow"><h1>Brak dostępu</h1><p>Nie masz uprawnień do aplikacji <strong>'.e($app['name']).'</strong>.</p><p>Skontaktuj się z administratorem, aby uzyskać dostęp.</p><div class="code">OAuth error: access_denied</div><a class="button" href="'.e($return).'">Powrót do aplikacji</a></section>';
    page('Brak dostępu', $body, null);
}

if ($path === '/.well-known/openid-configuration' && $method === 'GET') {
    $issuer = rtrim((string)$config['issuer'], '/');
    jsonResponse([
        'issuer'=>$issuer,
        'authorization_endpoint'=>$issuer.'/oauth/authorize',
        'token_endpoint'=>$issuer.'/oauth/token',
        'userinfo_endpoint'=>$issuer.'/oauth/userinfo',
        'end_session_endpoint'=>$issuer.'/oauth/logout',
        'jwks_uri'=>$issuer.'/.well-known/jwks.json',
        'response_types_supported'=>['code'],
        'grant_types_supported'=>['authorization_code','refresh_token'],
        'subject_types_supported'=>['public'],
        'id_token_signing_alg_values_supported'=>['RS256'],
        'scopes_supported'=>['openid','profile','email','roles'],
        'token_endpoint_auth_methods_supported'=>['client_secret_basic','client_secret_post','none'],
        'code_challenge_methods_supported'=>['S256'],
    ]);
}

if ($path === '/.well-known/jwks.json' && $method === 'GET') {
    $pem = @file_get_contents((string)$config['keys']['public']);
    $key = $pem ? openssl_pkey_get_public($pem) : false;
    $details = $key ? openssl_pkey_get_details($key) : false;
    if (!is_array($details) || empty($details['rsa'])) jsonResponse(['error'=>'server_error'], 500);
    $b64u = static fn(string $v): string => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
    jsonResponse(['keys'=>[['kty'=>'RSA','use'=>'sig','alg'=>'RS256','kid'=>(string)$config['keys']['kid'],'n'=>$b64u($details['rsa']['n']),'e'=>$b64u($details['rsa']['e'])]]]);
}

if ($path === '/login') {
    if ($method === 'POST') {
        Security::requireCsrf($_POST['_csrf'] ?? null);
        if ($auth->login((string)($_POST['email'] ?? ''), (string)($_POST['password'] ?? ''))) {
            $return = (string)($_POST['return'] ?? '/dashboard');
            if (!str_starts_with($return, '/') || str_starts_with($return, '//')) $return = '/dashboard';
            redirect($return);
        }
        $error = '<div class="alert danger">Nieprawidłowe dane logowania.</div>';
    } else $error = '';
    $return = (string)($_GET['return'] ?? $_POST['return'] ?? '/dashboard');
    $body = '<section class="card narrow"><h1>Logowanie</h1>'.$error.'<form method="post"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><input type="hidden" name="return" value="'.e($return).'"><label>E-mail<input type="email" name="email" required autofocus></label><label>Hasło<input type="password" name="password" required></label><button class="primary" type="submit">Zaloguj</button></form></section>';
    page('Logowanie', $body, null);
}

if ($path === '/logout' && $method === 'POST') {
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $auth->logout();
    redirect('/login');
}

if ($path === '/oauth/authorize' && $method === 'GET') {
    $clientId = (string)($_GET['client_id'] ?? '');
    $redirectUri = (string)($_GET['redirect_uri'] ?? '');
    $app = $oidc->client($clientId);
    if (!$app) page('Błąd OAuth', '<section class="card narrow"><h1>Nieprawidłowy klient</h1><div class="code">invalid_client</div></section>');
    if (!$oidc->redirectAllowed((int)$app['id'], $redirectUri)) page('Błąd OAuth', '<section class="card narrow"><h1>Nieprawidłowy Redirect URI</h1><p>Żądanie zostało zatrzymane lokalnie.</p><div class="code">invalid_request</div></section>');
    if (($_GET['response_type'] ?? '') !== 'code') redirect($redirectUri . (str_contains($redirectUri, '?')?'&':'?') . http_build_query(['error'=>'unsupported_response_type','state'=>$_GET['state'] ?? null]));

    $user = $auth->currentUser();
    if (!$user) redirect('/login?return=' . rawurlencode($_SERVER['REQUEST_URI'] ?? '/dashboard'));
    if (!$access->hasAccess((int)$user['id'], $app)) oauthDeniedPage($app, $redirectUri, isset($_GET['state']) ? (string)$_GET['state'] : null);

    try {
        $scopes = $oidc->allowedScopes((int)$app['id'], (string)($_GET['scope'] ?? 'openid'));
        $code = $oidc->createAuthorizationCode($app, (int)$user['id'], $redirectUri, $scopes, isset($_GET['code_challenge']) ? (string)$_GET['code_challenge'] : null, isset($_GET['code_challenge_method']) ? (string)$_GET['code_challenge_method'] : null, isset($_GET['nonce']) ? (string)$_GET['nonce'] : null);
        $query = array_filter(['code'=>$code,'state'=>isset($_GET['state']) ? (string)$_GET['state'] : null], static fn($v) => $v !== null);
        redirect($redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query($query));
    } catch (RuntimeException $ex) {
        if ($ex->getMessage() === 'access_denied') oauthDeniedPage($app, $redirectUri, isset($_GET['state']) ? (string)$_GET['state'] : null);
        redirect($redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query(['error'=>$ex->getMessage(),'state'=>$_GET['state'] ?? null]));
    }
}

if ($path === '/oauth/token' && $method === 'POST') {
    try {
        $grant = (string)($_POST['grant_type'] ?? '');
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
        $result = match ($grant) {
            'authorization_code' => $oidc->exchangeAuthorizationCode($_POST, is_string($header) ? $header : null),
            'refresh_token' => $oidc->refresh($_POST, is_string($header) ? $header : null),
            default => throw new RuntimeException('unsupported_grant_type'),
        };
        jsonResponse($result);
    } catch (RuntimeException $ex) {
        $error = $ex->getMessage();
        $status = $error === 'invalid_client' ? 401 : 400;
        if ($status === 401) header('WWW-Authenticate: Basic realm="imAuthenticator token endpoint"');
        jsonResponse(['error'=>$error], $status);
    }
}

if ($path === '/oauth/userinfo' && in_array($method, ['GET','POST'], true)) {
    try { jsonResponse($oidc->userInfo(bearerToken())); }
    catch (RuntimeException) { header('WWW-Authenticate: Bearer error="invalid_token"'); jsonResponse(['error'=>'invalid_token'], 401); }
}

if ($path === '/oauth/logout') {
    $user = $auth->currentUser();
    if ($user) $audit->write('oidc.logout', 'success', (int)$user['id'], (int)$user['id']);
    $auth->logout();
    $target = (string)($_GET['post_logout_redirect_uri'] ?? '/login');
    if (!str_starts_with($target, '/') || str_starts_with($target, '//')) $target = '/login';
    redirect($target);
}

if ($path === '/' || $path === '/dashboard') {
    $user = $auth->requireUser();
    $apps = $db->all('SELECT * FROM applications WHERE enabled=1 AND deleted_at IS NULL ORDER BY name');
    $apps = array_values(array_filter($apps, static fn(array $app): bool => $access->hasAccess((int)$user['id'], $app)));
    $cards = '';
    foreach ($apps as $app) $cards .= '<a class="app-card" href="'.e($app['url']).'"><div class="app-icon">'.e(mb_strtoupper(mb_substr($app['name'],0,1))).'</div><div><strong>'.e($app['name']).'</strong><span>'.e(appTypeLabel($app['app_type'])).'</span></div></a>';
    if ($cards === '') $cards = '<div class="empty">Nie masz obecnie dostępu do żadnej aplikacji.</div>';
    page('Moje aplikacje', '<div class="page-head"><div><h1>Moje aplikacje</h1><p>Widoczne są wyłącznie aplikacje, do których masz efektywny dostęp.</p></div></div><div class="app-grid">'.$cards.'</div>', $user);
}

if ($path === '/admin/applications' && $method === 'GET') {
    $admin = $auth->requireAdmin();
    $apps = $db->all('SELECT a.*,(SELECT COUNT(*) FROM application_users au WHERE au.application_id=a.id AND au.enabled=1) AS users_count FROM applications a WHERE a.deleted_at IS NULL ORDER BY a.created_at DESC');
    $rows = '';
    foreach ($apps as $app) {
        $rows .= '<tr><td><div class="app-icon small">'.e(mb_strtoupper(mb_substr($app['name'],0,1))).'</div></td><td><a href="/admin/applications/'.(int)$app['id'].'"><strong>'.e($app['name']).'</strong></a></td><td>'.e(appTypeLabel($app['app_type'])).'</td><td class="truncate">'.e($app['url']).'</td><td><code>'.e($app['client_id']).'</code></td><td>'.(int)$app['users_count'].'</td><td><span class="badge '.((bool)$app['enabled']?'ok':'muted').'">'.((bool)$app['enabled']?'Aktywna':'Wyłączona').'</span></td><td>'.e($app['last_used_at'] ?: '—').'</td><td><a href="/admin/applications/'.(int)$app['id'].'">Otwórz</a></td></tr>';
    }
    if ($rows === '') $rows = '<tr><td colspan="9" class="empty">Brak aplikacji.</td></tr>';
    $body = '<div class="page-head"><div><h1>Aplikacje</h1><p>Klienci OAuth/OIDC i polityki dostępu.</p></div><a class="button primary" href="/admin/applications/new">Dodaj aplikację</a></div><div class="table-wrap"><table><thead><tr><th>Ikona</th><th>Nazwa</th><th>Typ</th><th>URL</th><th>Client ID</th><th>Użytkownicy</th><th>Status</th><th>Ostatnie użycie</th><th>Akcje</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';
    page('Aplikacje', $body, $admin);
}

if ($path === '/admin/applications/new' && $method === 'GET') {
    $admin = $auth->requireAdmin();
    $body = '<div class="page-head"><div><h1>Dodaj aplikację</h1><p>Kreator klienta OAuth/OpenID Connect.</p></div></div><form method="post" action="/admin/applications" id="appWizard" class="card wizard"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'">
    <section class="wizard-step active" data-step="1"><div class="step-label">Krok 1 z 5</div><h2>Dane aplikacji</h2><label>Nazwa aplikacji<input name="name" required></label><label>Opis<textarea name="description" rows="3"></textarea></label><label>Adres aplikacji<input type="url" name="url" placeholder="https://xyz.example.com" required></label><label>Ikona/logo URL<input type="url" name="icon"></label><label>Typ aplikacji<select name="app_type" id="appType"><option value="website">Strona WWW</option><option value="wordpress">WordPress</option><option value="php">Własna aplikacja PHP</option><option value="spa">SPA</option><option value="mobile">Aplikacja mobilna</option><option value="oidc" selected>Generic OpenID Connect</option><option value="m2m">Machine-to-Machine</option></select></label></section>
    <section class="wizard-step" data-step="2"><div class="step-label">Krok 2 z 5</div><h2>Typ integracji</h2><label>Integracja<select name="integration_type" id="integrationType"><option value="generic_oidc">Generic OpenID Connect</option><option value="wordpress_oidc">WordPress / OpenID Connect</option><option value="public_pkce">Public Client + PKCE</option><option value="client_credentials">Machine-to-Machine</option></select></label><div class="hint">Kreator dobiera zalecany typ klienta i scopes. Public Client zawsze wymaga PKCE S256.</div></section>
    <section class="wizard-step" data-step="3"><div class="step-label">Krok 3 z 5</div><h2>Callback / Redirect URI</h2><label>Redirect URI — jeden na linię<textarea name="redirect_uris" rows="5" placeholder="https://xyz.example.com/oauth/callback" required></textarea></label><div class="hint">Wildcardy są zabronione. Wymagany jest HTTPS, z wyjątkiem localhost do developmentu.</div></section>
    <section class="wizard-step" data-step="4"><div class="step-label">Krok 4 z 5</div><h2>Klient i scopes</h2><p>Client ID i Client Secret zostaną wygenerowane kryptograficznie. Nie wpisuje się ich ręcznie.</p><label>Scopes<input name="scopes" value="openid profile email roles" readonly></label></section>
    <section class="wizard-step" data-step="5"><div class="step-label">Krok 5 z 5</div><h2>Dostęp użytkowników</h2><label>Polityka dostępu<select name="access_policy"><option value="none" selected>Brak dostępu — administrator musi przypisać użytkowników</option><option value="all">Wszyscy użytkownicy</option><option value="users">Wybrani użytkownicy</option><option value="groups">Wybrane grupy</option><option value="roles">Wybrane role</option><option value="mixed">Reguły mieszane</option></select></label><div class="alert warning">Bezpieślna wartość domyślna to brak dostępu.</div></section>
    <div class="wizard-actions"><button type="button" id="prevStep">Wstecz</button><button type="button" class="primary" id="nextStep">Dalej</button><button type="submit" class="primary hidden" id="createApp">Utwórz aplikację</button></div></form>
    <script>let s=1;const steps=[...document.querySelectorAll(".wizard-step")],next=document.getElementById("nextStep"),prev=document.getElementById("prevStep"),create=document.getElementById("createApp"),type=document.getElementById("appType"),integration=document.getElementById("integrationType");function show(){steps.forEach(x=>x.classList.toggle("active",Number(x.dataset.step)===s));prev.disabled=s===1;next.classList.toggle("hidden",s===5);create.classList.toggle("hidden",s!==5)}next.onclick=()=>{if(s<5)s++;show()};prev.onclick=()=>{if(s>1)s--;show()};type.onchange=()=>{integration.value=type.value==="wordpress"?"wordpress_oidc":(["spa","mobile"].includes(type.value)?"public_pkce":(type.value==="m2m"?"client_credentials":"generic_oidc"))};show();</script>';
    page('Dodaj aplikację', $body, $admin);
}

if ($path === '/admin/applications' && $method === 'POST') {
    $admin = $auth->requireAdmin();
    Security::requireCsrf($_POST['_csrf'] ?? null);
    $name = trim((string)($_POST['name'] ?? ''));
    $url = trim((string)($_POST['url'] ?? ''));
    $appType = (string)($_POST['app_type'] ?? 'oidc');
    $integration = (string)($_POST['integration_type'] ?? 'generic_oidc');
    $policy = (string)($_POST['access_policy'] ?? 'none');
    $validTypes = ['website','wordpress','php','spa','mobile','oidc','m2m'];
    $validIntegrations = ['wordpress_oidc','generic_oidc','public_pkce','client_credentials'];
    $validPolicies = ['none','all','users','groups','roles','mixed'];
    if ($name === '' || !filter_var($url, FILTER_VALIDATE_URL) || !in_array($appType,$validTypes,true) || !in_array($integration,$validIntegrations,true) || !in_array($policy,$validPolicies,true)) page('Błąd', '<div class="alert danger">Nieprawidłowe dane aplikacji.</div>', $admin);
    $redirects = array_values(array_unique(array_filter(array_map('trim', preg_split('/\R/', (string)($_POST['redirect_uris'] ?? '')) ?: []))));
    if ($integration !== 'client_credentials' && $redirects === []) page('Błąd', '<div class="alert danger">Dodaj co najmniej jeden Redirect URI.</div>', $admin);
    foreach ($redirects as $uri) if (!Security::validRedirectUri($uri)) page('Błąd', '<div class="alert danger">Nieprawidłowy Redirect URI: '.e($uri).'. Wildcardy i HTTP poza localhost są zabronione.</div>', $admin);

    $clientType = in_array($integration, ['public_pkce'], true) ? 'public' : 'confidential';
    $clientId = Security::clientId();
    $secret = $clientType === 'confidential' ? Security::clientSecret() : null;
    $slugBase = Security::slug($name);
    $slug = $slugBase;
    while ($db->one('SELECT 1 FROM applications WHERE slug=?', [$slug])) $slug = $slugBase . '-' . strtolower(Security::randomToken(4));
    $scopes = $integration === 'client_credentials' ? ['roles'] : ['openid','profile','email','roles'];

    $appId = $db->transaction(function () use ($db,$name,$url,$appType,$integration,$policy,$clientType,$clientId,$secret,$slug,$redirects,$scopes): int {
        $db->execute('INSERT INTO applications(uuid,name,slug,description,url,icon,app_type,integration_type,client_id,client_secret_hash,client_type,access_policy,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)', [Security::uuidV4(),$name,$slug,trim((string)($_POST['description'] ?? '')) ?: null,$url,trim((string)($_POST['icon'] ?? '')) ?: null,$appType,$integration,$clientId,$secret ? Security::secretHash($secret) : null,$clientType,$policy]);
        $id = $db->lastInsertId();
        foreach ($redirects as $uri) $db->execute('INSERT INTO application_redirect_uris(application_id,redirect_uri) VALUES(?,?)', [$id,$uri]);
        foreach ($scopes as $scope) $db->execute('INSERT INTO application_scopes(application_id,scope) VALUES(?,?)', [$id,$scope]);
        return $id;
    });
    if ($secret !== null) $_SESSION['client_secrets'][$appId] = $secret;
    $audit->write('application.created', 'success', (int)$admin['id'], null, $appId, null, ['type'=>$appType,'integration'=>$integration,'access_policy'=>$policy]);
    redirect('/admin/applications/'.$appId.'?created=1');
}

if (preg_match('#^/admin/applications/(\d+)$#', $path, $m) && $method === 'GET') {
    $admin = $auth->requireAdmin();
    $appId = (int)$m[1];
    $app = $db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL', [$appId]);
    if (!$app) { http_response_code(404); page('Nie znaleziono', '<div class="alert danger">Nie znaleziono aplikacji.</div>', $admin); }
    $redirects = array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id', [$appId]), 'redirect_uri');
    $scopes = array_column($db->all('SELECT scope FROM application_scopes WHERE application_id=? ORDER BY scope', [$appId]), 'scope');
    $secret = $_SESSION['client_secrets'][$appId] ?? null;
    $issuer = rtrim((string)$config['issuer'], '/');
    $notice = isset($_GET['created']) ? '<div class="alert success"><strong>Aplikacja '.e($app['name']).' została utworzona.</strong> Zapisz Client Secret teraz — później nie będzie możliwy do odczytania.</div>' : '';
    $secretHtml = $app['client_type'] === 'public' ? '<span class="muted">Public Client — brak sekretu</span>' : ($secret ? '<code class="secret">'.e($secret).'</code>' : '<span class="muted">Sekret jest przechowywany tylko jako hash. Regeneruj, aby otrzymać nowy.</span>');
    $endpointRows = [
        'Issuer URL'=>$issuer,
        'Client ID'=>$app['client_id'],
        'Client Secret'=>$secretHtml,
        'Discovery URL'=>$issuer.'/.well-known/openid-configuration',
        'Authorization Endpoint'=>$issuer.'/oauth/authorize',
        'Token Endpoint'=>$issuer.'/oauth/token',
        'UserInfo Endpoint'=>$issuer.'/oauth/userinfo',
        'Logout Endpoint'=>$issuer.'/oauth/logout',
        'Redirect URI'=>implode("\n", $redirects),
    ];
    $configRows = '';
    foreach ($endpointRows as $label=>$value) $configRows .= '<div class="kv"><span>'.e($label).'</span><div>'.($label==='Client Secret' ? $value : '<code>'.nl2br(e((string)$value)).'</code>').'</div></div>';
    $tabs = '<div class="tabs"><a href="#config">Konfiguracja</a><a href="#users">Użytkownicy</a><a href="#roles">Role</a><a href="#access">Dostęp</a><a href="/admin/applications/'.$appId.'/test">Testuj</a></div>';

    $users = $db->all('SELECT u.id,u.name,u.email,u.enabled,au.enabled AS direct_enabled,au.created_at,creator.email AS creator_email FROM users u LEFT JOIN application_users au ON au.user_id=u.id AND au.application_id=? LEFT JOIN users creator ON creator.id=au.created_by ORDER BY u.name', [$appId]);
    $roles = $db->all('SELECT * FROM app_roles WHERE application_id=? ORDER BY name', [$appId]);
    $userRows = '';
    foreach ($users as $u) {
        $effective = $access->hasAccess((int)$u['id'], $app);
        $uRoles = $access->rolesForUser((int)$u['id'], $appId);
        $userRows .= '<tr><td><input type="checkbox" name="user_ids[]" value="'.(int)$u['id'].'"></td><td>'.e($u['name']).'</td><td>'.e($u['email']).'</td><td>'.((bool)$u['enabled']?'Aktywny':'Wyłączony').'</td><td><span class="badge '.($effective?'ok':'muted').'">'.($effective?'Tak':'Nie').'</span></td><td>'.e(implode(', ', $uRoles) ?: '—').'</td><td>'.e($u['created_at'] ?: '—').'</td><td>'.e($u['creator_email'] ?: '—').'</td></tr>';
    }
    $roleOptions = '<option value="">— rola —</option>'; foreach ($roles as $r) $roleOptions .= '<option value="'.(int)$r['id'].'">'.e($r['name']).'</option>';
    $roleList = ''; foreach ($roles as $r) $roleList .= '<li><strong>'.e($r['name']).'</strong> '.e($r['description'] ?? '').'</li>'; if ($roleList==='') $roleList='<li class="muted">Brak ról aplikacyjnych.</li>';

    $groups = $db->all('SELECT g.*,ag.group_id AS selected FROM groups g LEFT JOIN application_groups ag ON ag.group_id=g.id AND ag.application_id=? ORDER BY g.name', [$appId]);
    $sysRoles = $db->all('SELECT r.*,ar.role_id AS selected FROM system_roles r LEFT JOIN application_system_roles ar ON ar.role_id=r.id AND ar.application_id=? ORDER BY r.name', [$appId]);
    $groupChecks=''; foreach($groups as $g) $groupChecks.='<label class="check"><input type="checkbox" name="group_ids[]" value="'.(int)$g['id'].'" '.($g['selected']?'checked':'').'> '.e($g['name']).'</label>';
    $sysRoleChecks=''; foreach($sysRoles as $r) $sysRoleChecks.='<label class="check"><input type="checkbox" name="system_role_ids[]" value="'.(int)$r['id'].'" '.($r['selected']?'checked':'').'> '.e($r['name']).'</label>';

    $wordpress = $app['app_type']==='wordpress' ? '<section class="card"><h2>Konfiguracja WordPress</h2><div class="kv"><span>Issuer URL</span><code>'.e($issuer).'</code></div><div class="kv"><span>Client ID</span><code>'.e($app['client_id']).'</code></div><div class="kv"><span>Client Secret</span>'.$secretHtml.'</div><div class="kv"><span>Scopes</span><code>openid profile email roles</code></div><p>Skonfiguruj kompatybilny plugin OpenID Connect jako klienta OIDC. Użyj Discovery URL powyżej i dokładnie tego Redirect URI, które plugin zgłosi. Architektura jest zgodna z przyszłym pluginem imAuthenticator dla WordPress.</p></section>' : '';

    $body = $notice.'<div class="page-head"><div><h1>'.e($app['name']).'</h1><p>'.e($app['url']).' · '.e(appTypeLabel($app['app_type'])).'</p></div><span class="badge '.((bool)$app['enabled']?'ok':'muted').'">'.((bool)$app['enabled']?'Aktywna':'Wyłączona').'</span></div>'.$tabs.'<section class="card" id="config"><h2>Konfiguracja OIDC</h2>'.$configRows.'<div class="actions"><a class="button" href="/admin/applications/'.$appId.'/config.json">Pobierz konfigurację</a><a class="button" href="/admin/applications/'.$appId.'/test">Testuj integrację</a><form method="post" action="/admin/applications/'.$appId.'/secret/regenerate" class="inline"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><button>Regeneruj secret</button></form></div></section>'.$wordpress.
    '<section class="card" id="users"><h2>Użytkownicy</h2><form method="post" action="/admin/applications/'.$appId.'/users/bulk"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><div class="toolbar"><select name="bulk_action"><option value="grant">Nadaj dostęp</option><option value="revoke">Odbierz dostęp</option><option value="assign_role">Przypisz rolę</option><option value="remove_role">Usuń rolę</option></select><select name="app_role_id">'.$roleOptions.'</select><button class="primary">Wykonaj</button></div><div class="table-wrap"><table><thead><tr><th></th><th>Użytkownik</th><th>E-mail</th><th>Status</th><th>Dostęp</th><th>Role w aplikacji</th><th>Nadano</th><th>Kto nadał</th></tr></thead><tbody>'.$userRows.'</tbody></table></div></form></section>'.
    '<section class="card" id="roles"><h2>Role aplikacyjne</h2><ul>'.$roleList.'</ul><form method="post" action="/admin/applications/'.$appId.'/roles"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><div class="form-row"><label>Nazwa roli<input name="name" placeholder="editor" required pattern="[A-Za-z0-9._-]+"></label><label>Opis<input name="description"></label></div><button class="primary">Dodaj rolę</button></form></section>'.
    '<section class="card" id="access"><h2>Polityka dostępu</h2><form method="post" action="/admin/applications/'.$appId.'/access-policy"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><label>Tryb<select name="access_policy">'.implode('', array_map(static fn($v,$l)=>'<option value="'.$v.'" '.($app['access_policy']===$v?'selected':'').'>'.$l.'</option>', ['none','all','users','groups','roles','mixed'], ['Brak dostępu','Wszyscy użytkownicy','Wybrani użytkownicy','Wybrane grupy','Wybrane role','Reguły mieszane'])).'</select></label><h3>Grupy</h3><div class="checks">'.($groupChecks ?: '<span class="muted">Brak grup.</span>').'</div><h3>Role systemowe</h3><div class="checks">'.($sysRoleChecks ?: '<span class="muted">Brak ról systemowych.</span>').'</div><button class="primary">Zapisz politykę</button></form></section>'.
    '<section class="card danger-zone"><h2>Stan aplikacji</h2><div class="actions"><form method="post" action="/admin/applications/'.$appId.'/status"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><input type="hidden" name="enabled" value="'.((bool)$app['enabled']?'0':'1').'"><button>'.((bool)$app['enabled']?'Wyłącz':'Włącz').'</button></form><form method="post" action="/admin/applications/'.$appId.'/delete" onsubmit="return confirm(\'Usunąć aplikację? Tokeny zostaną unieważnione, a rekord zostanie zachowany dla audytu.\')"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><button class="danger">Usuń aplikację</button></form></div></section>';
    page($app['name'], $body, $admin);
}

if (preg_match('#^/admin/applications/(\d+)/config\.json$#', $path, $m) && $method === 'GET') {
    $auth->requireAdmin(); $appId=(int)$m[1]; $app=$db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL',[$appId]); if(!$app) jsonResponse(['error'=>'not_found'],404);
    $redirects=array_column($db->all('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id',[$appId]),'redirect_uri'); $issuer=rtrim((string)$config['issuer'],'/');
    header('Content-Disposition: attachment; filename="imAuthenticator-'.preg_replace('/[^A-Za-z0-9._-]/','-',(string)$app['slug']).'.json"');
    jsonResponse(['issuer'=>$issuer,'client_id'=>$app['client_id'],'redirect_uri'=>$redirects[0]??null,'redirect_uris'=>$redirects,'discovery_url'=>$issuer.'/.well-known/openid-configuration']);
}

if (preg_match('#^/admin/applications/(\d+)/users/bulk$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $ids=array_values(array_unique(array_map('intval',(array)($_POST['user_ids']??[])))); $action=(string)($_POST['bulk_action']??''); $roleId=(int)($_POST['app_role_id']??0);
    foreach($ids as $uid){ if($uid<1)continue; if($action==='grant')$access->grantUser($appId,$uid,(int)$admin['id']); elseif($action==='revoke')$access->revokeUser($appId,$uid,(int)$admin['id']); elseif(in_array($action,['assign_role','remove_role'],true)&&$roleId>0){$valid=$db->one('SELECT id FROM app_roles WHERE id=? AND application_id=?',[$roleId,$appId]);if(!$valid)continue;if($action==='assign_role')$db->execute('INSERT IGNORE INTO app_user_roles(application_id,user_id,app_role_id,created_by) VALUES(?,?,?,?)',[$appId,$uid,$roleId,(int)$admin['id']]);else $db->execute('DELETE FROM app_user_roles WHERE application_id=? AND user_id=? AND app_role_id=?',[$appId,$uid,$roleId]);$audit->write('application.user_role.'.($action==='assign_role'?'assigned':'removed'),'success',(int)$admin['id'],$uid,$appId,null,['role_id'=>$roleId]);}}
    redirect('/admin/applications/'.$appId.'#users');
}

if (preg_match('#^/admin/applications/(\d+)/roles$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $name=trim((string)($_POST['name']??'')); if(!preg_match('/^[A-Za-z0-9._-]{1,120}$/',$name)) page('Błąd','<div class="alert danger">Nieprawidłowa nazwa roli.</div>',$admin); $db->execute('INSERT INTO app_roles(application_id,name,description) VALUES(?,?,?)',[$appId,$name,trim((string)($_POST['description']??''))?:null]); $audit->write('application.role.created','success',(int)$admin['id'],null,$appId,null,['role'=>$name]); redirect('/admin/applications/'.$appId.'#roles');
}

if (preg_match('#^/admin/applications/(\d+)/access-policy$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $policy=(string)($_POST['access_policy']??'none'); if(!in_array($policy,['none','all','users','groups','roles','mixed'],true))$policy='none'; $groupIds=array_unique(array_map('intval',(array)($_POST['group_ids']??[]))); $roleIds=array_unique(array_map('intval',(array)($_POST['system_role_ids']??[])));
    $db->transaction(function()use($db,$appId,$policy,$groupIds,$roleIds,$admin){$db->execute('UPDATE applications SET access_policy=? WHERE id=?',[$policy,$appId]);$db->execute('DELETE FROM application_groups WHERE application_id=?',[$appId]);foreach($groupIds as $id)if($id>0)$db->execute('INSERT INTO application_groups(application_id,group_id,created_by) SELECT ?,id,? FROM groups WHERE id=?',[$appId,(int)$admin['id'],$id]);$db->execute('DELETE FROM application_system_roles WHERE application_id=?',[$appId]);foreach($roleIds as $id)if($id>0)$db->execute('INSERT INTO application_system_roles(application_id,role_id,created_by) SELECT ?,id,? FROM system_roles WHERE id=?',[$appId,(int)$admin['id'],$id]);});
    $audit->write('application.access_policy.updated','success',(int)$admin['id'],null,$appId,null,['policy'=>$policy]); redirect('/admin/applications/'.$appId.'#access');
}

if (preg_match('#^/admin/applications/(\d+)/secret/regenerate$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $app=$db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL',[$appId]); if(!$app||$app['client_type']!=='confidential')redirect('/admin/applications/'.$appId); $secret=Security::clientSecret(); $db->execute('UPDATE applications SET client_secret_hash=? WHERE id=?',[Security::secretHash($secret),$appId]); $_SESSION['client_secrets'][$appId]=$secret; $access->revokeApplication($appId,(int)$admin['id'],'client secret regenerated'); $audit->write('application.secret.regenerated','success',(int)$admin['id'],null,$appId); redirect('/admin/applications/'.$appId.'?secret_regenerated=1');
}

if (preg_match('#^/admin/applications/(\d+)/status$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $enabled=(int)($_POST['enabled']??0)===1; $db->execute('UPDATE applications SET enabled=? WHERE id=?',[$enabled?1:0,$appId]); if(!$enabled)$access->revokeApplication($appId,(int)$admin['id']); $audit->write('application.'.($enabled?'enabled':'disabled'),'success',(int)$admin['id'],null,$appId); redirect('/admin/applications/'.$appId);
}

if (preg_match('#^/admin/applications/(\d+)/delete$#', $path, $m) && $method === 'POST') {
    $admin=$auth->requireAdmin(); Security::requireCsrf($_POST['_csrf']??null); $appId=(int)$m[1]; $db->execute('UPDATE applications SET enabled=0,deleted_at=NOW() WHERE id=?',[$appId]); $access->revokeApplication($appId,(int)$admin['id'],'application soft-deleted'); $db->execute('UPDATE application_users SET enabled=0 WHERE application_id=?',[$appId]); $audit->write('application.deleted','success',(int)$admin['id'],null,$appId); redirect('/admin/applications');
}

if (preg_match('#^/admin/applications/(\d+)/test$#', $path, $m)) {
    $admin=$auth->requireAdmin(); $appId=(int)$m[1]; $app=$db->one('SELECT * FROM applications WHERE id=? AND deleted_at IS NULL',[$appId]); if(!$app)page('Nie znaleziono','<div class="alert danger">Nie znaleziono aplikacji.</div>',$admin); $redirect=$db->one('SELECT redirect_uri FROM application_redirect_uris WHERE application_id=? ORDER BY id LIMIT 1',[$appId]);
    $checks=[['Klient znaleziony',true],['Klient aktywny',(bool)$app['enabled']],['Redirect URI poprawne',$redirect ? $oidc->redirectAllowed($appId,(string)$redirect['redirect_uri']) : $app['integration_type']==='client_credentials'],['Użytkownik zalogowany',true],['Użytkownik posiada dostęp',$access->hasAccess((int)$admin['id'],$app)]];
    if($method==='POST'){Security::requireCsrf($_POST['_csrf']??null);if($redirect&&$access->hasAccess((int)$admin['id'],$app)){try{$verifier=null;$challenge=null;$methodPkce=null;if($app['client_type']==='public'){$verifier=Security::randomToken(48);$challenge=rtrim(strtr(base64_encode(hash('sha256',$verifier,true)),'+/','-_'),'=');$methodPkce='S256';}$code=$oidc->createAuthorizationCode($app,(int)$admin['id'],(string)$redirect['redirect_uri'],['openid','profile','email','roles'],$challenge,$methodPkce,'self-test');$input=['grant_type'=>'authorization_code','code'=>$code,'redirect_uri'=>$redirect['redirect_uri'],'client_id'=>$app['client_id']];if($app['client_type']==='public')$input['code_verifier']=$verifier;else $input['client_secret']=(string)($_POST['client_secret']??($_SESSION['client_secrets'][$appId]??''));$tokens=$oidc->exchangeAuthorizationCode($input,null);$checks[]=['Authorization code wygenerowany',true];$checks[]=['Token endpoint działa',isset($tokens['access_token'])];$info=$oidc->userInfo((string)$tokens['access_token']);$checks[]=['UserInfo działa',isset($info['sub'])];$db->execute('UPDATE oauth_access_tokens SET revoked_at=NOW() WHERE token_hash=?',[Security::tokenHash((string)$tokens['access_token'])]);$db->execute('UPDATE oauth_refresh_tokens SET revoked_at=NOW() WHERE token_hash=?',[Security::tokenHash((string)$tokens['refresh_token'])]);}catch(Throwable $ex){$checks[]=['Flow testowy',false,$ex->getMessage()];}}}
    $lis='';foreach($checks as $c)$lis.='<li class="check-result '.($c[1]?'pass':'fail').'"><strong>'.($c[1]?'OK':'BŁĄD').'</strong> '.e($c[0]).(isset($c[2])?' — '.e($c[2]):'').'</li>'; $secretInput=$app['client_type']==='confidential'?'<label>Client Secret do testu<input type="password" name="client_secret" autocomplete="off" placeholder="Podaj aktualny sekret"></label>':''; $body='<div class="page-head"><div><h1>Test integracji — '.e($app['name']).'</h1><p>Tokeny testowe nie są logowane i są unieważniane po teście.</p></div><a class="button" href="/admin/applications/'.$appId.'">Wróć</a></div><section class="card"><ul class="test-list">'.$lis.'</ul><form method="post"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'">'.$secretInput.'<button class="primary">Uruchom pełny test</button></form></section>'; page('Test integracji',$body,$admin);
}

if (preg_match('#^/admin/users/(\d+)/applications$#',$path,$m)) {
    $admin=$auth->requireAdmin();$userId=(int)$m[1];$target=$db->one('SELECT id,name,email,enabled FROM users WHERE id=?',[$userId]);if(!$target)page('Nie znaleziono','<div class="alert danger">Nie znaleziono użytkownika.</div>',$admin);
    if($method==='POST'){Security::requireCsrf($_POST['_csrf']??null);$appId=(int)($_POST['application_id']??0);$action=(string)($_POST['action']??'');if($action==='grant')$access->grantUser($appId,$userId,(int)$admin['id']);elseif($action==='revoke')$access->revokeUser($appId,$userId,(int)$admin['id']);redirect('/admin/users/'.$userId.'/applications');}
    $apps=$db->all('SELECT * FROM applications WHERE deleted_at IS NULL ORDER BY name');$rows='';foreach($apps as $app){$has=$access->hasAccess($userId,$app);$roles=$access->rolesForUser($userId,(int)$app['id']);$rows.='<tr><td>'.e($app['name']).'</td><td><span class="badge '.($has?'ok':'muted').'">'.($has?'Tak':'Nie').'</span></td><td>'.e(implode(', ',$roles)?:'—').'</td><td><form method="post"><input type="hidden" name="_csrf" value="'.e(Security::csrfToken()).'"><input type="hidden" name="application_id" value="'.(int)$app['id'].'"><input type="hidden" name="action" value="'.($has?'revoke':'grant').'"><button>'.($has?'Odbierz dostęp':'Nadaj dostęp').'</button></form></td></tr>';}$body='<div class="page-head"><div><h1>Aplikacje użytkownika</h1><p>'.e($target['name']).' · '.e($target['email']).'</p></div></div><div class="table-wrap"><table><thead><tr><th>Aplikacja</th><th>Dostęp</th><th>Role</th><th>Akcja</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';page('Aplikacje użytkownika',$body,$admin);
}

if ($path === '/admin/audit' && $method === 'GET') {
    $admin=$auth->requireAdmin();$logs=$db->all('SELECT l.*,actor.email AS actor_email,subject.email AS subject_email,a.name AS app_name FROM audit_log l LEFT JOIN users actor ON actor.id=l.actor_user_id LEFT JOIN users subject ON subject.id=l.subject_user_id LEFT JOIN applications a ON a.id=l.application_id ORDER BY l.id DESC LIMIT 250');$rows='';foreach($logs as $log)$rows.='<tr><td>'.e($log['created_at']).'</td><td>'.e($log['actor_email']?:'system').'</td><td>'.e($log['action']).'</td><td>'.e($log['app_name']?:'—').'</td><td>'.e($log['subject_email']?:'—').'</td><td><span class="badge '.($log['result']==='success'?'ok':'danger').'">'.e($log['result']).'</span></td><td>'.e($log['reason']?:'—').'</td></tr>';$body='<div class="page-head"><div><h1>Audit Log</h1><p>Ostatnie 250 zdarzeń uwierzytelniania i administracji.</p></div></div><div class="table-wrap"><table><thead><tr><th>Data</th><th>Aktor</th><th>Zdarzenie</th><th>Aplikacja</th><th>Użytkownik</th><th>Wynik</th><th>Powód</th></tr></thead><tbody>'.$rows.'</tbody></table></div>';page('Audit Log',$body,$admin);
}

http_response_code(404);
$user = $auth->currentUser();
page('404', '<section class="card narrow"><h1>404</h1><p>Nie znaleziono strony.</p></section>', $user);
